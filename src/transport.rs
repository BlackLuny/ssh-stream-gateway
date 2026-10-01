//! Verified HTTPS transport, optionally carried through an HTTP(S) CONNECT proxy.
use anyhow::{Context, Result, anyhow, bail, ensure};
use http::{HeaderValue, Uri};
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECT_HEADERS: usize = 16 * 1024;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Connect with native trust plus any certificates in `ca_file`. TLS verification
/// is mandatory, including for HTTPS proxies. Only the origin negotiates h2.
/// HTTPS_PROXY (then ALL_PROXY) selects the route; NO_PROXY bypasses it. Uppercase
/// variables take precedence over lowercase. HTTP_PROXY is for HTTP origins and
/// deliberately does not apply to this HTTPS-only transport.
pub async fn connect(uri: &Uri, ca_file: Option<&Path>) -> Result<Box<dyn AsyncReadWrite>> {
    let proxy = proxy_from_env(uri)?;
    connect_routed(uri, ca_file, proxy).await
}

async fn connect_routed(
    uri: &Uri,
    ca_file: Option<&Path>,
    proxy: Option<Intercept>,
) -> Result<Box<dyn AsyncReadWrite>> {
    ensure!(uri.scheme_str() == Some("https"), "endpoint must use HTTPS");
    let authority = uri.authority().context("endpoint has no authority")?;
    ensure!(
        !authority.as_str().contains('@'),
        "endpoint must not contain credentials"
    );
    let target = socket_authority(uri)?;
    let ca_file = ca_file.map(Path::to_path_buf);
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        // Loading the native certificate store can block; keep it inside the
        // overall deadline without blocking Tokio's scheduler.
        let roots = tokio::task::spawn_blocking(move || load_roots(ca_file.as_deref()))
            .await
            .context("certificate loader failed")??;
        let mut stream: Box<dyn AsyncReadWrite>;
        if let Some(proxy) = proxy {
            stream = dial(proxy.uri())
                .await
                .context("cannot reach configured proxy")?;
            if proxy.uri().scheme_str() == Some("https") {
                stream = tls(stream, proxy.uri(), roots.clone(), b"http/1.1")
                    .await
                    .context("HTTPS proxy TLS handshake failed")?;
            }
            stream = Box::new(tunnel(stream, &target, proxy.basic_auth()).await?);
        } else {
            stream = dial(uri).await.context("cannot reach HTTPS endpoint")?;
        }
        tls(stream, uri, roots, b"h2")
            .await
            .context("endpoint TLS handshake failed")
    })
    .await
    .context("connection timed out after 30 seconds")?
}

fn load_roots(ca_file: Option<&Path>) -> Result<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if let Some(path) = ca_file {
        let mut count = 0;
        for cert in CertificateDer::pem_file_iter(path).context("cannot open CA PEM file")? {
            roots
                .add(cert.context("invalid certificate in CA PEM file")?)
                .context("CA PEM contains an unusable certificate")?;
            count += 1;
        }
        ensure!(count > 0, "CA PEM file contains no certificates");
    }
    ensure!(!roots.is_empty(), "no usable TLS trust roots were found");
    Ok(Arc::new(roots))
}

async fn dial(uri: &Uri) -> Result<Box<dyn AsyncReadWrite>> {
    let host = tls_host(uri)?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    Ok(Box::new(stream))
}

fn tls_host(uri: &Uri) -> Result<&str> {
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .context("URL has no host")?;
    // http::Uri retains IPv6 brackets; DNS and rustls ServerName do not.
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host))
}

async fn tls(
    stream: Box<dyn AsyncReadWrite>,
    uri: &Uri,
    roots: Arc<RootCertStore>,
    protocol: &[u8],
) -> Result<Box<dyn AsyncReadWrite>> {
    let name =
        ServerName::try_from(tls_host(uri)?.to_owned()).context("invalid TLS server name")?;
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![protocol.to_vec()];
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await?;
    if protocol == b"h2" {
        ensure!(
            stream.get_ref().1.alpn_protocol() == Some(b"h2"),
            "endpoint did not negotiate HTTP/2 (h2)"
        );
    }
    Ok(Box::new(stream))
}

fn socket_authority(uri: &Uri) -> Result<String> {
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .context("URL has no host")?;
    let authority = uri.authority().context("URL has no authority")?.as_str();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let suffix = host_port
        .strip_prefix(host)
        .context("invalid URL authority")?;
    ensure!(
        suffix.is_empty() || (suffix.starts_with(':') && uri.port_u16().is_some()),
        "invalid URL port"
    );
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    ensure!(port != 0, "URL port must not be zero");
    Ok(format!("{host}:{port}"))
}

fn env_value(upper: &str, lower: &str) -> Result<String> {
    for name in [upper, lower] {
        match std::env::var(name) {
            Ok(value) => return Ok(value),
            Err(std::env::VarError::NotPresent) => (),
            Err(_) => bail!("{name} is not valid UTF-8"),
        }
    }
    Ok(String::new())
}

fn proxy_from_env(uri: &Uri) -> Result<Option<Intercept>> {
    let specific = env_value("HTTPS_PROXY", "https_proxy")?;
    let selected = if specific.is_empty() {
        env_value("ALL_PROXY", "all_proxy")?
    } else {
        specific
    };
    select_proxy(uri, &selected, &env_value("NO_PROXY", "no_proxy")?)
}

fn select_proxy(uri: &Uri, value: &str, no_proxy: &str) -> Result<Option<Intercept>> {
    // Evaluate bypass first, so a deliberately bypassed host does not depend on
    // a proxy's validity. Handle '*' ourselves because matcher 0.1.20 misses IPs.
    let bypass = no_proxy.split(',').any(|part| part.trim() == "*")
        || Matcher::builder()
            .all("http://unused.invalid")
            .no(no_proxy)
            .build()
            .intercept(uri)
            .is_none();
    if value.is_empty() || bypass {
        return Ok(None);
    }
    // The matcher silently drops malformed proxies and strips their paths. Do
    // our validation before using it. Never attach the original input to errors:
    // a proxy URL can contain a username and password.
    let invalid = || {
        anyhow!(
            "configured proxy is invalid or unsupported; expected an HTTP(S) proxy URL; refusing fallback"
        )
    };
    let parsed: Uri = value.parse().map_err(|_| invalid())?;
    if !matches!(parsed.scheme_str(), Some("http" | "https"))
        || parsed.query().is_some()
        || !matches!(parsed.path(), "" | "/")
        || value.contains('#')
    {
        return Err(invalid());
    }
    socket_authority(&parsed).map_err(|_| invalid())?;
    let proxy = Matcher::builder()
        .all(value)
        .build()
        .intercept(uri)
        .ok_or_else(invalid)?;
    Ok(Some(proxy))
}

async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    target: &str,
    auth: Option<&HeaderValue>,
) -> Result<BufReader<S>> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n").into_bytes();
    if let Some(auth) = auth {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(auth.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream
        .write_all(&request)
        .await
        .context("cannot send proxy CONNECT")?;
    stream.flush().await.context("cannot flush proxy CONNECT")?;
    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    loop {
        let remaining = MAX_CONNECT_HEADERS - header.len();
        ensure!(remaining > 0, "proxy CONNECT headers exceed 16384 bytes");
        // `take` bounds even an unterminated line. The BufReader retains any
        // early tunnel bytes after the blank line, including TLS records.
        let count = (&mut reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut header)
            .await
            .context("cannot read proxy CONNECT response")?;
        ensure!(
            count != 0,
            "proxy closed connection before completing CONNECT headers"
        );
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(&header)
        .map_err(|_| anyhow!("malformed proxy CONNECT response"))?;
    ensure!(parsed.is_complete(), "incomplete proxy CONNECT response");
    match response.code {
        Some(200..=299) => Ok(reader),
        Some(407) => bail!("proxy authentication required (HTTP 407)"),
        Some(code) => bail!("proxy rejected CONNECT (HTTP {code})"),
        None => bail!("proxy CONNECT response has no status"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use tempfile::NamedTempFile;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn authority_ports_and_ipv6() {
        for (url, expected) in [
            ("https://example.com/", "example.com:443"),
            ("https://example.com:8443/", "example.com:8443"),
            ("http://example.com/", "example.com:80"),
            ("https://[::1]/", "[::1]:443"),
            ("https://[::1]:8443/", "[::1]:8443"),
        ] {
            assert_eq!(socket_authority(&url.parse().unwrap()).unwrap(), expected);
        }
        for url in [
            "https://example.com:65536/",
            "https://example.com:0/",
            "https://example.com:/",
        ] {
            if let Ok(uri) = url.parse() {
                assert!(socket_authority(&uri).is_err());
            }
        }
        assert_eq!(tls_host(&"https://[::1]/".parse().unwrap()).unwrap(), "::1");
    }

    #[test]
    fn bypass_matches_domains_addresses_cidrs_and_wildcard() {
        for url in [
            "https://example.com/",
            "https://a.example.com/",
            "https://127.0.0.1/",
            "https://10.42.1.2/",
            "https://[::1]/",
        ] {
            let uri = url.parse().unwrap();
            assert!(
                select_proxy(
                    &uri,
                    "http://proxy.invalid:8080",
                    ".example.com,127.0.0.1,10.0.0.0/8,::1"
                )
                .unwrap()
                .is_none()
            );
            assert!(
                select_proxy(&uri, "invalid proxy", "localhost, *")
                    .unwrap()
                    .is_none()
            );
        }
        let uri = "https://notexample.com/".parse().unwrap();
        assert!(
            select_proxy(&uri, "http://proxy.invalid:8080", ".example.com")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn malformed_proxy_never_becomes_a_direct_connection() {
        let uri = "https://origin.invalid/".parse().unwrap();
        for proxy in [
            "socks5://proxy.invalid:1080",
            "http://",
            "http://proxy.invalid:99999",
            "http://proxy.invalid:bad",
            "http://proxy.invalid/path",
            "http://proxy.invalid?secret=hidden",
            "http://proxy.invalid/#fragment",
            "invalid proxy",
        ] {
            let error = select_proxy(&uri, proxy, "").unwrap_err().to_string();
            assert!(error.contains("refusing fallback"));
            assert!(!error.contains(proxy));
        }
        assert!(
            select_proxy(&uri, "broken", "origin.invalid")
                .unwrap()
                .is_none()
        );
        assert!(select_proxy(&uri, "", "").unwrap().is_none());
    }

    #[test]
    fn proxy_auth_is_redacted_and_not_in_destination() {
        let uri = "https://origin.invalid/".parse().unwrap();
        let proxy = select_proxy(&uri, "https://alice:unit%2Dtest@proxy.invalid:443", "")
            .unwrap()
            .unwrap();
        assert_eq!(proxy.uri().to_string(), "https://proxy.invalid:443/");
        assert!(proxy.basic_auth().unwrap().is_sensitive());
        assert_eq!(proxy.basic_auth().unwrap(), "Basic YWxpY2U6dW5pdC10ZXN0");
        for output in [format!("{proxy:?}"), format!("{:?}", proxy.basic_auth())] {
            assert!(!output.contains("alice"));
            assert!(!output.contains("unit"));
            assert!(!output.contains("YWxp"));
        }
    }

    async fn mock_connect_response(
        response: &'static [u8],
    ) -> Result<BufReader<tokio::io::DuplexStream>> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            server.write_all(response).await.unwrap();
        });
        tunnel(client, "origin.invalid:443", None).await
    }

    #[tokio::test]
    async fn connect_preserves_early_tunnel_bytes() {
        let mut stream =
            mock_connect_response(b"HTTP/1.1 200 Connected\r\nX-Test: yes\r\n\r\nearly bytes")
                .await
                .unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"early bytes");
    }

    #[tokio::test]
    async fn connect_rejects_error_malformed_truncated_and_oversized_headers() {
        for (response, expected) in [
            (
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
                "authentication required",
            ),
            (&b"HTTP/1.1 502 Bad Gateway\r\n\r\n"[..], "HTTP 502"),
            (&b"not HTTP\r\n\r\n"[..], "malformed"),
            (&b"HTTP/1.1 200 Connected\r\n"[..], "before completing"),
        ] {
            let result = mock_connect_response(response).await;
            assert!(result.err().unwrap().to_string().contains(expected));
        }
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut request = [0; 256];
            assert!(server.read(&mut request).await.unwrap() > 0);
            server
                .write_all(&vec![b'x'; MAX_CONNECT_HEADERS + 1])
                .await
                .unwrap();
        });
        assert!(
            tunnel(client, "origin.invalid:443", None)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("exceed")
        );
    }

    #[tokio::test]
    async fn fragmented_connect_headers_work() {
        let (client, mut server) = tokio::io::duplex(1);
        let worker = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            for byte in b"HTTP/1.1 200 OK\r\n\r\nxyz" {
                server.write_all(&[*byte]).await.unwrap();
            }
        });
        let mut tunnel = tunnel(client, "origin.invalid:443", None).await.unwrap();
        let mut out = Vec::new();
        tunnel.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"xyz");
        worker.await.unwrap();
    }

    fn test_certificate(names: &[&str], alpn: &[&[u8]]) -> (TlsAcceptor, NamedTempFile) {
        let key = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![key.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
                )
                .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        // Only this public test certificate touches disk; its freshly generated
        // private key remains in memory and is never a real credential.
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), key.cert.pem()).unwrap();
        (TlsAcceptor::from(Arc::new(config)), file)
    }

    async fn origin(
        names: &[&str],
        alpn: &[&[u8]],
    ) -> (Uri, NamedTempFile, tokio::task::JoinHandle<()>) {
        let (acceptor, cert) = test_certificate(names, alpn);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri = format!("https://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = tls.write_all(b"ok").await;
                let _ = tls.shutdown().await;
            }
        });
        (uri, cert, task)
    }

    async fn assert_greeting(mut stream: Box<dyn AsyncReadWrite>) {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"ok");
    }

    #[tokio::test]
    async fn direct_tls_accepts_custom_ca_and_requires_h2() {
        let (uri, cert, task) = origin(&["127.0.0.1"], &[b"h2"]).await;
        assert_greeting(connect_routed(&uri, Some(cert.path()), None).await.unwrap()).await;
        task.await.unwrap();
        let (uri, cert, task) = origin(&["127.0.0.1"], &[]).await;
        let error = connect_routed(&uri, Some(cert.path()), None)
            .await
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("did not negotiate HTTP/2"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_rejects_unknown_ca_and_wrong_hostname() {
        let (uri, _cert, task) = origin(&["127.0.0.1"], &[b"h2"]).await;
        assert!(connect_routed(&uri, None, None).await.is_err());
        task.await.unwrap();
        let (uri, cert, task) = origin(&["localhost"], &[b"h2"]).await;
        assert!(connect_routed(&uri, Some(cert.path()), None).await.is_err());
        task.await.unwrap();
    }

    async fn proxy_to(
        origin: &Uri,
        tls: Option<TlsAcceptor>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "{}://alice:unit-test@{}",
            if tls.is_some() { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let destination = socket_authority(origin).unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut client: Box<dyn AsyncReadWrite> = match tls {
                Some(acceptor) => {
                    let stream = acceptor.accept(tcp).await.unwrap();
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
                    Box::new(stream)
                }
                None => Box::new(tcp),
            };
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(client.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!("CONNECT {destination} HTTP/1.1\r\n")));
            assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6dW5pdC10ZXN0\r\n"));
            let mut upstream = TcpStream::connect(destination).await.unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });
        (url, task)
    }

    #[tokio::test]
    async fn origin_tls_works_through_http_and_https_connect() {
        for secure_proxy in [false, true] {
            let (uri, cert, origin_task) = origin(&["127.0.0.1"], &[b"h2"]).await;
            let (proxy_tls, proxy_cert) = test_certificate(&["127.0.0.1"], &[b"http/1.1"]);
            if secure_proxy {
                let mut bundle = std::fs::read(cert.path()).unwrap();
                bundle.extend(std::fs::read(proxy_cert.path()).unwrap());
                std::fs::write(cert.path(), bundle).unwrap();
            }
            let (url, proxy_task) = proxy_to(&uri, secure_proxy.then_some(proxy_tls)).await;
            let proxy = select_proxy(&uri, &url, "").unwrap();
            let stream = connect_routed(&uri, Some(cert.path()), proxy)
                .await
                .unwrap();
            assert_greeting(stream).await;
            origin_task.await.unwrap();
            proxy_task.await.unwrap();
        }
    }

    #[test]
    fn empty_and_malformed_custom_ca_are_rejected() {
        let cert = NamedTempFile::new().unwrap();
        assert!(load_roots(Some(cert.path())).is_err());
        std::fs::write(
            cert.path(),
            "-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_roots(Some(cert.path())).is_err());
    }
}
