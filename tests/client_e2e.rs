//! Real CLI tests against disposable loopback TLS/H2 peers. No SSH is launched.
#![cfg(unix)]

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::{
    convert::Infallible,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStderr, ChildStdout, Command},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

const PASSWORD: &str = "unit-test-only-passphrase";
const CONTENT_TYPE: &str = "application/vnd.ssh-stream.v1";
const READY: &[u8] = b"ready\n";
const FINAL_STDOUT: &[u8] = b"final\0\xff\n";
const FINAL_STDERR: &[u8] = b"diagnostic\0\xfe\n";
const DEADLINE: Duration = Duration::from_secs(3);
type ReplySender = mpsc::Sender<std::result::Result<Frame<Bytes>, Infallible>>;

#[derive(Clone, Copy)]
enum Scenario {
    Duplex,
    EarlyExit,
    MissingExit,
    Redirect,
}

struct Gateway {
    address: SocketAddr,
    ca: PathBuf,
    password: PathBuf,
    _fixtures: TempDir,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    results: mpsc::UnboundedReceiver<Result<()>>,
    task: JoinHandle<()>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    async fn start(scenario: Scenario) -> Self {
        let fixtures = tempfile::tempdir().unwrap();
        let ca = fixtures.path().join("loopback-certificate.pem");
        let password = fixtures.path().join("known-test-passphrase");
        let mut secret = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&password)
            .unwrap();
        writeln!(secret, "{PASSWORD}").unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        std::fs::write(&ca, key.cert.pem()).unwrap();
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
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let connection_count = connections.clone();
        let (results_tx, results) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        connection_count.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let request_count = request_count.clone();
                        let results_tx = results_tx.clone();
                        sessions.spawn(async move {
                            let tls = acceptor.accept(tcp).await.unwrap();
                            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                            let service = service_fn(move |request| {
                                request_count.fetch_add(1, Ordering::SeqCst);
                                let results_tx = results_tx.clone();
                                async move {
                                    let (tx, rx) = mpsc::channel(8);
                                    tokio::spawn(async move {
                                        let result = exchange(request, tx, scenario).await;
                                        let _ = results_tx.send(result);
                                    });
                                    let mut response = Response::builder().header("content-type", CONTENT_TYPE);
                                    if matches!(scenario, Scenario::Redirect) {
                                        response = response.status(StatusCode::TEMPORARY_REDIRECT)
                                            .header("location", format!("https://{address}/must-not-follow"));
                                    }
                                    Ok::<_, Infallible>(response.body(StreamBody::new(ReceiverStream::new(rx))).unwrap())
                                }
                            });
                            // A client may close immediately after Exit or reject a redirect.
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls), service).await;
                        });
                    }
                    Some(completed) = sessions.join_next(), if !sessions.is_empty() => { completed.unwrap(); }
                }
            }
        });
        Self {
            address,
            ca,
            password,
            _fixtures: fixtures,
            requests,
            connections,
            results,
            task,
        }
    }

    fn child(&self, proxy: Option<&str>) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ssh-stream-gateway"));
        command
            .arg("exec")
            .arg("--endpoint")
            .arg(format!("https://{}/", self.address))
            .arg("--ca")
            .arg(&self.ca)
            .arg("--password-file")
            .arg(&self.password)
            .arg("test-target")
            .arg("printf protocol-test")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Never mutate the test runner's environment or inherit an external proxy.
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            command.env_remove(name);
        }
        if let Some(proxy) = proxy {
            command.env("HTTPS_PROXY", proxy);
        }
        command.spawn().unwrap()
    }

    async fn checked_exchange(&mut self) {
        tokio::time::timeout(DEADLINE, self.results.recv())
            .await
            .expect("fake gateway exchange exceeded three seconds")
            .expect("fake gateway exchange disappeared")
            .unwrap();
        assert_eq!(
            self.requests.load(Ordering::SeqCst),
            1,
            "command was retried"
        );
        assert_eq!(
            self.connections.load(Ordering::SeqCst),
            1,
            "transport was retried"
        );
    }
}

// This independently reads and writes the wire format rather than sharing the
// production codec, so mismatched lengths, kind bytes, and JSON are detectable.
async fn frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let length = reader.read_u32().await? as usize;
    ensure!(length <= 16 * 1024, "oversized client frame");
    let mut data = vec![0; length];
    reader.read_exact(&mut data).await?;
    Ok(Some((kind[0], data)))
}

async fn send(tx: &ReplySender, kind: u8, data: &[u8]) -> Result<()> {
    let mut bytes = Vec::with_capacity(5 + data.len());
    bytes.push(kind);
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(data);
    tx.send(Ok(Frame::data(Bytes::from(bytes))))
        .await
        .context("client stopped reading")
}

fn input_bytes() -> Vec<u8> {
    (0..131_077).map(|i| (i % 256) as u8).collect()
}

async fn exchange(request: Request<Incoming>, tx: ReplySender, scenario: Scenario) -> Result<()> {
    ensure!(
        request.version() == Version::HTTP_2,
        "request is not HTTP/2"
    );
    ensure!(
        request.method() == "POST" && request.uri().path() == "/v1/exec",
        "wrong method or path"
    );
    ensure!(
        request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some(CONTENT_TYPE),
        "wrong protocol content type"
    );
    ensure!(
        request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {PASSWORD}")),
        "missing origin authorization"
    );
    ensure!(
        !request.headers().contains_key("proxy-authorization"),
        "proxy credentials leaked to origin"
    );
    let input = request
        .into_body()
        .into_data_stream()
        .map_err(std::io::Error::other);
    let mut reader = StreamReader::new(input);
    let (kind, data) = frame(&mut reader).await?.context("missing OPEN frame")?;
    ensure!(kind == 1, "first frame is not OPEN");
    let open: serde_json::Value = serde_json::from_slice(&data)?;
    ensure!(
        open == serde_json::json!({"target": "test-target", "command": "printf protocol-test"}),
        "wrong OPEN payload"
    );
    if matches!(scenario, Scenario::Redirect) {
        return Ok(());
    }
    send(&tx, 17, READY).await?;
    match scenario {
        Scenario::Duplex => {
            let mut received = Vec::new();
            loop {
                let (kind, data) = frame(&mut reader)
                    .await?
                    .context("request ended before EOF")?;
                match kind {
                    2 => {
                        ensure!(!data.is_empty(), "empty STDIN frame");
                        received.extend_from_slice(&data);
                    }
                    3 => {
                        ensure!(data.is_empty(), "EOF frame has payload");
                        break;
                    }
                    _ => anyhow::bail!("unexpected request frame {kind}"),
                }
            }
            ensure!(received == input_bytes(), "binary stdin was corrupted");
            ensure!(
                frame(&mut reader).await?.is_none(),
                "request continued after EOF"
            );
            send(&tx, 17, FINAL_STDOUT).await?;
            send(&tx, 18, FINAL_STDERR).await?;
            send(&tx, 19, br#"{"code":42,"error":null}"#).await?;
        }
        Scenario::EarlyExit => {
            // Give Tokio's blocking stdin reader time to start, with the parent
            // intentionally holding the write end open and sending no bytes.
            tokio::time::sleep(Duration::from_millis(100)).await;
            send(&tx, 19, br#"{"code":0,"error":null}"#).await?;
            drop(tx);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Scenario::MissingExit => {
            // A clean HTTP response end without a protocol Exit is still an
            // unknown command outcome and must never cause automatic retry.
            drop(tx);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Scenario::Redirect => unreachable!(),
    }
    Ok(())
}

async fn output(mut child: Child, mut stdout: ChildStdout, mut stderr: ChildStderr) -> Output {
    tokio::time::timeout(DEADLINE, async move {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (_, _, status) = tokio::try_join!(
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err),
            child.wait()
        )
        .unwrap();
        Output {
            status,
            stdout: out,
            stderr: err,
        }
    })
    .await
    .expect("client did not exit within three seconds")
}

async fn duplex(proxy_enabled: bool) {
    let mut gateway = Gateway::start(Scenario::Duplex).await;
    let proxy = if proxy_enabled {
        Some(ConnectProxy::start(gateway.address).await)
    } else {
        None
    };
    let mut child = gateway.child(proxy.as_ref().map(|p| p.url.as_str()));
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut ready = vec![0; READY.len()];
    // No stdin has been sent yet: receiving this proves response streaming
    // starts before EOF rather than buffering the complete request.
    tokio::time::timeout(DEADLINE, stdout.read_exact(&mut ready))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready, READY);
    tokio::time::timeout(DEADLINE, async {
        stdin.write_all(&input_bytes()).await.unwrap();
        stdin.shutdown().await.unwrap();
    })
    .await
    .expect("client stopped accepting streamed stdin");
    drop(stdin);
    let result = output(child, stdout, stderr).await;
    assert_eq!(
        result.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, FINAL_STDOUT);
    assert_eq!(result.stderr, FINAL_STDERR);
    gateway.checked_exchange().await;
    if let Some(mut proxy) = proxy {
        proxy.checked().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_streams_binary_stdin_stdout_stderr_and_exit_status() {
    duplex(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_streams_verified_tls_inside_http_connect_without_leaking_credentials() {
    duplex(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_exits_when_remote_finishes_even_if_local_stdin_stays_open() {
    let mut gateway = Gateway::start(Scenario::EarlyExit).await;
    let mut child = gateway.child(None);
    let held_open = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = output(child, stdout, stderr).await;
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, READY);
    assert!(result.stderr.is_empty());
    drop(held_open);
    gateway.checked_exchange().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reports_unknown_outcome_after_missing_exit_and_never_retries() {
    let mut gateway = Gateway::start(Scenario::MissingExit).await;
    let mut child = gateway.child(None);
    drop(child.stdin.take());
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = output(child, stdout, stderr).await;
    assert_eq!(result.status.code(), Some(125));
    assert_eq!(result.stdout, READY);
    assert!(String::from_utf8_lossy(&result.stderr).contains("command outcome is unknown"));
    gateway.checked_exchange().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rejects_redirects_without_resending_a_command_or_credentials() {
    let mut gateway = Gateway::start(Scenario::Redirect).await;
    let mut child = gateway.child(None);
    drop(child.stdin.take());
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = output(child, stdout, stderr).await;
    assert_eq!(result.status.code(), Some(125));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("HTTP 307"));
    gateway.checked_exchange().await;
}

struct ConnectProxy {
    url: String,
    results: mpsc::UnboundedReceiver<Result<()>>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for ConnectProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ConnectProxy {
    async fn start(destination: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://proxy-user:proxy-test@{}",
            listener.local_addr().unwrap()
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let (results_tx, results) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let results_tx = results_tx.clone();
                        sessions.spawn(async move { let _ = results_tx.send(proxy_exchange(client, destination).await); });
                    }
                    Some(result) = sessions.join_next(), if !sessions.is_empty() => { result.unwrap(); }
                }
            }
        });
        Self {
            url,
            results,
            connections,
            task,
        }
    }
    async fn checked(&mut self) {
        tokio::time::timeout(DEADLINE, self.results.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.connections.load(Ordering::SeqCst), 1);
    }
}

async fn proxy_exchange(mut client: TcpStream, destination: SocketAddr) -> Result<()> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < 16 * 1024, "oversized CONNECT request");
        header.push(client.read_u8().await?);
    }
    let header = String::from_utf8(header)?;
    ensure!(
        header.starts_with(&format!("CONNECT {destination} HTTP/1.1\r\n")),
        "wrong proxy destination"
    );
    ensure!(
        header.contains(&format!("Host: {destination}\r\n")),
        "missing CONNECT Host"
    );
    ensure!(
        header.contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS10ZXN0\r\n"),
        "missing proxy authentication"
    );
    ensure!(
        !header.contains(PASSWORD) && !header.to_ascii_lowercase().contains("\r\nauthorization:"),
        "origin credential leaked to proxy"
    );
    let mut upstream = TcpStream::connect(destination).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    // Everything after CONNECT is end-to-end TLS. The proxy never parses or
    // terminates it; origin validation separately checks its Bearer header.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}
