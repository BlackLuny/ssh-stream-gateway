use crate::{
    auth,
    protocol::{self, Exit, Open},
    transport,
};
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Request, Uri};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;

pub struct Options {
    pub endpoint: String,
    pub ca: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub target: String,
    pub command: String,
}
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn endpoint(value: &str) -> Result<Uri> {
    let uri: Uri = value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid endpoint URL"))?;
    ensure!(
        uri.scheme_str() == Some("https") && uri.authority().is_some(),
        "endpoint must be an absolute HTTPS URL"
    );
    ensure!(
        !uri.authority().unwrap().as_str().contains('@'),
        "endpoint must not contain credentials"
    );
    ensure!(
        uri.query().is_none() && matches!(uri.path(), "" | "/" | "/v1/exec"),
        "endpoint path must be / or /v1/exec without a query"
    );
    let mut parts = uri.into_parts();
    parts.path_and_query = Some("/v1/exec".parse().unwrap());
    Ok(Uri::from_parts(parts)?)
}

pub async fn execute(options: Options) -> Result<i32> {
    let uri = endpoint(&options.endpoint)?;
    ensure!(
        crate::config::alias_valid(&options.target),
        "invalid target alias"
    );
    ensure!(
        !options.command.is_empty()
            && options.command.len() <= 8192
            && !options.command.contains('\0'),
        "remote command must be 1..8192 bytes without NUL"
    );
    let password = auth::read_password(options.password_file.as_deref())?;
    let stream = transport::connect(&uri, options.ca.as_deref()).await?;
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .initial_stream_window_size(65536)
        .initial_connection_window_size(262144)
        .max_send_buf_size(65536)
        .max_header_list_size(8192);
    let (mut sender, connection) = tokio::time::timeout(
        Duration::from_secs(10),
        builder.handshake(TokioIo::new(stream)),
    )
    .await
    .context("HTTP/2 handshake timed out")??;
    let _connection = AbortOnDrop(tokio::spawn(connection));
    let (tx, rx) = mpsc::channel::<std::result::Result<Frame<Bytes>, Infallible>>(8);
    let open = serde_json::to_vec(&Open {
        target: options.target,
        command: options.command,
    })?;
    tx.send(Ok(Frame::data(protocol::encode(protocol::OPEN, &open)?)))
        .await?;
    let mut authorization = http::HeaderValue::from_str(&format!("Bearer {}", *password))
        .map_err(|_| anyhow::anyhow!("invalid passphrase header"))?;
    authorization.set_sensitive(true);
    drop(password);
    let request = Request::post(uri)
        .header("authorization", authorization)
        .header("content-type", protocol::CONTENT_TYPE)
        .body(StreamBody::new(ReceiverStream::new(rx)))?;
    // Never retry a command or follow a redirect: execution may already have begun.
    let response = tokio::time::timeout(Duration::from_secs(20), sender.send_request(request))
        .await
        .context("gateway response timed out")?
        .context("gateway connection failed")?;
    ensure!(
        response.status().is_success(),
        "gateway rejected request (HTTP {})",
        response.status().as_u16()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            == Some(protocol::CONTENT_TYPE),
        "gateway returned an unexpected protocol"
    );
    let input = AbortOnDrop(tokio::spawn(async move {
        let mut input = tokio::io::stdin();
        let mut buffer = vec![0; protocol::MAX_FRAME];
        loop {
            let n = input.read(&mut buffer).await?;
            let frame = protocol::encode(
                if n == 0 {
                    protocol::EOF
                } else {
                    protocol::STDIN
                },
                &buffer[..n],
            )?;
            if tx.send(Ok(Frame::data(frame))).await.is_err() {
                return Ok::<(), anyhow::Error>(());
            }
            if n == 0 {
                return Ok(());
            }
        }
    }));
    let read = async {
        let stream = response
            .into_body()
            .into_data_stream()
            .map_err(std::io::Error::other);
        let mut reader = StreamReader::new(stream);
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        while let Some((kind, data)) = protocol::read(&mut reader).await? {
            match kind {
                protocol::STDOUT => {
                    ensure!(!data.is_empty(), "empty output frame");
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                protocol::STDERR => {
                    ensure!(!data.is_empty(), "empty error frame");
                    stderr.write_all(&data).await?;
                    stderr.flush().await?;
                }
                protocol::EXIT => {
                    let status: Exit =
                        serde_json::from_slice(&data).context("invalid exit frame")?;
                    ensure!((0..=255).contains(&status.code), "invalid exit status");
                    if let Some(error) = status.error {
                        // Do not print arbitrary server text or control sequences.
                        let known = matches!(
                            error.as_str(),
                            "stream_failure"
                                | "input_cancelled_or_invalid"
                                | "client_disconnected"
                                | "idle_timeout"
                                | "session_timeout"
                                | "server_shutdown"
                        );
                        eprintln!(
                            "gateway session ended: {}",
                            if known {
                                error.as_str()
                            } else {
                                "remote_error"
                            }
                        );
                    }
                    return Ok(status.code);
                }
                _ => bail!("unexpected server frame"),
            }
        }
        bail!("gateway disconnected without an exit status; command outcome is unknown")
    };
    tokio::pin!(read);
    let mut input = input;
    tokio::select! {
        result=&mut read=>result,
        result=&mut input.0=>{
            result.context("stdin task failed")??;
            // EOF only half-closes input; keep reading both output streams.
            tokio::select! { result=&mut read=>result, _=tokio::signal::ctrl_c()=>Ok(130) }
        },
        _=tokio::signal::ctrl_c()=>Ok(130),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_requires_https_and_exact_path() {
        assert_eq!(endpoint("https://example.test").unwrap().path(), "/v1/exec");
        for url in [
            "http://example.test",
            "https://user:password@example.test",
            "https://example.test/other",
            "https://example.test/?token=x",
            "//example.test",
        ] {
            assert!(endpoint(url).is_err());
        }
    }
}
