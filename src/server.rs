use crate::{
    auth,
    config::Config,
    protocol::{self, Exit, Open},
    ssh,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Child,
    sync::{Semaphore, mpsc, watch},
    time::{Instant, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{io::StreamReader, sync::CancellationToken};
use zeroize::Zeroizing;

type Output = mpsc::Sender<Result<Frame<Bytes>, Infallible>>;
type Body = StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>;
struct State {
    config: Config,
    attempts: Mutex<auth::Attempts>,
    auth_slots: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
    shutdown: CancellationToken,
    #[cfg(test)]
    fake_command: Option<fn(&str) -> tokio::process::Command>,
}
impl State {
    fn new(config: Config, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            sessions: Arc::new(Semaphore::new(config.max_sessions)),
            config,
            attempts: Mutex::new(auth::Attempts::default()),
            auth_slots: Arc::new(Semaphore::new(2)),
            shutdown,
            #[cfg(test)]
            fake_command: None,
        })
    }
    async fn authenticate(&self, headers: &http::HeaderMap) -> std::result::Result<(), StatusCode> {
        if headers.get_all(http::header::AUTHORIZATION).iter().count() != 1 {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let password = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| auth::check_password(s).is_ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let slot = self
            .auth_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        if !self.attempts.lock().unwrap().take() {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let hash = self.config.password_hash.clone();
        let valid = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            auth::verify(&hash, &password)
        })
        .await
        .unwrap_or(false);
        if !valid {
            return Err(StatusCode::UNAUTHORIZED);
        }
        self.attempts.lock().unwrap().success();
        Ok(())
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<Body> {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(Ok(Frame::data(Bytes::from_static(message.as_bytes()))))
        .ok();
    let mut result = Response::builder()
        .status(status)
        .header("cache-control", "no-store");
    if status == StatusCode::TOO_MANY_REQUESTS {
        result = result.header("retry-after", "12");
    }
    result
        .body(StreamBody::new(ReceiverStream::new(rx)))
        .unwrap()
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> std::result::Result<Response<Body>, Infallible> {
    if request.method() != http::Method::POST
        || request.uri().path() != "/v1/exec"
        || request.uri().query().is_some()
    {
        return Ok(response(StatusCode::NOT_FOUND, "not found\n"));
    }
    if request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        != Some(protocol::CONTENT_TYPE)
    {
        return Ok(response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported protocol\n",
        ));
    }
    if let Err(status) = state.authenticate(request.headers()).await {
        return Ok(response(status, "authentication unavailable or rejected\n"));
    }
    let permit = match state.sessions.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                "session limit reached\n",
            ));
        }
    };
    let stream = request
        .into_body()
        .into_data_stream()
        .map_err(std::io::Error::other);
    let mut reader = StreamReader::new(stream);
    let open = match timeout(Duration::from_secs(10), protocol::read(&mut reader)).await {
        Ok(Ok(Some((protocol::OPEN, data)))) => serde_json::from_slice::<Open>(&data).ok(),
        _ => None,
    };
    let Some(open) = open else {
        return Ok(response(StatusCode::BAD_REQUEST, "invalid opening frame\n"));
    };
    if !crate::config::alias_valid(&open.target)
        || open.command.is_empty()
        || open.command.len() > 8192
        || open.command.contains('\0')
    {
        return Ok(response(StatusCode::BAD_REQUEST, "invalid request\n"));
    }
    let Some(target) = state.config.targets.get(&open.target) else {
        return Ok(response(StatusCode::FORBIDDEN, "target not allowed\n"));
    };
    let mut command = ssh::command(target, &open.command);
    #[cfg(test)]
    if let Some(fake) = state.fake_command {
        command = fake(&open.command);
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return Ok(response(StatusCode::BAD_GATEWAY, "could not start SSH\n")),
    };
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let _permit = permit;
        run_session(
            child,
            reader,
            tx,
            state.config.session_seconds,
            state.config.idle_seconds,
            state.shutdown.clone(),
        )
        .await;
    });
    Ok(Response::builder()
        .header("content-type", protocol::CONTENT_TYPE)
        .header("cache-control", "no-store")
        .body(StreamBody::new(ReceiverStream::new(rx)))
        .unwrap())
}

async fn send(tx: &Output, kind: u8, payload: &[u8]) -> Result<()> {
    tx.send(Ok(Frame::data(protocol::encode(kind, payload)?)))
        .await
        .map_err(|_| anyhow::anyhow!("client disconnected"))
}
async fn pipe_output<R: AsyncRead + Unpin>(
    mut reader: R,
    kind: u8,
    tx: &Output,
    activity: &watch::Sender<Instant>,
) -> Result<()> {
    let mut buffer = vec![0; protocol::MAX_FRAME];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        send(tx, kind, &buffer[..n]).await?;
        activity.send_replace(Instant::now());
    }
}
async fn pipe_input<R: AsyncRead + Unpin>(
    mut reader: R,
    stdin: tokio::process::ChildStdin,
    activity: &watch::Sender<Instant>,
) -> Result<()> {
    let mut eof = false;
    let mut stdin = Some(stdin);
    loop {
        match protocol::read(&mut reader).await? {
            Some((protocol::STDIN, data)) if !eof && !data.is_empty() => {
                if let Err(error) = stdin.as_mut().unwrap().write_all(&data).await {
                    if error.kind() == std::io::ErrorKind::BrokenPipe {
                        drop(stdin.take());
                        return std::future::pending().await;
                    }
                    return Err(error.into());
                }
                activity.send_replace(Instant::now());
            }
            Some((protocol::EOF, data)) if !eof && data.is_empty() => {
                drop(stdin.take());
                eof = true;
                activity.send_replace(Instant::now());
            }
            Some((protocol::CANCEL, data)) if data.is_empty() => bail!("cancelled"),
            None if eof => return std::future::pending().await,
            _ => bail!("invalid input sequence"),
        }
    }
}
async fn idle(mut activity: watch::Receiver<Instant>, seconds: u64) {
    loop {
        let deadline = *activity.borrow_and_update() + Duration::from_secs(seconds);
        tokio::select! { _=tokio::time::sleep_until(deadline)=>return, result=activity.changed()=>if result.is_err() {return} }
    }
}
async fn run_session<R: AsyncRead + Unpin>(
    mut child: Child,
    reader: R,
    tx: Output,
    seconds: u64,
    idle_seconds: u64,
    shutdown: CancellationToken,
) {
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (activity, updates) = watch::channel(Instant::now());
    let result: std::result::Result<std::process::ExitStatus, &str> = {
        let complete = async {
            let (status, (), ()) = tokio::try_join!(
                async { child.wait().await.map_err(anyhow::Error::from) },
                pipe_output(stdout, protocol::STDOUT, &tx, &activity),
                pipe_output(stderr, protocol::STDERR, &tx, &activity)
            )?;
            Ok::<_, anyhow::Error>(status)
        };
        tokio::select! {
            result=complete=>result.map_err(|_|"stream_failure"),
            _=pipe_input(reader,stdin,&activity)=>Err("input_cancelled_or_invalid"),
            _=tx.closed()=>Err("client_disconnected"),
            _=idle(updates,idle_seconds)=>Err("idle_timeout"),
            _=tokio::time::sleep(Duration::from_secs(seconds))=>Err("session_timeout"),
            _=shutdown.cancelled()=>Err("server_shutdown"),
        }
    };
    let exit = match result {
        Ok(status) => Exit {
            code: status.code().unwrap_or(255),
            error: None,
        },
        Err(reason) => {
            // kill().await both signals and reaps. kill_on_drop is only a fallback.
            let _ = child.kill().await;
            Exit {
                code: if reason.ends_with("timeout") {
                    124
                } else {
                    125
                },
                error: Some(reason.into()),
            }
        }
    };
    if let Ok(data) = serde_json::to_vec(&exit) {
        let _ = timeout(Duration::from_secs(2), send(&tx, protocol::EXIT, &data)).await;
    }
}

pub async fn serve(config: Config) -> Result<()> {
    config.validate()?;
    let certs = CertificateDer::pem_file_iter(&config.tls_cert)
        .context("read TLS certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse TLS certificate")?;
    let key = PrivateKeyDer::from_pem_file(&config.tls_key).context("read TLS private key")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("configure server TLS")?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(config.bind)
        .await
        .context("bind gateway listener")?;
    eprintln!(
        "SSH streaming gateway listening on https://{} (HTTP/2)",
        listener.local_addr()?
    );
    let shutdown = CancellationToken::new();
    let state = State::new(config, shutdown.clone());
    let connections = Arc::new(Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=term.recv()=>break,
            Some(_)=tasks.join_next()=>{},
            incoming=listener.accept()=>{
                let (socket,_)=incoming?;
                let Ok(permit)=connections.clone().try_acquire_owned() else {drop(socket);continue};
                let acceptor=acceptor.clone(); let state=state.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(tls))=timeout(Duration::from_secs(10),acceptor.accept(socket)).await else {return};
                    if tls.get_ref().1.alpn_protocol()!=Some(b"h2") {return}
                    let cancel=state.shutdown.clone();
                    let service=service_fn(move|request|handle(request,state.clone()));
                    let mut builder=hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                    builder.max_concurrent_streams(4).max_header_list_size(8192).initial_stream_window_size(65536).initial_connection_window_size(262144).max_send_buf_size(65536);
                    let connection=builder.serve_connection(TokioIo::new(tls),service);
                    tokio::select! { _=connection=>{}, _=cancel.cancelled()=>{} }
                });
            }
        }
    }
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    // Active sessions own permits until child cleanup completes; wait for all of them.
    let _ = timeout(
        Duration::from_secs(10),
        state
            .sessions
            .acquire_many(state.config.max_sessions as u32),
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Target;
    use std::{collections::BTreeMap, process::Stdio, sync::OnceLock};
    use tokio::io::AsyncWriteExt;
    const TEST_PASSWORD: &str = "unit-test-only-passphrase";
    fn config() -> Config {
        static HASH: OnceLock<String> = OnceLock::new();
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert: "/tmp/not-used-cert".into(),
            tls_key: "/tmp/not-used-key".into(),
            password_hash: HASH
                .get_or_init(|| auth::hash_password(TEST_PASSWORD).unwrap())
                .clone(),
            max_sessions: 2,
            session_seconds: 10,
            idle_seconds: 5,
            targets: BTreeMap::from([(
                "test".into(),
                Target {
                    host: "example.test".into(),
                    port: 22,
                    user: "worker".into(),
                    identity_file: "/tmp/not-used-identity".into(),
                    known_hosts_file: "/tmp/not-used-hosts".into(),
                    identity_agent: None,
                },
            )]),
        }
    }
    fn fake(name: &str) -> tokio::process::Command {
        let mut cmd = match name {
            "cat" => tokio::process::Command::new("/bin/cat"),
            "sleep" => {
                let mut c = tokio::process::Command::new("/bin/sleep");
                c.arg("60");
                c
            }
            "output" => {
                let mut c = tokio::process::Command::new("/bin/sh");
                c.args(["-c", "printf 'out'; printf 'err' >&2; exit 42"]);
                c
            }
            "duplex" => {
                let mut c = tokio::process::Command::new("/bin/sh");
                c.args(["-c", "printf 'ready'; cat; printf 'done' >&2; exit 7"]);
                c
            }
            _ => panic!("unrecognized fake command"),
        };
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
    async fn frames(
        mut rx: mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
    ) -> (Vec<u8>, Vec<u8>, Exit) {
        let mut out = vec![];
        let mut err = vec![];
        while let Some(frame) = rx.recv().await {
            let bytes = frame.unwrap().into_data().unwrap();
            let (kind, data) = protocol::read(&mut &bytes[..]).await.unwrap().unwrap();
            match kind {
                protocol::STDOUT => out.extend(data),
                protocol::STDERR => err.extend(data),
                protocol::EXIT => return (out, err, serde_json::from_slice(&data).unwrap()),
                _ => panic!("unexpected frame"),
            }
        }
        panic!("missing exit")
    }
    async fn write(writer: &mut (impl tokio::io::AsyncWrite + Unpin), kind: u8, data: &[u8]) {
        writer
            .write_all(&protocol::encode(kind, data).unwrap())
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn binary_stdin_eof_closes_only_child_input() {
        let child = fake("cat").spawn().unwrap();
        let (mut writer, reader) = tokio::io::duplex(65536);
        let (tx, rx) = mpsc::channel(8);
        let task = tokio::spawn(run_session(
            child,
            reader,
            tx,
            5,
            3,
            CancellationToken::new(),
        ));
        let data = vec![0, 255, 10, 13, 1, 2];
        write(&mut writer, protocol::STDIN, &data).await;
        write(&mut writer, protocol::EOF, &[]).await;
        // Keep request stream open: protocol EOF must really close the pipe FD.
        let (out, err, status) = timeout(Duration::from_secs(2), frames(rx)).await.unwrap();
        assert_eq!(out, data);
        assert!(err.is_empty());
        assert_eq!(
            status,
            Exit {
                code: 0,
                error: None
            }
        );
        task.await.unwrap();
        drop(writer);
    }
    #[tokio::test]
    async fn separate_output_and_remote_early_exit_survive_busy_input() {
        let child = fake("output").spawn().unwrap();
        let (mut writer, reader) = tokio::io::duplex(65536);
        let (tx, rx) = mpsc::channel(8);
        let task = tokio::spawn(run_session(
            child,
            reader,
            tx,
            5,
            3,
            CancellationToken::new(),
        ));
        let input = tokio::spawn(async move {
            let data = protocol::encode(protocol::STDIN, &vec![0; 16384]).unwrap();
            loop {
                if writer.write_all(&data).await.is_err() {
                    break;
                }
            }
        });
        let (out, err, status) = timeout(Duration::from_secs(2), frames(rx)).await.unwrap();
        assert_eq!(out, b"out");
        assert_eq!(err, b"err");
        assert_eq!(
            status,
            Exit {
                code: 42,
                error: None
            }
        );
        task.await.unwrap();
        input.abort();
    }
    #[tokio::test]
    async fn cancel_disconnect_and_invalid_input_reap_child() {
        for mode in ["cancel", "disconnect", "invalid"] {
            let child = fake("sleep").spawn().unwrap();
            let pid = child.id().unwrap();
            let (mut writer, reader) = tokio::io::duplex(65536);
            let (tx, rx) = mpsc::channel(8);
            let task = tokio::spawn(run_session(
                child,
                reader,
                tx,
                10,
                5,
                CancellationToken::new(),
            ));
            if mode == "disconnect" {
                drop(rx)
            } else {
                write(
                    &mut writer,
                    if mode == "cancel" {
                        protocol::CANCEL
                    } else {
                        protocol::STDOUT
                    },
                    &[],
                )
                .await;
                let (_, _, status) = frames(rx).await;
                assert_eq!(status.code, 125);
            }
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            // SAFETY: kill(pid, 0) only queries existence; no signal is delivered.
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        }
    }
    #[tokio::test]
    async fn disconnect_unblocks_a_full_stdin_pipe() {
        let child = fake("sleep").spawn().unwrap();
        let pid = child.id().unwrap();
        let (mut writer, reader) = tokio::io::duplex(65536);
        let (tx, rx) = mpsc::channel(8);
        let task = tokio::spawn(run_session(
            child,
            reader,
            tx,
            10,
            5,
            CancellationToken::new(),
        ));
        let input = tokio::spawn(async move {
            let data = protocol::encode(protocol::STDIN, &vec![0; 16384]).unwrap();
            loop {
                if writer.write_all(&data).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(rx);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        input.abort();
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }
    #[tokio::test]
    async fn wall_and_idle_deadlines_kill_and_reap() {
        for (wall, idle_time, reason) in [(1, 10, "session_timeout"), (10, 1, "idle_timeout")] {
            let child = fake("sleep").spawn().unwrap();
            let pid = child.id().unwrap();
            let (_writer, reader) = tokio::io::duplex(1024);
            let (tx, rx) = mpsc::channel(8);
            let task = tokio::spawn(run_session(
                child,
                reader,
                tx,
                wall,
                idle_time,
                CancellationToken::new(),
            ));
            let (_, _, status) = timeout(Duration::from_secs(3), frames(rx)).await.unwrap();
            assert_eq!(status.code, 124);
            assert_eq!(status.error.as_deref(), Some(reason));
            task.await.unwrap();
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        }
    }
    async fn h2_request(
        state: Arc<State>,
        password: &str,
        target: &str,
        command: &str,
    ) -> (Response<Incoming>, Output, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |req| handle(req, state.clone())),
                )
                .await;
        });
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                .await
                .unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (tx, rx) = mpsc::channel(8);
        send(
            &tx,
            protocol::OPEN,
            &serde_json::to_vec(&Open {
                target: target.into(),
                command: command.into(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let request = Request::post("https://localhost/v1/exec")
            .header("content-type", protocol::CONTENT_TYPE)
            .header("authorization", format!("Bearer {password}"))
            .body(StreamBody::new(ReceiverStream::new(rx)))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        (response, tx, task)
    }
    #[tokio::test]
    async fn authentication_and_allowlist_precede_spawn() {
        fn forbidden(_: &str) -> tokio::process::Command {
            panic!("SSH must not spawn");
        }
        let mut state = State::new(config(), CancellationToken::new());
        Arc::get_mut(&mut state).unwrap().fake_command = Some(forbidden);
        for (pass, target, status) in [
            (
                "wrong-but-long-passphrase",
                "test",
                StatusCode::UNAUTHORIZED,
            ),
            (TEST_PASSWORD, "not-allowed", StatusCode::FORBIDDEN),
        ] {
            let (response, _, task) = h2_request(state.clone(), pass, target, "cat").await;
            assert_eq!(response.status(), status);
            task.abort();
        }
    }
    #[tokio::test]
    async fn h2_duplex_delivers_output_before_stdin_eof() {
        let mut state = State::new(config(), CancellationToken::new());
        Arc::get_mut(&mut state).unwrap().fake_command = Some(fake);
        let (response, tx, task) = h2_request(state, TEST_PASSWORD, "test", "duplex").await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut reader = StreamReader::new(
            response
                .into_body()
                .into_data_stream()
                .map_err(std::io::Error::other),
        );
        let ready = timeout(Duration::from_secs(2), protocol::read(&mut reader))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(ready, (protocol::STDOUT, b"ready".to_vec()));
        send(&tx, protocol::STDIN, b"\0binary\xff\n").await.unwrap();
        send(&tx, protocol::EOF, &[]).await.unwrap();
        let mut out = vec![];
        let mut err = vec![];
        let status = loop {
            let (kind, data) = timeout(Duration::from_secs(2), protocol::read(&mut reader))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match kind {
                protocol::STDOUT => out.extend(data),
                protocol::STDERR => err.extend(data),
                protocol::EXIT => break serde_json::from_slice::<Exit>(&data).unwrap(),
                _ => panic!(),
            }
        };
        assert_eq!(out, b"\0binary\xff\n");
        assert_eq!(err, b"done");
        assert_eq!(status.code, 7);
        task.abort();
    }
    #[tokio::test]
    async fn session_limit_rejects_additional_authenticated_session() {
        let mut cfg = config();
        cfg.max_sessions = 1;
        let mut state = State::new(cfg, CancellationToken::new());
        Arc::get_mut(&mut state).unwrap().fake_command = Some(fake);
        let (first, tx, one) = h2_request(state.clone(), TEST_PASSWORD, "test", "sleep").await;
        assert!(first.status().is_success());
        let (second, _, two) = h2_request(state, TEST_PASSWORD, "test", "sleep").await;
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(first);
        drop(tx);
        one.abort();
        two.abort();
    }
}
