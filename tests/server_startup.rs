//! Real-process startup/shutdown tests. All listeners are disposable loopback sockets.
#![cfg(unix)]
use std::{net::SocketAddr, path::PathBuf, process::Stdio, sync::OnceLock, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
    time::timeout,
};

struct Fixture {
    _dir: TempDir,
    config: PathBuf,
    cert: PathBuf,
}
impl Fixture {
    fn new(bind: SocketAddr) -> Self {
        static HASH: OnceLock<String> = OnceLock::new();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("test-cert.pem");
        let key = dir.path().join("test-key.pem");
        let config = dir.path().join("test-server.toml");
        let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        std::fs::write(&cert, generated.cert.pem()).unwrap();
        std::fs::write(&key, generated.signing_key.serialize_pem()).unwrap();
        let hash = HASH.get_or_init(|| {
            ssh_stream_gateway::auth::hash_password("unit-test-only-passphrase").unwrap()
        });
        std::fs::write(&config, format!(
            "bind = {bind:?}\ntls_cert = {cert:?}\ntls_key = {key:?}\npassword_hash = {hash:?}\n[targets.test]\nhost = \"example.invalid\"\nuser = \"test\"\nidentity_file = \"/NOT_USED_TEST_IDENTITY\"\nknown_hosts_file = \"/NOT_USED_TEST_HOSTS\"\n",
            bind=bind.to_string(), cert=cert.to_str().unwrap(), key=key.to_str().unwrap()
        )).unwrap();
        Self {
            _dir: dir,
            config,
            cert,
        }
    }
    fn spawn(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_ssh-stream-gateway"))
            .arg("serve")
            .arg("--config")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
}

#[tokio::test]
async fn sigterm_and_sigint_cleanly_stop_a_running_server() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let fixture = Fixture::new("127.0.0.1:0".parse().unwrap());
        let mut child = fixture.spawn();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        timeout(Duration::from_secs(3), stderr.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(line.contains("listening on https://127.0.0.1:"), "{line}");
        let pid = child.id().unwrap();
        // SAFETY: pid is the live test child we just spawned, not an unrelated process.
        assert_eq!(unsafe { libc::kill(pid as i32, signal) }, 0);
        let status = timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(0));
    }
}

#[tokio::test]
async fn occupied_port_is_a_fast_startup_error_not_an_interface_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(listener.local_addr().unwrap());
    let output = timeout(Duration::from_secs(3), fixture.spawn().wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("bind configured gateway listener"),
        "{stderr}"
    );
    assert!(!stderr.contains("waiting for interface"));
    assert!(!stderr.contains("listening on"));
}

#[tokio::test]
async fn missing_tls_material_fails_before_attempting_a_listener() {
    let fixture = Fixture::new("127.0.0.1:0".parse().unwrap());
    std::fs::remove_file(&fixture.cert).unwrap();
    let output = timeout(Duration::from_secs(3), fixture.spawn().wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("read TLS certificate"), "{stderr}");
    assert!(!stderr.contains("waiting for interface"));
    assert!(!stderr.contains("listening on"));
}
