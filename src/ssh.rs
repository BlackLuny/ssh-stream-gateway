//! Only this module constructs a local process. No shell or client-controlled SSH flags.
use crate::config::Target;
use std::{ffi::OsString, process::Stdio};
use tokio::process::Command;

pub fn arguments(target: &Target, remote_command: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "-F",
        "/dev/null",
        "-T",
        "-a",
        "-x",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oUpdateHostKeys=no",
        "-oGlobalKnownHostsFile=/dev/null",
        "-oKnownHostsCommand=none",
        "-oProxyCommand=none",
        "-oProxyJump=none",
        "-oPermitLocalCommand=no",
        "-oLocalCommand=none",
        "-oClearAllForwardings=yes",
        "-oForwardAgent=no",
        "-oForwardX11=no",
        "-oControlMaster=no",
        "-oControlPath=none",
        "-oControlPersist=no",
        "-oIdentitiesOnly=yes",
        "-oIdentityFile=none",
        "-oPasswordAuthentication=no",
        "-oKbdInteractiveAuthentication=no",
        "-oPreferredAuthentications=publickey",
        "-oConnectTimeout=15",
        "-oConnectionAttempts=1",
        "-oServerAliveInterval=15",
        "-oServerAliveCountMax=3",
        "-oEscapeChar=none",
        "-oLogLevel=ERROR",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    // Options supplied once: OpenSSH uses the first value, not the last.
    args.push(
        format!(
            "-oUserKnownHostsFile=\"{}\"",
            target.known_hosts_file.display()
        )
        .into(),
    );
    args.push(
        format!(
            "-oIdentityAgent={}",
            target
                .identity_agent
                .as_ref()
                .map_or_else(|| "none".into(), |p| format!("\"{}\"", p.display()))
        )
        .into(),
    );
    args.extend([
        OsString::from("-i"),
        target.identity_file.as_os_str().to_owned(),
        "-p".into(),
        target.port.to_string().into(),
        "-l".into(),
        target.user.clone().into(),
        "--".into(),
        target.host.clone().into(),
        remote_command.into(),
    ]);
    args
}

pub fn command(target: &Target, remote_command: &str) -> Command {
    let mut command = Command::new("/usr/bin/ssh");
    command
        .args(arguments(target, remote_command))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_arguments_are_fixed_and_remote_shell_is_explicit() {
        let t = Target {
            host: "example.test".into(),
            port: 22,
            user: "worker".into(),
            identity_file: "/tmp/key path".into(),
            known_hosts_file: "/tmp/host keys".into(),
            identity_agent: None,
        };
        let shell = "echo hi; $(touch /tmp/not-local)";
        let args = arguments(&t, shell);
        assert_eq!(args.last().unwrap(), shell);
        assert_eq!(
            &args[args.len() - 3..args.len() - 1],
            &[OsString::from("--"), OsString::from("example.test")]
        );
        for expected in [
            "-oForwardAgent=no",
            "-oIdentityAgent=none",
            "-oStrictHostKeyChecking=yes",
            "-oClearAllForwardings=yes",
            "-oEscapeChar=none",
        ] {
            assert!(args.contains(&expected.into()));
        }
        assert!(args.contains(&"-oUserKnownHostsFile=\"/tmp/host keys\"".into()));
    }
    #[test]
    fn missing_selected_key_cannot_fall_back_to_default_identities() {
        let dir = tempfile::tempdir().unwrap();
        let t = Target {
            host: "example.test".into(),
            port: 22,
            user: "worker".into(),
            identity_file: dir.path().join("missing-key"),
            known_hosts_file: dir.path().join("known-hosts"),
            identity_agent: None,
        };
        let output = std::process::Command::new("/usr/bin/ssh")
            .arg("-G")
            .args(arguments(&t, "true"))
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let identities: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("identityfile "))
            .collect();
        assert_eq!(identities, ["identityfile none"]);
        assert!(text.lines().any(|line| line == "identityagent none"));
        assert!(
            text.lines()
                .any(|line| line == "stricthostkeychecking true")
        );
    }
}
