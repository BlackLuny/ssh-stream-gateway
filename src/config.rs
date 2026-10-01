use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "bind_default")]
    pub bind: SocketAddr,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub password_hash: String,
    #[serde(default = "concurrency_default")]
    pub max_sessions: usize,
    #[serde(default = "duration_default")]
    pub session_seconds: u64,
    #[serde(default = "idle_default")]
    pub idle_seconds: u64,
    pub targets: BTreeMap<String, Target>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub endpoint: Option<String>,
    pub ca: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
}
impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("read client configuration")?;
        ensure!(bytes.len() <= 16384, "client configuration too large");
        let text = std::str::from_utf8(&bytes).context("client configuration must be UTF-8")?;
        let config: Self =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid client configuration"))?;
        if let Some(url) = &config.endpoint {
            crate::client::endpoint(url)?;
        }
        for path in [&config.ca, &config.password_file].into_iter().flatten() {
            ensure!(
                path.is_absolute(),
                "client configuration paths must be absolute"
            );
        }
        Ok(config)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    #[serde(default = "port_default")]
    pub port: u16,
    pub user: String,
    pub identity_file: PathBuf,
    pub known_hosts_file: PathBuf,
    /// Optional operator-selected local agent socket; forwarding stays disabled.
    pub identity_agent: Option<PathBuf>,
}
fn bind_default() -> SocketAddr {
    "127.0.0.1:8443".parse().unwrap()
}
fn concurrency_default() -> usize {
    4
}
fn duration_default() -> u64 {
    3600
}
fn idle_default() -> u64 {
    300
}
fn port_default() -> u16 {
    22
}

pub fn alias_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn literal_path(path: &Path) -> bool {
    // OpenSSH expands percent tokens and some environment/home substitutions.
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|s| !s.contains(['%', '$', '\n', '\r', '\0', '"', '\\']) && !s.is_empty())
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).context("read server configuration")?;
        ensure!(content.len() <= 128 * 1024, "configuration too large");
        // TOML errors can echo secrets from source lines; keep the diagnostic generic.
        let config: Self = toml::from_str(&content)
            .map_err(|_| anyhow::anyhow!("invalid server configuration"))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        let safe_bind = match self.bind.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
            IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
        };
        ensure!(
            safe_bind,
            "bind must be a loopback or explicit private/WireGuard address (no wildcard/public listener)"
        );
        ensure!(
            (1..=32).contains(&self.max_sessions),
            "max_sessions must be 1..32"
        );
        ensure!(
            (1..=86400).contains(&self.session_seconds),
            "session_seconds must be 1..86400"
        );
        ensure!(
            (1..=3600).contains(&self.idle_seconds),
            "idle_seconds must be 1..3600"
        );
        ensure!(
            literal_path(&self.tls_cert) && literal_path(&self.tls_key),
            "TLS paths must be literal absolute paths"
        );
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= 64,
            "configure 1..64 targets"
        );
        crate::auth::validate_hash(&self.password_hash)?;
        for (alias, target) in &self.targets {
            ensure!(alias_valid(alias), "invalid target alias");
            target.validate()?;
        }
        Ok(())
    }
}
impl Target {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port != 0, "target port must be nonzero");
        ensure!(
            !self.user.is_empty()
                && self.user.len() <= 64
                && self
                    .user
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                && !self.user.starts_with('-'),
            "invalid SSH user"
        );
        let host = self.host.as_str();
        let ip = host.parse::<IpAddr>().is_ok();
        let dns = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            });
        ensure!(ip || dns, "invalid SSH host; use a bare IP or DNS name");
        for path in [&self.identity_file, &self.known_hosts_file] {
            if !literal_path(path) {
                bail!("SSH paths must be literal absolute paths without expansion tokens");
            }
        }
        if let Some(path) = &self.identity_agent {
            ensure!(
                literal_path(path),
                "agent socket must be a literal absolute path"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> Target {
        Target {
            host: "example.test".into(),
            port: 22,
            user: "worker".into(),
            identity_file: "/Users/operator/.ssh/identity".into(),
            known_hosts_file: "/Users/operator/.ssh/known_hosts".into(),
            identity_agent: None,
        }
    }
    #[test]
    fn reject_target_option_and_path_injection() {
        for host in [
            "-oProxyCommand=evil",
            "x y",
            "user@host",
            "$(evil)",
            "host\nfoo",
            "host:22",
        ] {
            let mut t = target();
            t.host = host.into();
            assert!(t.validate().is_err());
        }
        for path in [
            "relative",
            "/tmp/%h",
            "/tmp/${EVIL}",
            "/tmp/\"inject",
            "/tmp/a\nb",
        ] {
            let mut t = target();
            t.identity_file = path.into();
            assert!(t.validate().is_err());
        }
        assert!(target().validate().is_ok());
        let mut t = target();
        t.host = "2001:db8::1".into();
        assert!(t.validate().is_ok());
        assert!(!alias_valid("../target"));
    }
}
