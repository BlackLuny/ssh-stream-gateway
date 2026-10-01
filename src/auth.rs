use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand_core::OsRng;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    time::Instant,
};
use zeroize::Zeroizing;

pub fn validate_hash(value: &str) -> Result<()> {
    let parsed = PasswordHash::new(value).map_err(|_| anyhow::anyhow!("invalid password hash"))?;
    ensure!(
        parsed.algorithm.as_str() == "argon2id" && parsed.version == Some(19),
        "password hash must use Argon2id v19"
    );
    let param = |name| parsed.params.get_decimal(name).unwrap_or(0);
    ensure!(
        (19456..=65536).contains(&param("m"))
            && (2..=5).contains(&param("t"))
            && (1..=4).contains(&param("p")),
        "password hash work parameters outside safe limits"
    );
    ensure!(
        parsed.hash.is_some_and(|h| h.len() == 32) && parsed.salt.is_some_and(|s| s.len() >= 22),
        "password hash must have a 32-byte output and >=16-byte salt"
    );
    Ok(())
}

pub fn verify(hash: &str, password: &[u8]) -> bool {
    PasswordHash::new(hash)
        .ok()
        .is_some_and(|hash| Argon2::default().verify_password(password, &hash).is_ok())
}

pub fn check_password(password: &str) -> Result<()> {
    ensure!(
        (20..=256).contains(&password.len()),
        "use a randomly chosen passphrase of 20..256 ASCII characters (six random words recommended)"
    );
    ensure!(
        password.bytes().all(|c| (32..=126).contains(&c))
            && !password.starts_with(' ')
            && !password.ends_with(' '),
        "passphrase must be printable ASCII without leading/trailing spaces"
    );
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    check_password(password)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|_| anyhow::anyhow!("password hashing failed"))
}

pub fn read_password(path: Option<&Path>) -> Result<Zeroizing<String>> {
    let password = if let Some(path) = path {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("open passphrase file")?;
        let metadata = file.metadata()?;
        ensure!(metadata.len() <= 258, "passphrase file too long");
        ensure!(
            metadata.is_file() && metadata.mode() & 0o077 == 0,
            "passphrase file must be a regular owner-only file (chmod 600)"
        );
        // SAFETY: geteuid takes no arguments and cannot invalidate memory.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "passphrase file must be owned by the current user"
        );
        let mut value = Zeroizing::new(String::new());
        file.take(258)
            .read_to_string(&mut value)
            .context("read passphrase file")?;
        while value.ends_with(['\n', '\r']) {
            value.pop();
        }
        value
    } else {
        prompt("Gateway passphrase: ")?
    };
    check_password(&password)?;
    Ok(password)
}

struct EchoGuard {
    tty: File,
    original: libc::termios,
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: valid TTY descriptor and initialized termios previously read from it.
        unsafe {
            libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSAFLUSH, &self.original);
        }
        let _ = self.tty.write_all(b"\n");
    }
}
pub fn prompt(label: &str) -> Result<Zeroizing<String>> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("open terminal; use --password-file for noninteractive execution")?;
    tty.write_all(label.as_bytes())?;
    tty.flush()?;
    // SAFETY: tcgetattr writes an initialized termios on success, checked below.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut original) } == 0,
        "read terminal settings failed"
    );
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    // SAFETY: termios was initialized by tcgetattr; descriptor is valid.
    ensure!(
        unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &hidden) } == 0,
        "disable terminal echo failed"
    );
    let mut guard = EchoGuard { tty, original };
    let mut value = Zeroizing::new(String::new());
    loop {
        let mut byte = [0u8];
        guard.tty.read_exact(&mut byte)?;
        match byte[0] {
            b'\n' | b'\r' => break,
            3 | 4 => anyhow::bail!("passphrase entry cancelled"),
            8 | 127 => {
                value.pop();
            }
            32..=126 => {
                ensure!(value.len() < 256, "passphrase too long");
                value.push(byte[0] as char);
            }
            _ => anyhow::bail!("passphrase must use printable ASCII characters"),
        }
    }
    Ok(value)
}

/// Global bucket: no attacker-controlled address/forwarded header map to exhaust.
pub struct Attempts {
    tokens: f64,
    updated: Instant,
}
impl Default for Attempts {
    fn default() -> Self {
        Self {
            tokens: 5.0,
            updated: Instant::now(),
        }
    }
}
impl Attempts {
    pub fn take(&mut self) -> bool {
        self.take_at(Instant::now())
    }
    fn take_at(&mut self, now: Instant) -> bool {
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() / 12.0).min(5.0);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
    pub fn success(&mut self) {
        self.tokens = (self.tokens + 1.0).min(5.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn argon_hash_round_trip() {
        let hash = hash_password("unit-test-only-passphrase").unwrap();
        validate_hash(&hash).unwrap();
        assert!(verify(&hash, b"unit-test-only-passphrase"));
        assert!(!verify(&hash, b"wrong"));
        assert!(hash_password("short").is_err());
        assert!(validate_hash("$argon2id$v=19$m=1,t=1,p=1$bad$bad").is_err());
    }
    #[test]
    fn rate_limit_is_bounded_and_recovers() {
        let mut b = Attempts::default();
        let now = b.updated;
        for _ in 0..5 {
            assert!(b.take_at(now));
        }
        assert!(!b.take_at(now));
        assert!(b.take_at(now + std::time::Duration::from_secs(12)));
        assert!(!b.take_at(now + std::time::Duration::from_secs(12)));
        b.success();
        assert!(b.take_at(now + std::time::Duration::from_secs(12)));
    }
    #[test]
    fn secret_file_permissions_and_symlinks_are_checked() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "unit-test-only-passphrase\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_password(Some(&path)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            &**read_password(Some(&path)).unwrap(),
            "unit-test-only-passphrase"
        );
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_password(Some(&link)).is_err());
    }
}
