"""Nonsecret, endpoint-pinned support for the restored gateway client."""
import hashlib
import os
from pathlib import Path
import stat

BASE = Path(__file__).absolute().parent
BINARY = BASE / "ssh-stream-gateway"
AUTH_DIR = BASE / ".private"
PASSWORD_NAME = "password"
ENDPOINT = "https://gateway.example.invalid"
TARGET = "build"
EXPECTED_HOST = b"example-build-host"
BINARY_SHA256 = "REPLACE_WITH_VERIFIED_BINARY_SHA256"


def verify_base():
    if BASE.resolve() != BASE:
        raise RuntimeError("Client directory must not contain symlinks")
    st = BASE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise RuntimeError("Client directory must be owned by you and mode 0700")


def verified_binary_fd():
    verify_base()
    fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise RuntimeError("Client binary ownership or permissions failed")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != BINARY_SHA256:
            raise RuntimeError("Client binary checksum failed")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_directory(create=False):
    verify_base()
    if create:
        try:
            os.mkdir(AUTH_DIR, 0o700)
        except FileExistsError:
            pass
    fd = os.open(AUTH_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        os.close(fd)
        raise RuntimeError("Authentication directory must be owned by you and mode 0700")
    return fd


def client_environment():
    # Keep only the existing network proxy settings. No debugging, loader,
    # credential overrides, custom CA overrides, or arbitrary environment.
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for key in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        if key in os.environ:
            result[key] = os.environ[key]
    return result


def argv(password_path, command):
    return [str(BINARY), "exec", "--endpoint", ENDPOINT,
            "--password-file", str(password_path), TARGET, command]


def validate_password(value):
    if not 20 <= len(value) <= 256 or value.startswith(" ") or value.endswith(" "):
        raise ValueError("Existing passphrase must be 20–256 printable ASCII characters without edge spaces")
    if any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("Existing passphrase must contain printable ASCII characters only")
