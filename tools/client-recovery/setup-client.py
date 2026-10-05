#!/usr/bin/env python3
"""User-run restoration only: hidden existing passphrase, fixed hostname test."""
import getpass
import os
import re
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
import warnings

from gateway_common import (AUTH_DIR, ENDPOINT, TARGET, EXPECTED_HOST, PASSWORD_NAME, argv,
                            client_environment, private_directory,
                            validate_password, verified_binary_fd)


class TerminationRequested(Exception):
    pass


def request_termination(signum, frame):
    raise TerminationRequested(f"Termination signal {signum}")


def failure_category(stdout, stderr, exit_code):
    """Map bounded untrusted diagnostics to fixed labels; never echo them."""
    text = bytes(stderr).decode("utf-8", "replace").lower()
    status = re.search(r"gateway rejected request \(http ([1-5][0-9]{2})\)", text)
    if status:
        number = status.group(1)
        explanations = {
            "401": "The gateway did not accept authentication (HTTP 401)",
            "403": "The gateway refused this request (HTTP 403)",
            "429": "The gateway rate limit was reached (HTTP 429); do not retry immediately",
            "502": "The gateway upstream failed (HTTP 502)",
            "503": "The gateway is temporarily unavailable (HTTP 503)",
            "504": "The gateway upstream timed out (HTTP 504)",
        }
        return "GATEWAY_HTTP_" + number, explanations.get(number, "The gateway returned a non-success HTTP status")
    markers = (
        ("proxy authentication required", "PROXY_AUTH_REQUIRED", "The configured network proxy requires authentication"),
        ("proxy rejected connect", "PROXY_CONNECT_REJECTED", "The configured network proxy rejected the connection"),
        ("configured proxy is invalid or unsupported", "PROXY_CONFIGURATION", "The existing network proxy configuration is unsupported"),
        ("cannot reach configured proxy", "PROXY_UNREACHABLE", "The configured network proxy could not be reached"),
        ("https proxy tls handshake failed", "PROXY_TLS_FAILED", "TLS verification or negotiation with the network proxy failed"),
        ("endpoint tls handshake failed", "ENDPOINT_TLS_FAILED", "TLS verification or negotiation with the gateway failed"),
        ("no usable tls trust roots", "TLS_TRUST_UNAVAILABLE", "The client could not load usable existing TLS trust roots"),
        ("cannot reach https endpoint", "ENDPOINT_UNREACHABLE", "The gateway address could not be reached"),
        ("did not negotiate http/2", "HTTP2_NOT_NEGOTIATED", "The gateway did not negotiate the required HTTP/2 protocol"),
        ("http/2 handshake timed out", "HTTP2_HANDSHAKE_TIMEOUT", "The gateway HTTP/2 handshake timed out"),
        ("gateway response timed out", "GATEWAY_RESPONSE_TIMEOUT", "The gateway did not return response headers in time"),
        ("connection timed out", "NETWORK_CONNECTION_TIMEOUT", "The gateway network connection timed out"),
        ("unspecific protocol error", "HTTP2_PROTOCOL_ERROR", "The client reported an HTTP/2 protocol error"),
        ("stream error received", "HTTP2_STREAM_RESET", "The HTTP/2 gateway stream was reset"),
        ("gateway connection failed", "GATEWAY_PROTOCOL_FAILURE", "The gateway connection failed while starting the request"),
        ("unexpected protocol", "GATEWAY_PROTOCOL_MISMATCH", "The gateway returned an unexpected response protocol"),
        ("open passphrase file", "LOCAL_AUTH_FILE_UNREADABLE", "The local private authentication file could not be opened"),
        ("passphrase file must", "LOCAL_AUTH_FILE_PERMISSION", "The local authentication file failed ownership or permission checks"),
        ("passphrase must", "LOCAL_PASSPHRASE_FORMAT", "The client rejected the passphrase format"),
        ("use a randomly chosen passphrase", "LOCAL_PASSPHRASE_FORMAT", "The client rejected the passphrase format"),
        ("host key verification failed", "SSH_HOST_KEY_REJECTED", "The existing SSH host-key check rejected the target"),
        ("permission denied (publickey", "SSH_AUTH_REJECTED", "The target rejected the gateway's existing SSH authentication"),
    )
    for marker, category, explanation in markers:
        if marker in text:
            return category, explanation
    if exit_code == 0 and bytes(stdout).rstrip(b"\r\n") != EXPECTED_HOST:
        return "REMOTE_IDENTITY_MISMATCH", "The successful command did not return the expected hostname"
    if exit_code == 0 and bytes(stderr).strip():
        return "UNEXPECTED_DIAGNOSTIC_OUTPUT", "The hostname command returned unexpected diagnostic output"
    if exit_code == 255:
        return "SSH_COMMAND_FAILED", "The gateway's SSH command failed; detailed output remains private"
    if exit_code == 2:
        return "CLIENT_USAGE_ERROR", "The local client rejected its command-line arguments"
    return "UNCLASSIFIED_CLIENT_FAILURE", "The client failed without a recognized safe diagnostic category"


def test_hostname(binary_fd, password_path):
    proc = None
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + 60
    protected_signals = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, protected_signals)
    try:
        proc = subprocess.Popen(
            argv(password_path, "hostname"), executable=f"/proc/self/fd/{binary_fd}",
            pass_fds=(binary_fd,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=client_environment(), start_new_session=True,
        )
        # A pending signal is delivered only after proc belongs to this try.
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        with selectors.DefaultSelector() as selector:
            for pipe, buffer, limit in ((proc.stdout, out, 256), (proc.stderr, err, 1024)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (buffer, limit))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("fixed hostname test", 60)
                for key, _ in selector.select(remaining):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer, limit = key.data
                    if len(buffer) + len(chunk) > limit:
                        raise RuntimeError("Gateway identity response exceeded its safe bound")
                    buffer.extend(chunk)
        proc.wait(timeout=max(0.001, deadline - time.monotonic()))
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, protected_signals)
        try:
            if proc is not None:
                os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc is not None:
            proc.wait(timeout=5)
        raise
    finally:
        if proc is not None:
            proc.stdout.close()
            proc.stderr.close()
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    # Never echo remote stdout/stderr or authentication diagnostics.
    ok = proc.returncode == 0 and out.rstrip(b"\r\n") == EXPECTED_HOST and not err.strip()
    category = ("OK", "Expected hostname verified") if ok else failure_category(out, err, proc.returncode)
    del out, err
    return ok, proc.returncode, category


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    binary_fd = verified_binary_fd()
    directory_fd = None
    pending_name = None
    pending_identity = None
    old_handlers = {sig: signal.signal(sig, request_termination)
                    for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise RuntimeError("Run this yourself in an interactive cloud terminal; no piped input")
        print("Restore existing gateway access only. No new passphrase or server change.")
        print(f"Your existing passphrase will be sent only to {ENDPOINT} with TLS validation.")
        print(f"It enables approved ongoing {TARGET} commands through this cloud workspace.")
        print("This activates the checksum-verified client binary for your test.")
        print("A temporary owner-only file is used for one hostname test, then cleaned on normal failure/cancel.")
        print("A forced kill or machine crash can leave a private pending file; do not upload this directory.")
        print(f"Only a successful {EXPECTED_HOST.decode('ascii')} result retains it in .private/password (mode 0600).")
        print("Do not paste the passphrase into chat. This does not renew unrelated permissions.")
        if input("Type SAVE AND TEST to approve saving and testing: ") != "SAVE AND TEST":
            print("Cancelled; no authentication file was created.")
            return 1
        # Activation is performed only by the user after the explicit approval.
        os.fchmod(binary_fd, 0o700)
        directory_fd = private_directory(create=True)
        if any(name.startswith(".pending-") for name in os.listdir(directory_fd)):
            raise RuntimeError("Unresolved private pending file exists; stop for local recovery without displaying it")
        try:
            os.stat(PASSWORD_NAME, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("An authentication file already exists; refusing to replace it")
        # Fail closed rather than falling back to echoed stdin.
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Existing gateway passphrase (hidden): ")
        validate_password(password)
        candidate_name = ".pending-" + secrets.token_hex(16)
        fd = os.open(candidate_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        pending_name = candidate_name
        pending_stat = os.fstat(fd)
        pending_identity = (pending_stat.st_dev, pending_stat.st_ino)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(password.encode("ascii") + b"\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            # Python cannot promise secure memory erasure; avoid retaining
            # additional copies or putting the passphrase in argv/environment.
            del password
        ok, code, category = test_hostname(binary_fd, AUTH_DIR / pending_name)
        if not ok:
            label, explanation = category
            raise RuntimeError(f"Gateway test failed [{label}, exit {code}]: {explanation}. Authentication was not saved")
        # Atomic no-clobber promotion. The pending link is removed in finally.
        os.link(pending_name, PASSWORD_NAME, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        print(EXPECTED_HOST.decode("ascii"))
        print("Existing gateway authentication saved with mode 0600. No new credential was created.")
        return 0
    finally:
        failed = sys.exc_info()[0] is not None
        # Complete bounded local cleanup without a second ordinary signal
        # interrupting it. SIGKILL and machine crashes remain uncatchable.
        cleanup_handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            if directory_fd is not None:
                if failed and pending_identity is not None:
                    try:
                        current = os.stat(PASSWORD_NAME, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        # Also covers a signal after link(2) committed but
                        # before the Python call returned. Never remove an
                        # unrelated file that may have appeared concurrently.
                        if (current.st_dev, current.st_ino) == pending_identity:
                            os.unlink(PASSWORD_NAME, dir_fd=directory_fd)
                if pending_name is not None:
                    try:
                        os.unlink(pending_name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                    os.fsync(directory_fd)
                os.close(directory_fd)
            os.close(binary_fd)
        finally:
            for sig, handler in cleanup_handlers.items():
                signal.signal(sig, old_handlers.get(sig, handler))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Check the setup result before retrying; do not display private files.", file=sys.stderr)
        raise SystemExit(130)
    except TerminationRequested:
        print("Setup terminated. Check the setup result before retrying; do not display private files.", file=sys.stderr)
        raise SystemExit(143)
    except subprocess.TimeoutExpired:
        print("Gateway test timed out; authentication was not saved. No automatic retry.", file=sys.stderr)
        raise SystemExit(124)
    except (OSError, RuntimeError, ValueError, getpass.GetPassWarning, EOFError) as exc:
        # All handled messages are local diagnostics, never remote output.
        print(f"Setup stopped: {exc}", file=sys.stderr)
        raise SystemExit(125)
