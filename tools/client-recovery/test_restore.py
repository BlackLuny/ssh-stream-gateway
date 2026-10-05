"""Synthetic-only wrapper tests; never connects or opens real credentials."""
import importlib.util
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import gateway_common as common

spec = importlib.util.spec_from_file_location("gateway_setup", Path(__file__).with_name("setup-client.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
FAKE = "synthetic-test-only-not-a-credential"


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gateway-wrapper-test-")
        self.base = Path(self.tmp.name)
        self.auth = self.base / ".private"
        self.mock_binary = self.base / "synthetic-client"
        self.mock_binary.write_bytes(b"synthetic non-executable fixture")
        self.patches = [
            patch.object(common, "BASE", self.base),
            patch.object(common, "AUTH_DIR", self.auth),
            patch.object(setup, "AUTH_DIR", self.auth),
            patch.object(setup, "verified_binary_fd", side_effect=lambda: os.open(self.mock_binary, os.O_RDONLY)),
            patch("builtins.input", return_value="SAVE AND TEST"),
            patch.object(setup.getpass, "getpass", return_value=FAKE),
            patch.object(setup.sys.stdin, "isatty", return_value=True),
            patch.object(setup.sys.stderr, "isatty", return_value=True),
        ]
        for p in self.patches:
            p.start()
        self.output = io.StringIO()
        self.outpatch = patch.object(setup.sys, "stdout", self.output)
        self.outpatch.start()

    def tearDown(self):
        self.outpatch.stop()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def assert_clean(self):
        self.assertFalse((self.auth / "password").exists())
        if self.auth.exists():
            self.assertEqual(list(self.auth.iterdir()), [])
        self.assertNotIn(FAKE, self.output.getvalue())

    def test_success_retains_private_file_after_test_only(self):
        def probe(fd, path):
            self.assertFalse((self.auth / "password").exists())
            self.assertEqual(path.read_text(), FAKE + "\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            return True, 0, ("OK", "Expected hostname verified")
        with patch.object(setup, "test_hostname", side_effect=probe):
            self.assertEqual(setup.main(), 0)
        final = self.auth / "password"
        self.assertEqual(final.read_text(), FAKE + "\n")
        self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode), 0o700)
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertEqual(list(self.auth.iterdir()), [final])
        self.assertNotIn(FAKE, self.output.getvalue())

    def test_cancel_creates_no_authentication(self):
        with patch("builtins.input", return_value="CANCEL"), patch.object(setup, "test_hostname") as probe:
            self.assertEqual(setup.main(), 1)
            probe.assert_not_called()
        self.assert_clean()

    def test_bad_password_creates_no_authentication(self):
        with patch.object(setup.getpass, "getpass", return_value="short"):
            with self.assertRaises(ValueError):
                setup.main()
        self.assert_clean()

    def test_failed_probe_cleans_temporary_file(self):
        with patch.object(setup, "test_hostname", return_value=(False, 125, ("GATEWAY_HTTP_401", "The gateway did not accept authentication (HTTP 401)"))):
            with self.assertRaises(RuntimeError):
                setup.main()
        self.assert_clean()

    def test_timeout_cleans_temporary_file(self):
        with patch.object(setup, "test_hostname", side_effect=subprocess.TimeoutExpired("synthetic", 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                setup.main()
        self.assert_clean()

    def test_interrupt_cleans_temporary_file(self):
        with patch.object(setup, "test_hostname", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                setup.main()
        self.assert_clean()

    def test_termination_signals_clean_and_restore_handler(self):
        for sig in (signal.SIGTERM, signal.SIGHUP):
            previous = signal.getsignal(sig)
            def stop_probe(*args):
                os.kill(os.getpid(), sig)
            with patch.object(setup, "test_hostname", side_effect=stop_probe):
                with self.assertRaises(setup.TerminationRequested):
                    setup.main()
            self.assert_clean()
            self.assertEqual(signal.getsignal(sig), previous)

    def test_interrupt_after_promotion_rolls_back(self):
        original_fsync = os.fsync
        count = 0
        def interrupted_fsync(fd):
            nonlocal count
            count += 1
            if count == 2:
                self.assertTrue((self.auth / "password").exists())
                raise KeyboardInterrupt
            return original_fsync(fd)
        with patch.object(setup, "test_hostname", return_value=(True, 0, ("OK", "Expected hostname verified"))), patch.object(setup.os, "fsync", side_effect=interrupted_fsync):
            with self.assertRaises(KeyboardInterrupt):
                setup.main()
        self.assert_clean()

    def test_signal_after_link_syscall_rolls_back(self):
        original_link = os.link
        def signal_after_link(*args, **kwargs):
            original_link(*args, **kwargs)
            raise setup.TerminationRequested("synthetic interruption after link")
        with patch.object(setup, "test_hostname", return_value=(True, 0, ("OK", "Expected hostname verified"))), patch.object(setup.os, "link", side_effect=signal_after_link):
            with self.assertRaises(setup.TerminationRequested):
                setup.main()
        self.assert_clean()

    def test_stale_pending_is_not_read_or_deleted(self):
        self.auth.mkdir(mode=0o700)
        pending = self.auth / ".pending-synthetic"
        pending.write_text("synthetic-old-value")
        with patch.object(setup, "test_hostname") as probe:
            with self.assertRaises(RuntimeError):
                setup.main()
            probe.assert_not_called()
        self.assertEqual(pending.read_text(), "synthetic-old-value")

    def test_binary_activation_requires_confirmation(self):
        self.mock_binary.chmod(0o600)
        with patch("builtins.input", return_value="CANCEL"):
            self.assertEqual(setup.main(), 1)
        self.assertEqual(stat.S_IMODE(self.mock_binary.stat().st_mode), 0o600)
        with patch.object(setup, "test_hostname", return_value=(True, 0, ("OK", "Expected hostname verified"))):
            self.assertEqual(setup.main(), 0)
        self.assertEqual(stat.S_IMODE(self.mock_binary.stat().st_mode), 0o700)

    def test_probe_output_limit_stops_child(self):
        real_popen = subprocess.Popen
        def fake_launch(*args, **kwargs):
            return real_popen([sys.executable, "-c", "import os,time;os.write(1,b'x'*300);time.sleep(10)"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True)
        with patch.object(setup.subprocess, "Popen", side_effect=fake_launch):
            with self.assertRaisesRegex(RuntimeError, "safe bound"):
                setup.test_hostname(123, self.auth / "pending")

    def test_safe_error_categories_never_echo_raw_diagnostics(self):
        secret = b"synthetic-secret-never-display-9384"
        cases = [
            (b"error: gateway rejected request (HTTP 401)", "GATEWAY_HTTP_401"),
            (b"error: gateway rejected request (HTTP 403)", "GATEWAY_HTTP_403"),
            (b"error: gateway rejected request (HTTP 429)", "GATEWAY_HTTP_429"),
            (b"error: endpoint TLS handshake failed: UnknownIssuer", "ENDPOINT_TLS_FAILED"),
            (b"error: proxy authentication required (HTTP 407)", "PROXY_AUTH_REQUIRED"),
            (b"error: gateway connection failed: http2 error: stream error received: unspecific protocol error detected", "HTTP2_PROTOCOL_ERROR"),
            (b"error: open passphrase file /private/path", "LOCAL_AUTH_FILE_UNREADABLE"),
            (b"unknown custom diagnostic with content", "UNCLASSIFIED_CLIENT_FAILURE"),
        ]
        for raw, expected in cases:
            category = setup.failure_category(b"", raw + b"\n" + secret, 125)
            self.assertEqual(category[0], expected)
            self.assertNotIn(secret.decode(), repr(category))
            self.assertNotIn("/private/path", repr(category))

    def test_failure_message_has_safe_category_not_secret(self):
        category = setup.failure_category(b"", b"error: gateway rejected request (HTTP 401)\n", 125)
        with patch.object(setup, "test_hostname", return_value=(False, 125, category)):
            with self.assertRaisesRegex(RuntimeError, "GATEWAY_HTTP_401") as caught:
                setup.main()
        self.assertNotIn(FAKE, str(caught.exception))
        self.assert_clean()

    def test_unknown_remote_identity_is_not_disclosed(self):
        category = setup.failure_category(b"private-hostname-not-for-output\n", b"", 0)
        self.assertEqual(category[0], "REMOTE_IDENTITY_MISMATCH")
        self.assertNotIn("private-hostname", repr(category))

    def test_existing_password_not_replaced(self):
        self.auth.mkdir(mode=0o700)
        old = self.auth / "password"
        old.write_text("synthetic-existing-file")
        with patch.object(setup, "test_hostname") as probe:
            with self.assertRaises(RuntimeError):
                setup.main()
            probe.assert_not_called()
        self.assertEqual(old.read_text(), "synthetic-existing-file")
        self.assertEqual(list(self.auth.iterdir()), [old])

    def test_auth_directory_symlink_refused(self):
        other = self.base / "other"
        other.mkdir(mode=0o700)
        self.auth.symlink_to(other)
        with self.assertRaises(OSError):
            setup.main()
        self.assertEqual(list(other.iterdir()), [])

    def test_auth_directory_bad_mode_refused(self):
        self.auth.mkdir(mode=0o755)
        self.auth.chmod(0o755)
        with self.assertRaises(RuntimeError):
            setup.main()
        self.assert_clean()

    def test_noninteractive_refused(self):
        with patch.object(setup.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(RuntimeError):
                setup.main()
        self.assert_clean()

    def test_pinned_argv_and_environment(self):
        args = common.argv(self.auth / "pending", "hostname")
        self.assertEqual(args[-1], "hostname")
        self.assertEqual(args[-2], "build")
        self.assertEqual(args[args.index("--endpoint") + 1], "https://gateway.example.invalid")
        self.assertNotIn(FAKE, " ".join(args))
        with patch.dict(os.environ, {"LD_PRELOAD":"bad", "SSL_CERT_FILE":"bad", "HTTPS_PROXY":"http://proxy.invalid:80"}, clear=True):
            env = common.client_environment()
        self.assertNotIn("LD_PRELOAD", env)
        self.assertNotIn("SSL_CERT_FILE", env)
        self.assertEqual(env["HTTPS_PROXY"], "http://proxy.invalid:80")

    def test_probe_identity_strict_and_no_output_echo(self):
        real_popen = subprocess.Popen
        for stdout, stderr, code, expected in [
            (b"example-build-host\n", b"", 0, True),
            (b"wrong\n", b"", 0, False),
            (b"example-build-host\n", b"error", 0, False),
            (b"example-build-host\n", b"", 125, False),
            (b"example-build-host extra\n", b"", 0, False),
        ]:
            def fake_launch(*args, **kwargs):
                return real_popen([sys.executable, "-c",
                                   f"import os;os.write(1,{stdout!r});os.write(2,{stderr!r});raise SystemExit({code})"],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  start_new_session=True)
            with patch.object(setup.subprocess, "Popen", side_effect=fake_launch) as launch:
                result = setup.test_hostname(123, self.auth / "pending")
                self.assertEqual(result[:2], (expected, code))
                self.assertEqual(result[2][0] == "OK", expected)
                kw = launch.call_args.kwargs
                self.assertEqual(kw["executable"], "/proc/self/fd/123")
                self.assertEqual(kw["stdin"], subprocess.DEVNULL)
                self.assertEqual(kw["pass_fds"], (123,))
        self.assertEqual(self.output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
