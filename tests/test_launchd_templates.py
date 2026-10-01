"""Offline assertions for the shipped placeholder LaunchAgent; never load jobs."""

import pathlib
import plistlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "examples" / "launchd" / "com.example.ssh-stream-gateway.agent.plist"
)


class LaunchAgentTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with TEMPLATE.open("rb") as source:
            cls.job = plistlib.load(source)

    def test_label_matches_filename(self):
        self.assertEqual(self.job["Label"], TEMPLATE.stem)

    def test_current_gui_user_only(self):
        self.assertEqual(self.job["LimitLoadToSessionType"], "Aqua")
        self.assertNotIn("UserName", self.job)
        self.assertNotIn("GroupName", self.job)

    def test_foreground_direct_binary_and_placeholder_config(self):
        self.assertEqual(
            self.job["ProgramArguments"],
            [
                "/ABSOLUTE/PATH/TO/ssh-stream-gateway",
                "serve",
                "--config",
                "/ABSOLUTE/PATH/TO/private/server.toml",
            ],
        )
        for key in ("Program", "WorkingDirectory", "EnvironmentVariables", "Sockets"):
            self.assertNotIn(key, self.job)

    def test_unsuccessful_exits_restart_with_throttling(self):
        self.assertIs(self.job["RunAtLoad"], True)
        self.assertEqual(self.job["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(self.job["ThrottleInterval"], 60)
        for key in ("StartInterval", "WatchPaths", "QueueDirectories", "StartOnMount"):
            self.assertNotIn(key, self.job)

    def test_shutdown_and_private_creation_mask(self):
        self.assertEqual(self.job["ExitTimeOut"], 45)
        self.assertEqual(self.job["Umask"], 0o077)
        self.assertNotIn("AbandonProcessGroup", self.job)

    def test_no_unbounded_log_files_or_interactive_stdin(self):
        for key in ("StandardInPath", "StandardOutPath", "StandardErrorPath"):
            self.assertEqual(self.job[key], "/dev/null")


if __name__ == "__main__":
    unittest.main()
