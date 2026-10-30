"""Static regression checks for the repository CI security boundary."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    ".github/workflows/tests.yml": (
        "- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
        "- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5",
    ),
    ".github/workflows/portal-tests.yml": (
        "- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
        "- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4",
    ),
    ".github/workflows/config-auditor-tests.yml": (
        "- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
        "- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5",
    ),
    ".github/workflows/secrets.yml": (
        "uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6",
        "uses: gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e # v3",
    ),
}


class CIConfigurationSecurityTests(unittest.TestCase):
    def _workflow(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_all_reusable_actions_are_verified_immutable_commits(self) -> None:
        for relative_path, expected_lines in WORKFLOWS.items():
            contents = self._workflow(relative_path)
            actual_lines = tuple(
                line.strip() for line in contents.splitlines() if "uses:" in line
            )
            self.assertEqual(actual_lines, expected_lines, relative_path)
            for line in actual_lines:
                action_ref = line.split("uses: ", 1)[1].split(" #", 1)[0]
                self.assertRegex(action_ref, r"^[\w./-]+@[0-9a-f]{40}$", line)

    def test_pre_commit_secret_hook_is_immutable_and_redacts(self) -> None:
        contents = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("repo: https://github.com/gitleaks/gitleaks", contents)
        self.assertIn(
            "rev: 6eaad039603a4de39fddd1cf5f727391efe9974e # v8.30.0",
            contents,
        )
        self.assertIn('      - id: gitleaks\n        args: ["--redact"]', contents)

    def test_pull_requests_use_untrusted_safe_trigger_and_read_only_scopes(self) -> None:
        expected_permissions = {
            ".github/workflows/tests.yml": "contents: read",
            ".github/workflows/portal-tests.yml": "contents: read",
            ".github/workflows/config-auditor-tests.yml": "contents: read",
            ".github/workflows/secrets.yml": "contents: read\n  pull-requests: read",
        }
        for relative_path, expected in expected_permissions.items():
            contents = self._workflow(relative_path)
            self.assertNotRegex(contents, r"(?m)^\s*pull_request_target\s*:")
            self.assertRegex(contents, r"(?m)^\s*pull_request\s*:")
            permissions = contents.split("permissions:\n", 1)[1].split("\njobs:", 1)[0].strip()
            self.assertEqual(permissions, expected, relative_path)
            self.assertNotRegex(permissions, r"(?m)^\s*[\w-]+:\s*write\s*$")

    def test_secret_scan_remains_blocking_and_redacted(self) -> None:
        contents = self._workflow(".github/workflows/secrets.yml")
        self.assertIn("timeout-minutes: 10", contents)
        self.assertIn(
            'gitleaks git --no-banner --redact --exit-code=1 --log-opts="--all" .',
            contents,
        )
        self.assertIn("gitleaks dir --no-banner --redact --exit-code=1 .", contents)
        self.assertIn("steps.incremental_scan.outcome == 'failure'", contents)
        self.assertRegex(
            contents,
            r"(?s)Fail if the official incremental scan failed.*?\n\s*exit 1\s*$",
        )

    def test_config_auditor_keeps_its_independent_vendor_and_bridge_tests(self) -> None:
        contents = self._workflow(".github/workflows/config-auditor-tests.yml")
        self.assertIn("timeout-minutes: 10", contents)
        self.assertIn("working-directory: integrations/config-auditor", contents)
        self.assertIn("run: python -m pytest", contents)
        self.assertIn("run: python -m unittest tests/test_config_auditor_bridge.py", contents)


if __name__ == "__main__":
    unittest.main()
