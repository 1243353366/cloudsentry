"""Static regression checks for the repository CI security boundary."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATHS = (
    ".github/workflows/tests.yml",
    ".github/workflows/portal-tests.yml",
    ".github/workflows/config-auditor-tests.yml",
    ".github/workflows/secrets.yml",
)

# Actions this repository is allowed to run. Adding one is a deliberate change to
# this list, which is the point: an unreviewed action cannot appear silently.
ALLOWED_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "actions/setup-node",
    "gitleaks/gitleaks-action",
}

USES_RE = re.compile(r"uses:\s*([\w./-]+)@([0-9a-f]{40})\s*#\s*(\S+)\s*$")


class CIConfigurationSecurityTests(unittest.TestCase):
    def _workflow(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def _action_references(self):
        references = []
        for relative_path in WORKFLOW_PATHS:
            for line_no, line in enumerate(self._workflow(relative_path).splitlines(), 1):
                if "uses:" not in line:
                    continue
                references.append((relative_path, line_no, line.strip()))
        return references

    def test_all_reusable_actions_are_verified_immutable_commits(self) -> None:
        """Every action must be an immutable commit of a reviewed action.

        This deliberately asserts the property rather than a pinned version list:
        the repository enables Dependabot, so a test that names one exact SHA per
        workflow would fail every dependency update and force the bump to be
        merged with the check disabled.
        """
        references = self._action_references()
        self.assertTrue(references, "no workflow action references were found")
        for relative_path, line_no, line in references:
            match = USES_RE.search(line)
            self.assertIsNotNone(
                match,
                f"{relative_path}:{line_no}: expected owner/action@<40-hex sha> # <version>, got {line!r}",
            )
            action, sha, label = match.groups()
            self.assertIn(
                action,
                ALLOWED_ACTIONS,
                f"{relative_path}:{line_no}: {action} is not a reviewed action for this repository",
            )
            self.assertRegex(label, r"^v\d", f"{relative_path}:{line_no}: label {label!r} is not a version")
            self.assertNotIn(" ", sha)

    def test_one_label_never_points_at_two_different_commits(self) -> None:
        """A version comment must identify exactly one commit across all workflows."""
        seen: dict[tuple[str, str], str] = {}
        for relative_path, line_no, line in self._action_references():
            match = USES_RE.search(line)
            assert match is not None, line
            action, sha, label = match.groups()
            previous = seen.setdefault((action, label), sha)
            self.assertEqual(
                previous,
                sha,
                f"{relative_path}:{line_no}: {action} {label} is pinned to two different commits",
            )

    def test_no_floating_action_refs_remain(self) -> None:
        for relative_path in WORKFLOW_PATHS:
            for line_no, line in enumerate(self._workflow(relative_path).splitlines(), 1):
                if "uses:" not in line:
                    continue
                self.assertNotRegex(
                    line,
                    r"uses:\s*[\w./-]+@(main|master|v\d+\s*$)",
                    f"{relative_path}:{line_no}: floating action reference {line.strip()!r}",
                )

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
