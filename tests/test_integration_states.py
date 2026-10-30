"""Integration trust-state tests for explicitly invoked cloud collection.

All provider traffic is mocked.  These tests must never authenticate to or contact a
real provider.
"""

from __future__ import annotations

import json
import os
import sys
import types
import unittest
import urllib.error
from unittest import mock

from reverse_shell_decoy import collectors


SINCE = "2026-10-01T00:00:00Z"
UNTIL = "2026-10-01T01:00:00Z"
CF_ACCOUNT = "a" * 32
_STATUS_KEYS = {
    "state",
    "reason",
    "source",
    "read_only_requests",
    "coverage",
    "credentials_retained",
    "checked_at_utc",
}


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def read(self, size=-1):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False


class _RecordingOpener:
    def __init__(self, responses):
        self.responses = list(responses)

    def open(self, request, timeout):
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return _Response(response)


class _TypedAwsError(Exception):
    """Minimal boto-style exception with a safe, typed response code."""

    def __init__(self, code, raw_message):
        super().__init__(raw_message)
        self.response = {"Error": {"Code": code, "Message": raw_message}}


class IntegrationStateTests(unittest.TestCase):
    def setUp(self):
        self.environ = mock.patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN": "cf-state-test-token",
                "AWS_ACCESS_KEY_ID": "AKIATESTACCESSKEY0000",
                "AWS_SECRET_ACCESS_KEY": "aws-state-test-secret",
            },
            clear=False,
        )
        self.environ.start()
        self.addCleanup(self.environ.stop)

    def _collect_cloudflare_with(self, response):
        opener = _RecordingOpener([response])
        with mock.patch.object(collectors.urllib.request, "build_opener", return_value=opener):
            return collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

    def _assert_status(self, status, *, state, reason, coverage):
        self.assertEqual(set(status), _STATUS_KEYS)
        self.assertEqual(status["state"], state)
        self.assertEqual(status["reason"], reason)
        self.assertEqual(status["source"], "local_explicit_collection")
        self.assertTrue(status["read_only_requests"])
        self.assertEqual(status["coverage"], coverage)
        self.assertFalse(status["credentials_retained"])
        self.assertRegex(status["checked_at_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_success_is_a_bounded_local_read_only_status_and_redacts_values(self):
        active_token = os.environ["CLOUDFLARE_API_TOKEN"]
        aws_access_key_shape = "AKIA" + "".join(chr(65 + index) for index in range(16))
        result = self._collect_cloudflare_with(
            {
                "success": True,
                "result": [
                    {
                        "id": "audit-1",
                        "detail": f"Bearer {active_token}; observed {aws_access_key_shape}",
                    }
                ],
            }
        )

        self._assert_status(
            result["integration_status"],
            state="customer_authorized_integration",
            reason="bounded_read_only_request_completed",
            coverage="bounded_sample",
        )
        rendered = json.dumps(result)
        self.assertNotIn(active_token, rendered)
        self.assertNotIn(aws_access_key_shape, rendered)
        self.assertIn("[redacted credential]", rendered)

    def test_selected_provider_credential_is_scrubbed_from_innocuous_keys_and_messages(self):
        active_token = os.environ["CLOUDFLARE_API_TOKEN"]
        result = collectors._result(
            "cloudflare",
            SINCE,
            UNTIL,
            [
                {
                    "ordinary_detail": f"unlabelled value {active_token}",
                    f"ordinary-key-{active_token}": "ordinary value",
                }
            ],
            1,
            False,
            [f"ordinary collector message {active_token}"],
        )

        rendered = json.dumps(result)
        self.assertNotIn(active_token, rendered)
        self.assertIn("[redacted credential]", rendered)

    def test_http_401_and_403_have_fixed_unavailable_states_without_provider_body(self):
        token = os.environ["CLOUDFLARE_API_TOKEN"]
        cases = (
            (401, "authentication_failed"),
            (403, "permission_denied"),
        )
        for status_code, reason in cases:
            with self.subTest(status_code=status_code):
                result = self._collect_cloudflare_with(
                    urllib.error.HTTPError(
                        "https://api.cloudflare.com/client/v4/accounts/x/logs/audit",
                        status_code,
                        f"raw provider detail {token}",
                        {},
                        None,
                    )
                )

                self._assert_status(
                    result["integration_status"],
                    state="integration_unavailable",
                    reason=reason,
                    coverage="unavailable",
                )
                self.assertEqual(result["events"], [])
                self.assertNotIn(token, json.dumps(result))
                # Preserve the existing safe message contract for callers and tests.
                self.assertIn(f"status {status_code}", " ".join(result["warnings"]))

    def test_aws_expired_token_requires_explicit_safe_sdk_code(self):
        raw_token = os.environ["AWS_SECRET_ACCESS_KEY"]

        class Sts:
            def get_caller_identity(self):
                raise _TypedAwsError("ExpiredTokenException", f"raw value: {raw_token}")

        class Session:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def client(self, name, region_name, endpoint_url):
                self.assertEqual(name, "sts")
                return Sts()

            def assertEqual(self, actual, expected):
                if actual != expected:
                    raise AssertionError(f"{actual!r} != {expected!r}")

        fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=Session))
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
            result = collectors.collect_cloud("aws", "123456789012", SINCE, UNTIL)

        self._assert_status(
            result["integration_status"],
            state="credential_expired_or_revoked",
            reason="credential_expired",
            coverage="unavailable",
        )
        self.assertEqual(result["events"], [])
        self.assertNotIn(raw_token, json.dumps(result))

    def test_aws_unknown_or_unsafe_sdk_metadata_stays_generic_unavailable(self):
        raw_token = os.environ["AWS_SECRET_ACCESS_KEY"]

        class Sts:
            def get_caller_identity(self):
                raise _TypedAwsError("InvalidClientTokenId", f"raw value: {raw_token}")

        class Session:
            def __init__(self, **kwargs):
                pass

            def client(self, name, region_name, endpoint_url):
                return Sts()

        fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=Session))
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
            result = collectors.collect_cloud("aws", "123456789012", SINCE, UNTIL)

        self._assert_status(
            result["integration_status"],
            state="integration_unavailable",
            reason="unknown_failure",
            coverage="unavailable",
        )
        self.assertNotIn(raw_token, json.dumps(result))

        class UnsafeMetadataError(Exception):
            @property
            def response(self):
                raise RuntimeError(f"do not inspect {raw_token}")

        self.assertEqual(collectors._aws_sdk_failure_reason(UnsafeMetadataError()), "unknown_failure")

    def test_missing_credential_remains_an_exception_with_safe_state_metadata(self):
        with mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": ""}, clear=False):
            with self.assertRaises(collectors.MissingCredentialError) as raised:
                collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        error = raised.exception
        self.assertEqual(error.safe_reason, "missing_credentials")
        self.assertEqual(error.integration_state, "integration_unavailable")
        self._assert_status(
            error.integration_status,
            state="integration_unavailable",
            reason="missing_credentials",
            coverage="unavailable",
        )

    def test_optional_dependency_and_scope_mismatch_remain_exceptions(self):
        with mock.patch.dict(sys.modules, {"boto3": None}):
            with self.assertRaises(collectors.OptionalDependencyError) as raised:
                collectors.collect_cloud("aws", "123456789012", SINCE, UNTIL)

        self._assert_status(
            raised.exception.integration_status,
            state="integration_unavailable",
            reason="optional_dependency_unavailable",
            coverage="unavailable",
        )

        class Sts:
            def get_caller_identity(self):
                return {"Account": "999999999999"}

        class Session:
            def __init__(self, **kwargs):
                pass

            def client(self, name, region_name, endpoint_url):
                return Sts()

        fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=Session))
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
            with self.assertRaises(collectors.ScopeMismatchError) as raised:
                collectors.collect_cloud("aws", "123456789012", SINCE, UNTIL)

        self._assert_status(
            raised.exception.integration_status,
            state="integration_unavailable",
            reason="scope_mismatch",
            coverage="unavailable",
        )


if __name__ == "__main__":
    unittest.main()
