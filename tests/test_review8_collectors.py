"""Focused regression tests for targeted cloud collector review fixes.

Every transport path is mocked or in-memory; these tests make no provider request.
"""

from __future__ import annotations

import json
import os
import types
import unittest
import urllib.error
from unittest import mock

from reverse_shell_decoy import collectors


SINCE = "2026-10-01T00:00:00Z"
UNTIL = "2026-10-01T01:00:00Z"
CF_ACCOUNT = "a" * 32


class _Response:
    def __init__(self, payload):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

    def read(self, size=-1):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False


class _Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return _Response(response)


class _Socket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class _StreamingResponse:
    """A finite response exposing urllib's socket shape for deadline testing."""

    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.socket = _Socket()
        self.fp = types.SimpleNamespace(raw=types.SimpleNamespace(_sock=self.socket))
        self.read_sizes = []

    def read(self, size):
        self.read_sizes.append(size)
        return next(self.chunks)


class Review8CollectorTests(unittest.TestCase):
    def setUp(self):
        self.environ = mock.patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN": "cf-test-token",
                "RENDER_API_KEY": "render-test-token",
                "RAILWAY_API_TOKEN": "railway-test-token",
                "AWS_ACCESS_KEY_ID": "AKIATESTACCESS",
                "AWS_SECRET_ACCESS_KEY": "aws-test-secret",
            },
            clear=False,
        )
        self.environ.start()
        self.addCleanup(self.environ.stop)

    def _mock_http(self, responses):
        opener = _Opener(responses)
        patched = mock.patch.object(
            collectors.urllib.request,
            "build_opener",
            return_value=opener,
        )
        patched.start()
        self.addCleanup(patched.stop)
        return opener

    def test_render_later_service_failure_retains_prior_records_with_partial_warning(self):
        provider_body_secret = "render-provider-body-must-not-appear"
        opener = self._mock_http(
            [
                [
                    {"service": {"id": "srv-first"}},
                    {"service": {"id": "srv-second"}},
                ],
                [{"event": {"id": "evt-first"}}],
                urllib.error.HTTPError(
                    "https://api.render.com/v1/services/srv-second/events",
                    500,
                    provider_body_secret,
                    {},
                    None,
                ),
            ]
        )

        result = collectors.collect_cloud("render", "tea-workspace1", SINCE, UNTIL)

        self.assertEqual(result["events"], [{"event": {"id": "evt-first"}}])
        self.assertEqual(result["coverage"]["pages_fetched"], 1)
        self.assertTrue(result["coverage"]["truncated"])
        self.assertEqual(result["coverage"]["assessment"], "bounded_sample_not_an_all_clear")
        self.assertIn("successful prior service records were retained", " ".join(result["warnings"]))
        self.assertIn("status 500", " ".join(result["warnings"]))
        self.assertNotIn(provider_body_secret, json.dumps(result))
        self.assertEqual(len(opener.requests), 3)

    def test_cross_provider_known_credentials_are_redacted_without_scanning_other_environment(self):
        active_cloudflare_credential = "cloudflare-opaque-credential"
        cross_provider_credential = "render-opaque-credential"
        unrelated_environment_value = "unlisted-environment-value"
        with mock.patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN": active_cloudflare_credential,
                "RENDER_API_KEY": cross_provider_credential,
                "UNRELATED_ENV_VALUE": unrelated_environment_value,
            },
            clear=True,
        ):
            result = collectors._result(
                "cloudflare",
                SINCE,
                UNTIL,
                [
                    {
                        "note": f"active={active_cloudflare_credential}; cross={cross_provider_credential}",
                        "tokensUsed": 4,
                        "expirationTokenCount": 2,
                        "sessionToken": "must-be-omitted",
                        "unrelated": unrelated_environment_value,
                    }
                ],
                1,
                False,
                [],
            )

        rendered = json.dumps(result)
        event = result["events"][0]
        self.assertNotIn(active_cloudflare_credential, rendered)
        self.assertNotIn(cross_provider_credential, rendered)
        self.assertIn("[redacted credential]", event["note"])
        self.assertEqual(event["tokensUsed"], 4)
        self.assertEqual(event["expirationTokenCount"], 2)
        self.assertNotIn("sessionToken", event)
        self.assertEqual(event["unrelated"], unrelated_environment_value)

    def test_redirect_is_explicitly_refused_without_location_or_provider_message(self):
        provider_body_secret = "redirect-provider-body-must-not-appear"
        private_location = "https://untrusted.invalid/with-secret"
        opener = self._mock_http(
            [
                urllib.error.HTTPError(
                    "https://api.cloudflare.com/client/v4/accounts/a/logs/audit",
                    302,
                    provider_body_secret,
                    {"Location": private_location},
                    None,
                )
            ]
        )

        result = collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertEqual(result["integration_status"]["reason"], "redirect_refused")
        self.assertEqual(result["integration_status"]["state"], "integration_unavailable")
        self.assertIn("redirect was refused", " ".join(result["warnings"]))
        rendered = json.dumps(result)
        self.assertNotIn(provider_body_secret, rendered)
        self.assertNotIn(private_location, rendered)
        self.assertEqual(len(opener.requests), 1)

    def test_rate_limit_reports_retry_after_without_echoing_or_retrying(self):
        provider_body_secret = "rate-limit-provider-body-must-not-appear"
        retry_after_value = "987654"
        opener = self._mock_http(
            [
                urllib.error.HTTPError(
                    "https://api.cloudflare.com/client/v4/accounts/a/logs/audit",
                    429,
                    provider_body_secret,
                    {"Retry-After": retry_after_value},
                    None,
                )
            ]
        )

        with mock.patch.object(collectors.time, "sleep") as sleep:
            result = collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertEqual(result["integration_status"]["reason"], "rate_limited")
        warning_text = " ".join(result["warnings"])
        self.assertIn("Retry-After was received", warning_text)
        self.assertIn("no automatic retry was attempted", warning_text)
        rendered = json.dumps(result)
        self.assertNotIn(provider_body_secret, rendered)
        self.assertNotIn(retry_after_value, rendered)
        self.assertEqual(len(opener.requests), 1)
        sleep.assert_not_called()

    def test_streaming_read_uses_one_overall_deadline_not_a_fresh_timeout_per_chunk(self):
        response = _StreamingResponse([b"{", b"}"])
        # The first small chunk arrives at time 100.  A per-recv 15-second timeout
        # would permit another read; the overall deadline at 115 rejects it instead.
        with mock.patch.object(
            collectors.time,
            "monotonic",
            side_effect=[100.0, 100.0, 115.01],
        ):
            with self.assertRaisesRegex(
                collectors.CloudCollectionError,
                "overall HTTP read deadline",
            ):
                collectors._read_response_bytes(response)

        self.assertEqual(len(response.read_sizes), 1)
        self.assertEqual(response.socket.timeouts, [collectors.HTTP_TIMEOUT_SECONDS])

    def test_https_opener_and_tls_handler_are_reused_within_a_collection_process(self):
        opener = _Opener([
            {"success": True, "result": []},
            {"success": True, "result": []},
        ])
        factory = mock.Mock(return_value=opener)
        url = collectors._fixed_url(
            "api.cloudflare.com",
            f"/client/v4/accounts/{CF_ACCOUNT}/logs/audit",
        )

        with mock.patch.object(collectors.urllib.request, "build_opener", factory):
            collectors._request_json(url, {}, method="GET")
            collectors._request_json(url, {}, method="GET")

        self.assertEqual(factory.call_count, 1)
        handlers = factory.call_args.args
        self.assertTrue(any(isinstance(handler, collectors._NoRedirect) for handler in handlers))
        self.assertTrue(any(isinstance(handler, collectors.urllib.request.HTTPSHandler) for handler in handlers))
        self.assertEqual(len(opener.requests), 2)


if __name__ == "__main__":
    unittest.main()
