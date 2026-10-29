"""Tests for manual cloud collection; every HTTP path is mocked.

No test in this module opens a real network socket or uses actual cloud credentials.
"""

from __future__ import annotations

import json
import os
import sys
import types
import unittest
import urllib.error
import urllib.parse
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


class _RecordingOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return _Response(response)


class CollectorTests(unittest.TestCase):
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
        opener = _RecordingOpener(responses)
        patched = mock.patch.object(
            collectors.urllib.request,
            "build_opener",
            return_value=opener,
        )
        patched.start()
        self.addCleanup(patched.stop)
        return opener

    def test_cloudflare_uses_fixed_https_get_host_and_two_page_cap(self):
        opener = self._mock_http(
            [
                {
                    "success": True,
                    "result": [{"id": "one", "requestParameters": {"token": "drop"}}],
                    "result_info": {"cursor": "next-page"},
                },
                {
                    "success": True,
                    "result": [{"id": "two", "responseElements": {"secret": "drop"}}],
                    "result_info": {"cursor": "would-require-third-page"},
                },
            ]
        )

        result = collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertEqual([event["id"] for event in result["events"]], ["one", "two"])
        self.assertNotIn("requestParameters", result["events"][0])
        self.assertNotIn("responseElements", result["events"][1])
        self.assertEqual(result["coverage"]["pages_fetched"], 2)
        self.assertTrue(result["coverage"]["truncated"])
        self.assertEqual(len(opener.requests), 2)
        for request, timeout in opener.requests:
            parsed = urllib.parse.urlsplit(request.full_url)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.hostname, "api.cloudflare.com")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, collectors.HTTP_TIMEOUT_SECONDS)
            self.assertEqual(parsed.path, f"/client/v4/accounts/{CF_ACCOUNT}/logs/audit")
            query = urllib.parse.parse_qs(parsed.query)
            self.assertEqual(query["since"], [SINCE])
            self.assertEqual(query["before"], [UNTIL])
            self.assertEqual(query["limit"], ["100"])
        self.assertNotIn("cursor", urllib.parse.parse_qs(urllib.parse.urlsplit(opener.requests[0][0].full_url).query))
        self.assertEqual(
            urllib.parse.parse_qs(urllib.parse.urlsplit(opener.requests[1][0].full_url).query)["cursor"],
            ["next-page"],
        )

    def test_missing_pagination_metadata_still_marks_sample_not_all_clear(self):
        opener = self._mock_http([{"success": True, "result": [{"id": "only"}]}])

        result = collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertEqual(len(opener.requests), 1)
        self.assertFalse(result["coverage"]["truncated"])
        self.assertEqual(result["coverage"]["assessment"], "bounded_sample_not_an_all_clear")
        self.assertIn("not an all-clear", " ".join(result["warnings"]))

    def test_scope_time_and_explicit_credential_are_required_before_http(self):
        with self.assertRaises(ValueError):
            collectors.collect_cloud("cloudflare", "not-an-account", SINCE, UNTIL)
        with self.assertRaises(ValueError):
            collectors.collect_cloud("cloudflare", CF_ACCOUNT, UNTIL, SINCE)
        with self.assertRaises(ValueError):
            collectors.collect_cloud(
                "cloudflare", CF_ACCOUNT, "2026-10-01T00:00:00+00:00", UNTIL
            )
        with self.assertRaises(ValueError):
            collectors.collect_cloud(
                "cloudflare", CF_ACCOUNT, "2026-10-01T00:00:00Z", "2026-10-09T00:00:01Z"
            )
        with mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": ""}, clear=False):
            with self.assertRaises(collectors.MissingCredentialError):
                collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

    def test_http_error_is_sanitized_and_cannot_echo_token(self):
        token = "never-return-this-token"
        os.environ["CLOUDFLARE_API_TOKEN"] = token
        opener = self._mock_http(
            [
                urllib.error.HTTPError(
                    "https://api.cloudflare.com/client/v4/accounts/x/logs/audit",
                    403,
                    f"denied for {token}",
                    {},
                    None,
                )
            ]
        )

        result = collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertEqual(len(opener.requests), 1)
        rendered = json.dumps(result)
        self.assertNotIn(token, rendered)
        self.assertIn("status 403", " ".join(result["warnings"]))

    def test_redirect_handler_is_installed_and_no_redirect_url_is_used(self):
        opener = _RecordingOpener([{"success": True, "result": []}])
        captured_handlers = []

        def fake_build_opener(*handlers):
            captured_handlers.extend(handlers)
            return opener

        with mock.patch.object(collectors.urllib.request, "build_opener", side_effect=fake_build_opener):
            collectors.collect_cloud("cloudflare", CF_ACCOUNT, SINCE, UNTIL)

        self.assertTrue(any(isinstance(handler, collectors._NoRedirect) for handler in captured_handlers))
        self.assertEqual(
            urllib.parse.urlsplit(opener.requests[0][0].full_url).hostname,
            "api.cloudflare.com",
        )

    def test_unsupported_provider_does_not_build_or_open_a_request(self):
        with mock.patch.object(
            collectors.urllib.request,
            "build_opener",
            side_effect=AssertionError("network construction must not occur"),
        ):
            with self.assertRaises(collectors.UnsupportedProvider):
                collectors.collect_cloud("unknown-cloud", "workspace_123", SINCE, UNTIL)

    def test_aws_sts_scope_mismatch_prevents_cloudtrail_lookup(self):
        calls = []

        class Sts:
            def get_caller_identity(self):
                calls.append("sts")
                return {"Account": "999999999999"}

        class Session:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def client(self, name, region_name, endpoint_url):
                if endpoint_url != "https://sts.us-east-1.amazonaws.com":
                    raise AssertionError("AWS endpoint must be explicitly provider-owned")
                calls.append(name)
                if name == "sts":
                    return Sts()
                raise AssertionError("CloudTrail must not be created after an identity mismatch")

        fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=Session))
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
            with self.assertRaises(collectors.ScopeMismatchError):
                collectors.collect_cloud("aws", "123456789012", SINCE, UNTIL, region="us-east-1")

        self.assertEqual(calls, ["sts", "sts"])

    def test_render_uses_owner_filtered_service_list_and_bounded_service_event_gets(self):
        opener = self._mock_http(
            [
                [
                    {"service": {"id": "srv-first"}, "cursor": "a"},
                    {"service": {"id": "srv-second"}, "cursor": "b"},
                    {"service": {"id": "srv-third"}, "cursor": "c"},
                ],
                [{"event": {"id": "evt-one", "details": {"envValues": "nope"}}, "cursor": "one"}],
                [{"event": {"id": "evt-two"}, "cursor": "two"}],
            ]
        )

        result = collectors.collect_cloud("render", "tea-workspace1", SINCE, UNTIL)

        self.assertEqual(len(opener.requests), 3)
        first_url = urllib.parse.urlsplit(opener.requests[0][0].full_url)
        self.assertEqual(first_url.hostname, "api.render.com")
        self.assertEqual(first_url.path, "/v1/services")
        self.assertEqual(urllib.parse.parse_qs(first_url.query)["ownerId"], ["tea-workspace1"])
        self.assertTrue(all(request.get_method() == "GET" for request, _ in opener.requests))
        self.assertTrue(result["coverage"]["truncated"])
        self.assertEqual(result["coverage"]["services_sampled"], 2)
        self.assertNotIn("envValues", result["events"][0]["event"]["details"])

    def test_railway_uses_only_documented_read_only_graphql_query(self):
        opener = self._mock_http(
            [
                {
                    "data": {
                        "auditLogs": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "audit-1",
                                        "eventType": "service.updated",
                                        "createdAt": "2026-10-01T00:30:00Z",
                                        "payload": {"secret": "remove", "safe": "retain"},
                                        "context": {},
                                    }
                                }
                            ],
                            "pageInfo": {"hasNextPage": True},
                        }
                    }
                }
            ]
        )

        result = collectors.collect_cloud("railway", "workspace_123", SINCE, UNTIL)

        request = opener.requests[0][0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(urllib.parse.urlsplit(request.full_url).hostname, "backboard.railway.com")
        self.assertEqual(urllib.parse.urlsplit(request.full_url).path, "/graphql/v2")
        request_body = json.loads(request.data.decode("utf-8"))
        self.assertIn("auditLogs(workspaceId:", request_body["query"])
        self.assertNotIn("mutation", request_body["query"].lower())
        self.assertEqual(result["events"][0]["payload"], {"safe": "retain"})
        self.assertTrue(result["coverage"]["truncated"])


if __name__ == "__main__":
    unittest.main()
