import json
import socket
import unittest
from unittest.mock import patch

from reverse_shell_decoy.cloud import analyze_cloud_logs


class CloudLogAnalysisTests(unittest.TestCase):
    def test_aws_records_envelope_and_logging_disable_review(self):
        content = json.dumps(
            {
                "Records": [
                    {
                        "eventID": "native-aws-1",
                        "eventTime": "2026-02-01T01:02:03Z",
                        "eventSource": "cloudtrail.amazonaws.com",
                        "eventName": "StopLogging",
                        "sourceIPAddress": "192.0.2.10",
                        "userIdentity": {"type": "IAMUser", "principalId": "opaque"},
                        "requestParameters": {"secret": "must-not-appear"},
                    }
                ]
            }
        )

        report = analyze_cloud_logs("aws", content)

        self.assertEqual(report["source_kind"], "manual_cloud_log_import")
        self.assertFalse(report["source_is_synthetic"])
        self.assertFalse(report["simulation"])
        self.assertEqual(report["summary"]["counts"]["events"], 1)
        self.assertEqual(report["events"][0]["timestamp_utc"], "2026-02-01T01:02:03Z")
        self.assertEqual(report["events"][0]["source_ip"], "192.0.2.10")
        self.assertIn("identity_sha256", report["events"][0])
        self.assertNotIn("requestParameters", json.dumps(report))
        self.assertEqual(report["findings"][0]["category"], "logging_configuration")
        self.assertEqual(report["findings"][0]["confidence"], "medium")
        self.assertIn(report["events"][0]["event_id"], report["findings"][0]["event_ids"])

    def test_cloudflare_result_envelope_and_change_scope(self):
        content = json.dumps(
            {
                "result": [
                    {
                        "id": "native-cf-1",
                        "action": "zone.settings.change",
                        "timestamp": "2026-02-01T01:02:03+00:00",
                        "ip": "198.51.100.10",
                        "actor": {"email": "operator@example.invalid"},
                        "resources": [{"resource_type": "zone", "resource_id": "redacted"}],
                    }
                ]
            }
        )

        report = analyze_cloud_logs("cloudflare", content)

        self.assertEqual(report["events"][0]["provider"], "cloudflare")
        self.assertEqual(report["events"][0]["category"], "dns_configuration")
        self.assertEqual(report["events"][0]["resource_type"], "zone")
        self.assertEqual(report["findings"][0]["category"], "dns_configuration")
        self.assertNotIn("operator@example.invalid", json.dumps(report))

    def test_render_events_wrapper_and_railway_logs_wrapper(self):
        render_content = json.dumps(
            {
                "events": [
                    {
                        "timestamp": "2026-02-01T01:02:03Z",
                        "actor": "operator@example.invalid",
                        "event": "StartShellEvent",
                        "status": "success",
                        "metadata": {
                            "service": "private-service-name",
                            "source_ip": "203.0.113.10",
                            "token": "not-returned",
                        },
                    }
                ]
            }
        )
        railway_content = json.dumps(
            {
                "logs": [
                    {
                        "id": "native-railway-1",
                        "eventType": "workspace.member.role.update",
                        "createdAt": "2026-02-01T01:02:03Z",
                        "actor": {"id": "operator-id"},
                        "payload": {"environmentValue": "not-returned"},
                    }
                ]
            }
        )

        render = analyze_cloud_logs("render", render_content)
        railway = analyze_cloud_logs("railway", railway_content)

        self.assertEqual(render["events"][0]["category"], "shell_access")
        self.assertEqual(render["findings"][0]["category"], "shell_access")
        self.assertEqual(render["events"][0]["resource_type"], "service")
        self.assertNotIn("private-service-name", json.dumps(render))
        self.assertNotIn("not-returned", json.dumps(render))
        self.assertEqual(railway["events"][0]["category"], "workspace_permissions")
        self.assertEqual(railway["findings"][0]["category"], "workspace_permissions")
        self.assertNotIn("operator-id", json.dumps(railway))
        self.assertNotIn("environmentValue", json.dumps(railway))

    def test_no_network_or_account_connection_is_attempted(self):
        content = json.dumps({"Records": []})
        with patch.object(socket, "create_connection", side_effect=AssertionError("network call")):
            report = analyze_cloud_logs("aws", content)

        self.assertEqual(report["records_seen"], 0)
        self.assertFalse(report["source_is_synthetic"])
        self.assertNotIn("connected", json.dumps(report).lower())
        self.assertNotIn("scanned", json.dumps(report).lower())

    def test_zero_records_is_unknown_and_incomplete_not_clean(self):
        report = analyze_cloud_logs("aws", json.dumps({"Records": []}))

        self.assertEqual(report["events"], [])
        self.assertTrue(report["summary"]["missing_coverage"]["no_usable_records"])
        self.assertEqual(report["summary"]["coverage_status"], "unknown")
        self.assertTrue(any("unknown and incomplete" in warning for warning in report["warnings"]))
        self.assertIn("No result is an all-clear", report["limitation_notice"])

    def test_malformed_and_deep_json_are_safe_and_coverage_unknown(self):
        malformed = analyze_cloud_logs("aws", '{"Records": [}')
        deeply_nested = "[" * 70 + "0" + "]" * 70
        deep = analyze_cloud_logs("aws", deeply_nested, format="json")

        for report in (malformed, deep):
            self.assertEqual(report["events"], [])
            self.assertTrue(report["summary"]["missing_coverage"]["input_unparseable"])
            self.assertEqual(report["summary"]["coverage_status"], "unknown")
            self.assertTrue(any("coverage is unknown" in warning for warning in report["warnings"]))

    def test_text_fallback_is_bounded_escaped_and_secret_redacted(self):
        line = "2026-02-01T01:02:03Z StartShellEvent token=supersecret <unsafe>"
        report = analyze_cloud_logs("render", line, format="text")
        encoded = json.dumps(report)

        self.assertEqual(report["input_format"], "text")
        self.assertEqual(report["events"][0]["category"], "shell_access")
        self.assertIn("source_event_sha256", report["events"][0])
        self.assertIn("[REDACTED]", report["events"][0]["text_excerpt"])
        self.assertIn("&lt;unsafe&gt;", report["events"][0]["text_excerpt"])
        self.assertNotIn("supersecret", encoded)
        self.assertTrue(any("fallback" in warning for warning in report["warnings"]))

    def test_render_and_railway_unknown_events_do_not_be_promoted_to_findings(self):
        render = analyze_cloud_logs(
            "render", json.dumps({"events": [{"event": "UnknownFutureEvent"}]})
        )
        railway = analyze_cloud_logs(
            "railway", json.dumps({"logs": [{"eventType": "new.future.event"}]})
        )

        self.assertEqual(render["events"][0]["category"], "render_workspace_activity")
        self.assertEqual(render["findings"], [])
        self.assertEqual(railway["events"][0]["category"], "railway_workspace_activity")
        self.assertEqual(railway["findings"], [])
        with self.assertRaises(ValueError):
            analyze_cloud_logs("unsupported", "{}")

    def test_record_and_input_limits(self):
        content = json.dumps({"Records": [{"eventName": "One"}, {"eventName": "Two"}]})
        with patch("reverse_shell_decoy.cloud.MAX_RECORDS", 1):
            report = analyze_cloud_logs("aws", content)
        self.assertEqual(report["summary"]["counts"]["events"], 1)
        self.assertTrue(report["summary"]["missing_coverage"]["record_limit_reached"])
        self.assertTrue(any("record limit" in warning for warning in report["warnings"]))
        with patch("reverse_shell_decoy.cloud.MAX_INPUT_BYTES", 4):
            with self.assertRaises(ValueError):
                analyze_cloud_logs("aws", "12345")

    def test_synthetic_demo_wrapper_never_looks_like_an_account_observation(self):
        content = json.dumps(
            {
                "demo": True,
                "Records": [
                    {
                        "simulation": True,
                        "eventTime": "2026-02-01T01:02:03Z",
                        "eventSource": "cloudtrail.amazonaws.com",
                        "eventName": "DeleteTrail",
                    }
                ],
            }
        )
        report = analyze_cloud_logs("aws", content)

        self.assertTrue(report["source_is_synthetic"])
        self.assertFalse(report["simulation"])
        self.assertTrue(report["events"][0]["simulation"])
        self.assertEqual(report["events"][0]["observation"], "synthetic_demo_record")
        self.assertTrue(report["findings"][0]["simulation"])
        self.assertTrue(any("synthetic demo" in warning for warning in report["warnings"]))

    def test_five_operational_errors_make_a_timed_burst_not_a_compromise_claim(self):
        records = [
            {
                "eventTime": f"2026-02-01T01:0{index}:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "LookupEvents",
                "errorCode": "ServiceError",
            }
            for index in range(5)
        ]
        report = analyze_cloud_logs("aws", json.dumps({"Records": records}))

        bursts = [
            finding
            for finding in report["findings"]
            if finding["category"] == "operational_error_burst"
        ]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["event_count"], 5)
        self.assertIn("not evidence of compromise", bursts[0]["indicator"])
        self.assertEqual(bursts[0]["confidence"], "low")


if __name__ == "__main__":
    unittest.main()
