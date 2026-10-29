import json
import unittest

from reverse_shell_decoy.cloud import analyze_cloud_logs


class CloudRoundTripTests(unittest.TestCase):
    def test_manual_collector_wrappers_retain_native_actions_and_coverage(self):
        examples = {
            "aws": ({"CloudTrailEvent": {"eventTime": "2026-10-29T12:00:00Z", "eventName": "StopLogging"}}, "StopLogging"),
            "cloudflare": ({"when": "2026-10-29T12:00:00Z", "action": {"type": "update", "description": "DNS record updated"}, "resource": {"type": "dns"}}, None),
            "render": ({"event": {"timestamp": "2026-10-29T12:00:00Z", "type": "deploy_started"}}, "deploy_started"),
            "railway": ({"createdAt": "2026-10-29T12:00:00Z", "eventType": "deployment.created"}, "deployment.created"),
        }
        for provider, (event, expected) in examples.items():
            with self.subTest(provider=provider):
                data = {"provider": provider, "source": "manual_read_only_cloud_api", "coverage": {"truncated": True}, "events": [event]}
                result = analyze_cloud_logs(provider, json.dumps(data))
                self.assertEqual(len(result["events"]), 1)
                self.assertIn("timestamp_utc", result["events"][0])
                self.assertTrue(any("truncated" in w for w in result["warnings"]))
                if expected:
                    self.assertEqual(result["events"][0]["action"], expected)

    def test_cloudtrail_event_history_json_text_is_normalized(self):
        event = {"CloudTrailEvent": json.dumps({"eventName": "StopLogging", "eventTime": "2026-10-29T12:00:00Z"})}
        result = analyze_cloud_logs("aws", json.dumps({"Records": [event]}))
        self.assertEqual(result["events"][0]["action"], "StopLogging")
        self.assertTrue(result["findings"])


if __name__ == "__main__":
    unittest.main()
