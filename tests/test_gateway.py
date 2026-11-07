import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from zero_exposure_secret_gateway.core import (
    resolve_secret_intent,
    scan_and_redact_trajectory,
    inject_secret_to_provider,
    compute_secret_receipt,
)


class TestZeroExposureSecretGateway(unittest.TestCase):
    def test_resolve_secret_intent_conversational(self):
        res = resolve_secret_intent(
            description="I am hosting a voice agent on Railway that needs OpenAI and Twilio credentials",
            project="railway-comms",
            service="voice-worker",
        )
        self.assertEqual(res["project"], "railway-comms")
        self.assertEqual(res["service"], "voice-worker")
        self.assertEqual(res["recommended_key"], "OPENAI_API_KEY")
        self.assertIn("TWILIO_AUTH_TOKEN", res["candidate_keys"])

    def test_resolve_explicit_key(self):
        res = resolve_secret_intent(
            description="Custom secret",
            explicit_key="my-custom-webhook-secret",
            project="identity-sentinel",
        )
        self.assertEqual(res["recommended_key"], "MY_CUSTOM_WEBHOOK_SECRET")
        self.assertEqual(res["confidence"], 1.0)

    def test_scan_and_redact_trajectory(self):
        clean_text = "Here is an instruction without any exposed keys."
        scanned = scan_and_redact_trajectory(clean_text)
        self.assertFalse(scanned["has_leaks"])
        self.assertEqual(scanned["leak_count"], 0)
        self.assertEqual(scanned["redacted_text"], clean_text)

    def test_inject_secret_dry_run_hidden_prompt(self):
        secret_input = "mock_secret_placeholder_string_12345"
        res = inject_secret_to_provider(
            key="STRIPE_SECRET_KEY",
            project="tulio-billing",
            service="payments-api",
            environment="production",
            provider="railway",
            dry_run=True,
            prompt_fn=lambda _msg: secret_input,
        )
        self.assertEqual(res["status"], "DRY_RUN_READY")
        self.assertEqual(res["key"], "STRIPE_SECRET_KEY")
        self.assertNotIn(secret_input, res["masked_command"])
        self.assertTrue(res["receipt"]["fingerprint"].startswith("sha256:"))
        self.assertEqual(res["receipt"]["length"], len(secret_input))

    def test_compute_secret_receipt(self):
        rec = compute_secret_receipt("super-secret-value")
        self.assertTrue(rec["verified_non_empty"])
        self.assertEqual(rec["length"], 18)


if __name__ == "__main__":
    unittest.main()
