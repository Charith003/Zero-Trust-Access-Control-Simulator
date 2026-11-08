import unittest

from risk_engine import evaluate_access, normalise_record


class RiskEngineTests(unittest.TestCase):
    def test_normal_request_is_allowed(self):
        record = normalise_record({"mfa_status": 1})
        self.assertEqual(evaluate_access(record)["decision"], "ALLOW")

    def test_mixed_signals_are_challenged(self):
        record = normalise_record({"device_consistency": 0, "login_consistency": 0,
                                   "mfa_status": 1, "sensitive_data": 1, "failed_transactions": 1})
        self.assertEqual(evaluate_access(record)["decision"], "CHALLENGE")

    def test_multiple_anomalies_are_denied(self):
        record = normalise_record({"device_consistency": 0, "location_consistency": 0,
                                   "login_consistency": 0, "mfa_status": 0,
                                   "anomalous_activity": 1, "sensitive_data": 1})
        self.assertEqual(evaluate_access(record)["decision"], "DENY")

    def test_uploaded_json_field_format(self):
        record = normalise_record({"userId": "abc", "loginConsistency": 7,
                                   "accessLocationConsistency": 0, "mfaEnabled": 1,
                                   "sessionDuration": "1:16:30", "failedTransactions": 2})
        self.assertEqual(record["user_id"], "abc")
        self.assertEqual(record["location_consistency"], 0)
        self.assertAlmostEqual(record["session_duration"], 76.5)


if __name__ == "__main__":
    unittest.main()
