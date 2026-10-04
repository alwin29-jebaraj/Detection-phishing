"""
Unit tests for the Phishing Rule Engine.
Uses synthetic safe test cases.
"""
import unittest
from analyzers.rule_engine import run_email_rules

class TestRuleEngine(unittest.TestCase):

    def test_urgent_language(self):
        sample = "Please verify your account immediately. This is urgent."
        indicators, urls = run_email_rules(sample)
        names = [ind.indicator for ind in indicators]
        self.assertTrue(
            any("urgent" in name.lower() or "immediate" in name.lower() for name in names),
            f"Expected urgent indicator in {names}"
        )

    def test_account_suspension(self):
        sample = "Your account will be suspended today due to unusual activity. Failure to verify will result in permanent suspension."
        indicators, urls = run_email_rules(sample)
        names = [ind.indicator for ind in indicators]
        self.assertTrue(
            any("suspension" in name.lower() or "suspended" in name.lower() for name in names),
            f"Expected suspension indicator in {names}"
        )
        self.assertTrue(
            any("unusual activity" in name.lower() for name in names),
            f"Expected unusual activity indicator in {names}"
        )

    def test_credential_request(self):
        sample = "Dear customer, please verify your account and confirm your password to restore access."
        indicators, urls = run_email_rules(sample)
        names = [ind.indicator for ind in indicators]
        self.assertTrue(
            any("verification" in name.lower() or "credential" in name.lower() or "password" in name.lower() for name in names),
            f"Expected credential/verification indicator in {names}"
        )

    def test_financial_request(self):
        sample = "Please update your credit card and bank account details for your pending refund."
        indicators, urls = run_email_rules(sample)
        names = [ind.indicator for ind in indicators]
        self.assertTrue(
            any("card" in name.lower() or "bank" in name.lower() or "refund" in name.lower() for name in names),
            f"Expected financial indicator in {names}"
        )

    def test_suspicious_cta(self):
        sample = "Please click here to update your information and verify now."
        indicators, urls = run_email_rules(sample)
        names = [ind.indicator for ind in indicators]
        self.assertTrue(
            any("click" in name.lower() or "cta" in name.lower() or "verify" in name.lower() for name in names),
            f"Expected call to action indicator in {names}"
        )

    def test_low_risk_message(self):
        sample = (
            "Hi Alex, attached is the minutes from our Tuesday engineering sync. "
            "Let me know if you have feedback before our next sprint on Monday. Thanks!"
        )
        indicators, urls = run_email_rules(sample)
        self.assertEqual(len(indicators), 0, f"Expected 0 indicators for benign text, got {indicators}")

    def test_synthetic_high_risk_combination(self):
        sample = """
        Subject: Urgent: Your Account Will Be Suspended
        
        Dear Customer,
        Your account will be suspended today due to unusual activity. 
        Verify your account immediately using the link below:
        https://secure-account-verification.example.com/login
        Failure to verify will result in permanent suspension.
        """
        indicators, urls = run_email_rules(sample)
        self.assertGreaterEqual(len(indicators), 4)
        self.assertIn("https://secure-account-verification.example.com/login", urls)

if __name__ == '__main__':
    unittest.main()
