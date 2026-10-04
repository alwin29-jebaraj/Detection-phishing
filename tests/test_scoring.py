"""
Unit tests for Explainable Risk Scoring and Synthetic Test Cases.
"""
import unittest
from models.analysis import Indicator
from scoring.risk_scorer import calculate_risk_score, generate_recommendation
from analyzers.rule_engine import run_email_rules
from analyzers.url_analyzer import analyze_url

class TestScoring(unittest.TestCase):

    def test_score_calculation(self):
        indicators = [
            Indicator("Urgent language", "desc", "medium", 12, "urgent"),
            Indicator("Threatening language", "desc", "high", 15, "suspended"),
            Indicator("Credential request", "desc", "high", 20, "verify account"),
        ]
        score, level, breakdown = calculate_risk_score(indicators)
        self.assertEqual(score, 47)
        self.assertEqual(level, "MEDIUM")
        self.assertEqual(len(breakdown), 3)

    def test_score_capping_at_100(self):
        indicators = [
            Indicator("Critical 1", "desc", "critical", 35, "ev1"),
            Indicator("Critical 2", "desc", "critical", 35, "ev2"),
            Indicator("Critical 3", "desc", "critical", 35, "ev3"),
            Indicator("Critical 4", "desc", "critical", 35, "ev4"),
        ]
        score, level, breakdown = calculate_risk_score(indicators)
        self.assertEqual(score, 100)
        self.assertEqual(level, "CRITICAL")

    def test_risk_level_thresholds(self):
        # 0-24: LOW
        self.assertEqual(calculate_risk_score([Indicator("Low", "", "low", 15, "")])[1], "LOW")
        # 25-49: MEDIUM
        self.assertEqual(calculate_risk_score([Indicator("Med", "", "medium", 30, "")])[1], "MEDIUM")
        # 50-74: HIGH
        self.assertEqual(calculate_risk_score([Indicator("High", "", "high", 65, "")])[1], "HIGH")
        # 75-100: CRITICAL
        self.assertEqual(calculate_risk_score([Indicator("Crit", "", "critical", 85, "")])[1], "CRITICAL")

    def test_synthetic_case_1_high_risk(self):
        """
        Test 1 — High Risk
        Subject: “Urgent: Your Account Will Be Suspended”
        https://secure-account-verification.example.com/login
        Expected result: HIGH or CRITICAL risk.
        """
        email = """
        Subject: Urgent: Your Account Will Be Suspended

        Dear Customer,

        Your account will be suspended today due to unusual activity. Verify your account immediately using the link below:

        https://secure-account-verification.example.com/login

        Failure to verify will result in permanent suspension.
        """
        indicators, urls = run_email_rules(email)
        score, level, breakdown = calculate_risk_score(indicators)
        self.assertIn(level, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(score, 50)

    def test_synthetic_case_2_medium_risk(self):
        """
        Test 2 — Medium Risk
        Account notification, request to review activity, one suspicious call to action.
        Expected result: MEDIUM risk.
        """
        email = """
        Subject: Account Security Review Notification

        Hello user,

        We noticed a login from an unfamiliar device. Please review your account activity. 
        Click here to update your information if this was not you.
        """
        indicators, urls = run_email_rules(email)
        score, level, breakdown = calculate_risk_score(indicators)
        self.assertIn(level, ["MEDIUM", "HIGH"])
        self.assertGreaterEqual(score, 25)

    def test_synthetic_case_3_low_risk(self):
        """
        Test 3 — Low Risk
        Normal routine fictional notification without urgency, threats, or credentials.
        Expected result: LOW risk.
        """
        email = """
        Subject: Weekly Engineering Newsletter #42

        Hello team,

        Welcome to this week's edition. We have successfully rolled out the updated documentation portal.
        Check out the release notes on the internal wiki for details on new team guidelines.

        Best regards,
        Engineering Operations
        """
        indicators, urls = run_email_rules(email)
        score, level, breakdown = calculate_risk_score(indicators)
        self.assertEqual(level, "LOW")
        self.assertLessEqual(score, 24)

if __name__ == '__main__':
    unittest.main()
