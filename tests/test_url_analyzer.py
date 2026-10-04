"""
Unit tests for URL Analyzer.
Statically evaluates URLs without network requests.
"""
import unittest
from analyzers.url_analyzer import analyze_url

class TestUrlAnalyzer(unittest.TestCase):

    def test_suspicious_synthetic_url(self):
        url = "https://secure-account-verification.example.com/login"
        res = analyze_url(url)
        self.assertTrue(res.is_https)
        self.assertGreaterEqual(res.hyphen_count, 2)
        self.assertIn("login", res.matched_keywords)
        self.assertTrue(any("verif" in k for k in res.matched_keywords))
        
        # Check that indicators were triggered
        indicator_names = [ind.indicator for ind in res.indicators]
        self.assertTrue(any("Login" in n for n in indicator_names))
        self.assertTrue(any("Verification" in n for n in indicator_names))

    def test_ip_address_host(self):
        url = "http://192.168.1.100/secure/login.php"
        res = analyze_url(url)
        self.assertTrue(res.has_ip_address)
        indicator_names = [ind.indicator for ind in res.indicators]
        self.assertTrue(any("IP Address" in n for n in indicator_names))

    def test_brand_impersonation_in_subdomain(self):
        url = "https://paypal-security-update.attacker-domain.com/auth"
        res = analyze_url(url)
        indicator_names = [ind.indicator for ind in res.indicators]
        self.assertTrue(any("Brand Name" in n or "Impersonation" in n for n in indicator_names))

    def test_authority_at_symbol(self):
        url = "http://legitimate-bank.com@malicious-site.com/login"
        res = analyze_url(url)
        self.assertTrue(res.has_suspicious_characters)
        indicator_names = [ind.indicator for ind in res.indicators]
        self.assertTrue(any("Deceptive Authority '@'" in n for n in indicator_names))

    def test_safe_clean_url(self):
        url = "https://www.example.com/about/contact-us"
        res = analyze_url(url)
        self.assertFalse(res.has_ip_address)
        self.assertFalse(res.has_suspicious_characters)
        self.assertEqual(len(res.indicators), 0)

if __name__ == '__main__':
    unittest.main()
