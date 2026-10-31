import unittest

from promptscreen.detectors import find_pii, find_secrets, luhn_ok, shannon_entropy


class Entropy(unittest.TestCase):
    def test_uniform_single_char(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_two_symbols(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0, places=6)

    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)


class Luhn(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(luhn_ok("4111111111111111"))

    def test_invalid(self):
        self.assertFalse(luhn_ok("4111111111111112"))


class Secrets(unittest.TestCase):
    def test_aws_key_blocks(self):
        hits = find_secrets("creds AKIAIOSFODNN7EXAMPLE here")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule, "secret.aws_access_key")
        self.assertEqual(hits[0].action, "block")

    def test_clean_text(self):
        self.assertEqual(find_secrets("the quick brown fox jumps over the lazy dog"), [])

    def test_high_entropy_token(self):
        hits = find_secrets("token=A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6 ok")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule, "secret.high_entropy")
        self.assertEqual(hits[0].action, "flag")


class PII(unittest.TestCase):
    def test_email(self):
        hits = find_pii("reach me at alice@example.com please")
        self.assertEqual([h.rule for h in hits], ["pii.email"])

    def test_ssn(self):
        hits = find_pii("ssn 123-45-6789")
        self.assertEqual([h.rule for h in hits], ["pii.ssn"])

    def test_valid_card(self):
        hits = find_pii("card 4111 1111 1111 1111")
        self.assertIn("pii.card", [h.rule for h in hits])

    def test_invalid_card_not_flagged(self):
        hits = find_pii("number 4111 1111 1111 1112")
        self.assertNotIn("pii.card", [h.rule for h in hits])


if __name__ == "__main__":
    unittest.main()
