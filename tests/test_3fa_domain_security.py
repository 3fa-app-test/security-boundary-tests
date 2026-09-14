import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class ThreeFADomainSecurityTests(unittest.TestCase):
    def test_factor_resource_paths_reject_encoded_escape(self) -> None:
        for value in ("issuers/%2e%2e/secrets.json", "recovery/%252E%252E/key", "%2E%2e/factors.db"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_authenticator_callback_urls_reject_authority_confusion(self) -> None:
        allowed = {"auth.example.test"}
        for value in (
            "//auth.example.test/callback",
            "https://auth.example.test@attacker.invalid/callback",
            "https://attacker.invalid/auth.example.test/callback",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
