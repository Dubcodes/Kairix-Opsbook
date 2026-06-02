import base64
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "app"
sys.path.insert(0, str(APP_ROOT))

from kairix.security import (
    HASH_ITERATIONS,
    challenge_match,
    hash_password,
    password_hash_needs_upgrade,
    verify_password,
)


def legacy_hash(password: str, iterations: int = 1_000) -> str:
    salt = b"legacy-test-salt"
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    )


class SecurityHardeningTest(unittest.TestCase):
    def test_legacy_hashes_still_verify_but_need_upgrade(self) -> None:
        stored_hash = legacy_hash("correct horse battery staple")

        self.assertTrue(verify_password("correct horse battery staple", stored_hash))
        self.assertTrue(password_hash_needs_upgrade(stored_hash))

    def test_new_hash_uses_current_work_factor(self) -> None:
        stored_hash = hash_password("another good long phrase")

        self.assertTrue(verify_password("another good long phrase", stored_hash))
        self.assertFalse(password_hash_needs_upgrade(stored_hash))
        self.assertIn(f"pbkdf2_sha256${HASH_ITERATIONS}$", stored_hash)

    def test_challenge_match_identifies_account_or_reveal_secret(self) -> None:
        account_hash = legacy_hash("account password")
        reveal_hash = legacy_hash("reveal phrase")

        self.assertEqual(challenge_match("account password", account_hash, reveal_hash), "primary")
        self.assertEqual(challenge_match("reveal phrase", account_hash, reveal_hash), "secondary")
        self.assertEqual(challenge_match("wrong", account_hash, reveal_hash), "")


if __name__ == "__main__":
    unittest.main()
