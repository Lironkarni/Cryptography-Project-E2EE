import unittest
from HmacHelper import HmacHelper
from Crypto.Random import get_random_bytes

from Utilities.AESHelper import AESHelper


class TestHmacHelper( unittest.TestCase):

    def setUp(self):
        """Setup for HmacHelper tests."""
        self.key = get_random_bytes(32)  # 32-byte key for HMAC
        self.message = b"This is a test message"
        self.salt = get_random_bytes(16)  # 16-byte salt for key derivation

    def test_derive_key(self):
        """Test key derivation using PBKDF2."""
        password = b"password123"
        derived_key = HmacHelper.derive_key(password, self.salt)
        self.assertEqual(len(derived_key), 32, "Derived key length should be 32 bytes.")
        print("Key derivation successful.")

    def test_generate_hmac(self):
        """Test HMAC generation."""
        generated_hmac = HmacHelper.generate_hmac(self.key, self.message)
        self.assertIsInstance(generated_hmac, str, "Generated HMAC should be a string.")
        print(f"Generated HMAC: {generated_hmac}")

    def test_verify_hmac_success(self):
        """Test successful HMAC verification."""
        generated_hmac = HmacHelper.generate_hmac(self.key, self.message)
        verification_result = HmacHelper.verify_hmac(generated_hmac, self.key, self.message)
        self.assertTrue(verification_result, "HMAC verification should succeed.")
        print("HMAC verification succeeded.")

    def test_verify_hmac_failure(self):
        """Test HMAC verification failure with altered message."""
        generated_hmac = HmacHelper.generate_hmac(self.key, self.message)
        altered_message = b"This is an altered message"
        verification_result = HmacHelper.verify_hmac(generated_hmac, self.key, altered_message)
        self.assertFalse(verification_result, "HMAC verification should fail for altered message.")
        print("HMAC verification failed as expected.")

    @staticmethod
    def test_hmac_verify():
        msg = b"hello this is msg"
        key = get_random_bytes(32)
        hmac = HmacHelper.generate_hmac(key , msg)
        print("hmac: " , hmac)
        print("key: " , key)
        print("msg: " , msg)
        print(HmacHelper.verify_hmac(hmac , key , msg))
        print(HmacHelper.verify_hmac(hmac, key, b"ehello this is msg"))

    @staticmethod
    def test_kdf():
        otp = b"123456"
        password = b"<PASSWORD>"
        d_key = HmacHelper.derive_key(b"password123", otp)
        print(d_key)
        d_key = HmacHelper.derive_key(b"password123", b"223456")
        print(d_key)



    if __name__ == "__main__":
         unittest.main()
         test_hmac_verify()
         test_kdf()