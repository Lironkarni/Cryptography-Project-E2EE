import unittest
from Crypto.Random import get_random_bytes
from AESHelper import AESHelper

class TestAESHelper(unittest.TestCase):

    def setUp(self):
        """Setup for AESHelper tests."""
        self.helper = AESHelper()
        self.sample_message = b"This is a test message"
        print("Setup complete.")

    def test_key_and_iv_generation(self):
        """Test that key and IV are generated correctly."""
        self.assertEqual(len(self.helper.key), 32, "Key length should be 32 bytes.")
        self.assertEqual(len(self.helper.iv), 16, "IV length should be 16 bytes.")
        print("Key and IV generated correctly.")

    def test_set_key_and_iv(self):
        """Test setting a custom key and IV."""
        new_key = get_random_bytes(32)
        new_iv = get_random_bytes(16)
        self.helper.set_key(new_key)
        self.helper.set_iv(new_iv)
        self.assertEqual(self.helper.key, new_key, "Custom key was not set correctly.")
        self.assertEqual(self.helper.iv, new_iv, "Custom IV was not set correctly.")
        print("Custom key and IV set successfully.")

    def test_encrypt_and_decrypt(self):
        """Test encryption and decryption of a message."""
        encrypted_message = self.helper.encrypt(self.sample_message)
        decrypted_message = self.helper.decrypt(encrypted_message)
        self.assertEqual(decrypted_message, self.sample_message, "Decrypted message does not match the original.")
        print("Encryption and decryption successful.")

    def test_padding(self):
        """Test message padding and unpadding."""
        padded_message = self.helper._pad_message(self.sample_message)
        unpadded_message = self.helper._unpad_message(padded_message)
        self.assertEqual(unpadded_message, self.sample_message, "Unpadded message does not match the original.")
        print("Padding and unpadding successful.")

    def test_invalid_key_length(self):
        """Test setting an invalid key length."""
        invalid_key = get_random_bytes(16)  # Key length is too short
        with self.assertRaises(ValueError):
            self.helper.set_key(invalid_key)


    def test_invalid_iv_length(self):
        """Test setting an invalid IV length."""
        invalid_iv = get_random_bytes(8)  # IV length is too short
        with self.assertRaises(ValueError):
            self.helper.set_iv(invalid_iv)

    @staticmethod
    def test_enc_dec():
        aes_helper = AESHelper()
        print("key:")
        print(aes_helper.key)
        print("iv:")
        print(aes_helper.iv)
        msg = b"hello this is msg"
        print("msg: " , msg)
        enc_msg = aes_helper.encrypt(msg)
        print("encrypt msg: " , enc_msg)
        dec_msg = aes_helper.decrypt(enc_msg)
        print("decrypt msg: " , dec_msg)

    @staticmethod
    def test_set_key_iv():
        aes_helper = AESHelper()
        print("key:")
        print(aes_helper.key)
        print("iv:")
        print(aes_helper.iv)
        new_key = get_random_bytes(32)
        new_iv = get_random_bytes(16)
        aes_helper.set_key(new_key)
        aes_helper.set_iv(new_iv)
        print("key:")
        print(aes_helper.key)
        print("iv:")
        print(aes_helper.iv)

    @staticmethod
    def pad_unpad():
        aes_helper = AESHelper()
        msg = b"abcdef"
        print("unpad1 msg: " , msg)
        pad_msg = aes_helper._pad_message(msg)
        print("pad msg: " , pad_msg)
        unpad_msg = aes_helper._unpad_message(pad_msg)
        print("unpad msg2: " , unpad_msg)




    if __name__ == "__main__":

        print("hi")

        unittest.main()

        test_set_key_iv()
        test_enc_dec()
        pad_unpad()
