import unittest
import os
from Crypto.PublicKey import RSA
from RSAHelper import RSAHelper

class TestRSAHelper():

    def setUp(self):
        """Setup for RSAHelper tests."""
        self.phone_number = "1234567890"
        self.rsa_helper = RSAHelper(self.phone_number)
        self.test_message = "This is a test message"

    def tearDown(self):
        """Cleanup generated key files."""
        private_key_file = f"{self.phone_number}_private.der"
        public_key_file = f"{self.phone_number}_public.der"
        if os.path.exists(private_key_file):
            os.remove(private_key_file)
        if os.path.exists(public_key_file):
            os.remove(public_key_file)

    def test_key_generation(self):
        """Test RSA key generation."""
        self.assertGreater(len(self.rsa_helper.private_key), 0, "Private key is empty.")
        self.assertGreater(len(self.rsa_helper.public_key), 0, "Public key is empty.")
        print(f"Actual private key length: {len(self.rsa_helper.private_key)}")
        print(f"Actual public key length: {len(self.rsa_helper.public_key)}")
        print("Key generation successful.")

    def test_save_and_load_keys(self):
        """Test saving and loading RSA keys to/from files."""
        self.rsa_helper.save_keys_to_file()
        self.rsa_helper.load_keys_from_file()
        self.assertIsNotNone(self.rsa_helper.private_key, "Private key not loaded correctly.")
        self.assertIsNotNone(self.rsa_helper.public_key, "Public key not loaded correctly.")
        print("Save and load keys successful.")

    def test_sign_and_verify_message(self):
        """Test signing and verifying a message."""
        signature = self.rsa_helper.sign_message(self.phone_number, self.test_message)
        verification_result = RSAHelper.verify_signature(self.test_message, signature, self.rsa_helper.public_key)
        self.assertTrue(verification_result, "Message signature verification failed.")
        print("Sign and verify message successful.")

    def test_encrypt_and_decrypt_message(self):
        """Test encryption and decryption of a message."""
        encrypted_message = RSAHelper.encrypt_with_public_key(self.rsa_helper.public_key, self.test_message)
        decrypted_message = self.rsa_helper.decrypt_with_private_key(self.phone_number, encrypted_message)
        self.assertEqual(decrypted_message, self.test_message, "Decrypted message does not match the original.")
        print("Encrypt and decrypt message successful.")

    def test_get_server_public_key(self):
        """Test loading server public key when file exists."""
        self.rsa_helper.save_server_keys()  # Save the server keys to ensure file exists
        public_key = RSAHelper.get_server_public_key()
        self.assertIsNotNone(public_key, "Failed to load server public key.")
        print("Get server public key successful.")

    @staticmethod
    def test_a_b_dec_enc():
        rsa_a = RSAHelper("0500000000")
        rsa_b = RSAHelper("0511111111")

        print("rsa_a.public_key:" , rsa_a.public_key)
        print("rsa_b.public_key:" , rsa_b.public_key)
        print("rsa_a.private:", rsa_a.private_key)
        print("rsa_b.private:", rsa_b.private_key)

        msg = "hello this is msg"
        print("msg: " , msg)
        enc_msg = rsa_a.encrypt_with_public_key(rsa_b.public_key, msg)
        print("encrypt msg: " , enc_msg)
        dec_msg = rsa_b.decrypt_with_private_key(rsa_a.phone_number, enc_msg)
        print("decrypt msg: " , dec_msg)




    if __name__ == "__main__":
        #unittest.main()
        test_a_b_dec_enc()
