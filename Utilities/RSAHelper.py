import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

class RSAHelper:
#Initializes the RSAHelper class and generates\loads RSA keys.
    def __init__(self,phone_number):
        self.key_size = 2048
        self.phone_number = phone_number
        self.keys = RSA.generate(self.key_size)
        self.private_key = self.keys.exportKey('DER')
        self.public_key = self.keys.publickey().exportKey('DER')

    def set_keys(self, public_key, private_key):
        self.private_key = private_key
        self.public_key = public_key

    def save_keys_to_file(self):
        private_key_file = f"{self.phone_number}_private.der"
        public_key_file = f"{self.phone_number}_public.der"
        # Save the private key
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(self.private_key)
        # Save the public key
        with open(public_key_file, "wb") as pub_file:
            pub_file.write(self.public_key)

    def save_server_keys(self):
        private_key_file = "server_private.der"
        public_key_file = "server_public.der"

        with open(private_key_file, "wb") as priv_file:
            priv_file.write(self.private_key)
        print(f"[Server] Private key saved to {private_key_file}.")

        with open(public_key_file, "wb") as pub_file:
            pub_file.write(self.public_key)
        print(f"[Server] Public key saved to {public_key_file}.")


    @staticmethod
    def get_server_public_key():
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Build the path to the file in the Server folder
        public_key_file = os.path.join(script_dir, "../Server/server_public.der")
        public_key_file = os.path.normpath(public_key_file)
        try:
            with open(public_key_file, "rb") as pub_file:
                public_key = RSA.importKey(pub_file.read())
            print(f"[Server] Public key loaded successfully from {public_key_file}.")
            return public_key
        except FileNotFoundError:
            raise Exception("[Server] Public key file not found. Ensure it has been generated and saved.")


    def load_keys_from_file(self):
        private_key_file = f"{self.phone_number}_private.der"
        public_key_file = f"{self.phone_number}_public.der"

        if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
            raise FileNotFoundError("Key files not found. Ensure keys are generated and saved first.")

        with open(private_key_file, "rb") as priv_file:
            self.private_key = RSA.importKey(priv_file.read())
        print(f"Loaded private key from {private_key_file}.")

        with open(public_key_file, "rb") as pub_file:
            self.public_key = RSA.importKey(pub_file.read())
        print(f"Loaded public key from {public_key_file}.")

#Decrypts a message using the private key.
    def decrypt_with_private_key(self, phone_number, encrypted_message):
        rsa_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_message = cipher.decrypt(encrypted_message)
        print("Message decrypted successfully.")
        return decrypted_message

#Signs a message with the private key and returns the signature.
    def sign_message(self, message):
        priv_key = RSA.importKey(self.private_key)
        if isinstance(message, bytes):
            hash_obj = SHA256.new(message)
        else:
            hash_obj = SHA256.new(message.encode())
        signer = pkcs1_15.new(priv_key)
        signature = signer.sign(hash_obj)
        print("Message signed successfully.")
        return signature

#Verifies the signature of a message using the provided public key.
    @staticmethod
    def verify_signature(message, signature, public_key):
        try:
            if isinstance(message, bytes):
                hash_obj = SHA256.new(message)
            else:
                hash_obj = SHA256.new(message.encode())
            verifier = pkcs1_15.new(public_key)
            verifier.verify(hash_obj, signature)
            print("Signature verification succeeded.")
            return True
        except (ValueError, TypeError):
            print("Signature verification failed.")
            return False

#Encrypts a message using the provided public key.
    @staticmethod
    def encrypt_with_public_key(public_key_der, message):
        recipient_public_key = RSA.import_key(public_key_der)
        cipher = PKCS1_OAEP.new(recipient_public_key)
        if isinstance(message, bytes):
            encrypted_message = cipher.encrypt(message)
        else:
            encrypted_message = cipher.encrypt(message.encode())
        print("Message encrypted with recipient's public key.")
        return encrypted_message


    @staticmethod
    def get_rsa_public_key_instance_from_bytes(public_key_bytes):
        return RSA.importKey(public_key_bytes)