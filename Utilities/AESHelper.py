
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESHelper:
    #Initializes the AESHelper object and generate the key and IV
    def __init__(self): #  key_path="aes_key.der", iv_path="aes_iv.der"
        self.key = get_random_bytes(32)
        self.iv = get_random_bytes(16)
        self.block_size = 16

    def set_key(self, new_key):
        if len(new_key) != 32:
            raise ValueError("Invalid key length. Key must be 32 bytes for AES-256.")
        self.key = new_key

    def set_iv(self, new_iv):
        if len(new_iv) != 16:
            raise ValueError("Invalid IV length. IV must be 16 bytes.")
        self.iv = new_iv

    def return_key(self):
        return self.key

    # Pads the plaintext message to make its length a multiple of the AES block size (16 bytes).
    def pad_message(self, message):
        return pad(message, self.block_size)

        # Removes padding from the decrypted message to retrieve the original plaintext.
    def unpad_message(self, padded_message):
        return unpad(padded_message, self.block_size)

    # Encrypts a plaintext message using AES in CBC mode with the loaded key and IV.
    def encrypt(self, message):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_message = self.pad_message(message)
        encrypted_message = cipher.encrypt(padded_message)
        print("Message encrypted.")
        return encrypted_message

    # Decrypts an encrypted message using AES in CBC mode with the loaded key and IV.
    def decrypt(self, encrypted_message):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted_message = cipher.decrypt(encrypted_message)
        print("Message decrypted.")
        return self.unpad_message(decrypted_message)
