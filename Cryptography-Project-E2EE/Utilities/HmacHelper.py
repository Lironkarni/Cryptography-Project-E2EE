import hashlib
import hmac


class HmacHelper:

    # Create Derive key for the registration stage
    @staticmethod
    def derive_key(password, salt, iterations=100000, key_length=32):
        derived_key = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password,
            salt=salt,
            iterations=iterations,
            dklen=key_length
        )
        return derived_key

    # check the signture
    @staticmethod
    def verify_hmac(received_hmac, key, message):
        # replace with generate_hmac
        calculated_hmac = hmac.new(key, message, hashlib.sha256).digest()
        if hmac.compare_digest(calculated_hmac, received_hmac):
            print("HMAC verification succeeded.")
            return True
        else:
            print("HMAC verification failed.")
            return False

    # create H-MAC
    @staticmethod
    def generate_hmac(key, message):
        # replace with
        hmac_object = hmac.new(key, message, hashlib.sha256)
        return hmac_object.digest()

