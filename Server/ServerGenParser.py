import struct


class ServerGenParser:
    # taking the header from the server each time we call the function
    def __init__(self, code , payload_size):
        """
        Initializes the ServerGenParser object with the given code and payload size.
        Args:
            code: the code of the payload
            payload_size: payload size
        """
        self.code = code
        self.payload_size = payload_size

    def empty_payload(self):
        """
        Creates an empty payload with the given code and payload size.
        Returns: the packet with empty payload using a struct

        """
        return struct.pack("HxxI", self.code, self.payload_size)

    def otp_payload(self, otp_code):
        """
        Creates a payload with the given OTP code.
        Args:
            otp_code: the OTP code to be sent

        Returns: the packet with the OTP code as payload using a struct

        """
        return struct.pack("HxxI6s" , self.code,self.payload_size, otp_code.encode("ascii"))

    # used for each boolean return of payload
    def accept_or_reject_payload(self, bool_val):
        """
        Creates a payload with the given boolean value.
        Args:
            bool_val: the boolean value to send

        Returns: the packet with the boolean value as payload using a struct

        """
        if bool_val:
            return struct.pack("HxxIB", self.code,self.payload_size , 1)
        else:
            return struct.pack("HxxIB", self.code,self.payload_size , 0)

    def phone_payload(self, phone_number):
        """
        Creates a payload with the given phone number.
        Args:
            phone_number: phone number to send

        Returns: the packet with the phone number as payload using a struct

        """
        return struct.pack("HxxI10s" , self.code,self.payload_size, phone_number.encode("ascii"))

    def get_rsa_public_key(self ,public_key, signature):
        """
        Creates a payload with the given public key and signature
        Args:
            public_key: public key of the user
            signature:  signature of the public key

        Returns: the packet with the public key and signature as payload using a struct

        """
        return struct.pack("HxxI294s256s" , self.code,self.payload_size,public_key, signature )

    def get_enc_aes_key(self, sender_phone_number ,aes_key,enc_key_size, signature1, sender_public_key, signature2):
        """
        Creates a payload with the given AES key and signatures.
        Args:
            sender_phone_number: sender phone number
            aes_key:
            enc_key_size:
            signature1: aes key signature
            sender_public_key: sender public key
            signature2: public key signature using the server private key

        Returns: the packet with the AES key and signatures as payload using a struct

        """
        return struct.pack(f"HxxI10s{enc_key_size}s256s294s256s", self.code,self.payload_size, sender_phone_number , aes_key, signature1 ,sender_public_key, signature2)

    def get_encrypted_message(self, enc_message1, message_size1, enc_message2, message_size2, phone_number, iv, hmac1, hmac2):
        """
        Creates a payload with the given encrypted messages and HMACs.
        Args:
            enc_message1: message number 1
            message_size1: message size 1
            enc_message2:  message number 2
            message_size2:  message size 2
            phone_number: sender phone number
            iv: iv of the aes key
            hmac1: hmac of the first message
            hmac2: hmac of the second message

        Returns: the packet with the encrypted messages and HMACs as payload using a struct

        """
        return struct.pack(f"HxxI10sxxII16s32s{message_size1}s32s{message_size2}s" , self.code,self.payload_size, phone_number, message_size1, message_size2 ,iv, hmac1, enc_message1, hmac2, enc_message2 )


    def send_ack(self, ack, phone_number ,hmac ):
        """
        Creates a payload with the given ACK, phone number, and HMAC.
        Args:
            ack: ack value
            phone_number: sender phone number
            hmac: hmac of the message

        Returns: the packet with the ACK, phone number, and HMAC as payload using a struct

        """
        return struct.pack(f"HxxI10s32sb" , self.code,self.payload_size, phone_number.encode("ascii"), hmac, ack)
