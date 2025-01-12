import struct

class ClientParser:
    def __init__(self, content):
        """
        the header from the server
        Args:
            content: the raw data packet
        """
        self.header = struct.unpack("HxxI" ,content[:8])
        self.code = self.header[0]
        self.payload_size = self.header[1]
        self.payload_raw = content[8:8+self.payload_size]
        self.payload = None


    def otp_payload(self):
        """
        gets an otp payload from the server and sets the payload to have the otp payload

        """
        self.payload = struct.unpack("6s" , self.payload_raw)

    # used for each boolean return of payload
    def accept_or_reject_payload(self):
        """
        gets an accept or reject payload and sets it.

        """
        self.payload = struct.unpack("B" , self.payload_raw)

    def phone_number_payload(self):
        """
        gets a phone number payload and sets it.

        """
        self.payload = struct.unpack("10s" , self.payload_raw)

    def get_rsa_public_key(self):
        """
        gets a rsa public key and signature payload and sets it.

        """
        self.payload = struct.unpack("294s256s" , self.payload_raw)

    def get_enc_aes_key(self):
        """
        gets sender phone number, encrypted aes key, public key of other user, and signatures for both of them for the payload and sets it.
        """
        self.payload = struct.unpack(f"10s{self.payload_size-816}s256s294s256s" , self.payload_raw)

    def get_encrypted_message(self):
        """
        gets the sender phone number, the encrypted message with message size, and the hmac of the message and sets it.
        """
        message_size = struct.unpack(f"10sxxII" , self.payload_raw[:20])
        if message_size[2] > 0:
            self.payload = struct.unpack(f"10sxxII16s32s{message_size[1]}s32s{message_size[2]}s" , self.payload_raw)
        else:
            self.payload = struct.unpack(f"10sxxII16s32s{message_size[1]}s" , self.payload_raw)

    def get_ack(self):
        """
        gets ack from the server
        """
        self.payload = struct.unpack(f"10s32sb" , self.payload_raw)
