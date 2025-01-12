import struct

class ClientGenParser:
    def __init__(self, phone_num, code, payload_size):
        """
        the header of the generative message
        Args:
            phone_num: phone number of the user
            code: the code number
            payload_size: payload size
        """
        self.phone_num = phone_num
        self.code = code
        self.payload_size = payload_size
        self.payload = None

    # used in sign in or for asking to create a connection to send message for another user
    def parse_phone_number_as_payload(self, phone_num):
        """
        Client way to generate a packet with phone number as payload
        Args:
            phone_num: the phone number of the user
        Returns:
            the packet with the phone number as payload using a struct
        """
        return struct.pack("10sHI10s", self.phone_num, self.code, self.payload_size ,phone_num)

    def get_public_key_from_user(self, public_key, hmac):
        """
        Client way to generate a packet with public key and hmac as payload
        Args:
            public_key: public key of the user
            hmac: hmac of the public key
        Returns: the packet with the public key and hmac as payload using a struct

        """
        return struct.pack("10sHI294s32s", self.phone_num, self.code, self.payload_size ,public_key,hmac) # public key and hmac

    # used for each boolean return of payload
    # for example if the user is online or if the user got the aes key
    def accept_or_reject_payload(self, target_number,bool_val):
        """
        Client way to generate a packet with a boolean value as payload
        Args:
            target_number: the number of the other user
            bool_val: the boolean value to send
        Returns: the packet with the boolean value as payload using a struct
        """
        if bool_val:
            return struct.pack("10sHI10sB", self.phone_num, self.code, self.payload_size, target_number, 1)
        else:
            return struct.pack("10sHI10sB", self.phone_num, self.code, self.payload_size, target_number, 0)

    def receive_aes_key(self, target_number ,enc_aes_key, signature):
        """
        Client way to generate a packet with the aes key and signature as payload
        Args:
            target_number: the number of the other user
            enc_aes_key: encrypted aes key
            signature: signature of the aes key

        Returns: the packet with the aes key and signature as payload using a struct

        """
        return struct.pack(f"10sHI10s{self.payload_size-266}s256s", self.phone_num, self.code, self.payload_size, target_number,enc_aes_key ,signature)

    def gen_send_message(self, phone_num, message_size, iv, hmac, enc_message):
        """
        Client way to generate a packet with the message as payload
        Args:
            phone_num: phone number of the other client
            message_size: message size
            iv: iv of the aes key
            hmac: the hmac of the message
            enc_message: the encrypted message

        Returns: the packet with the message as payload using a struct
        """
        return struct.pack(f"10sHI10sxxI16s32s{message_size}s", self.phone_num, self.code, self.payload_size, phone_num, message_size, iv, hmac, enc_message)

    def send_ack(self, phone_num, hmac, ack):
        """
        Client way to generate a packet with the ack as payload
        Args:
            phone_num: phone number of the other client
            hmac: the ack hmac
            ack: ack value
        Returns: the packet with the ack as payload using a struct
        """
        if ack:
            return struct.pack(f"10sHI10s32sb", self.phone_num, self.code, self.payload_size, phone_num, hmac, 1)
        else:
            return struct.pack(f"10sHI10s32sb", self.phone_num, self.code, self.payload_size, phone_num, hmac, 0)

    def send_empty_packet(self):
        """
        send an empty packet
        Returns: an empty packet with only header without payload using a struct

        """
        return struct.pack(f"10sHI", self.phone_num, self.code, self.payload_size)