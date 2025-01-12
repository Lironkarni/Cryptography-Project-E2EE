import struct

class ServerParser:
    def __init__(self, packet):
        """
        Initializes the ServerParser data with the given packet.
        Args:
            packet: the raw packet to parse
        """
        self.header = struct.unpack("10sHI", packet[:16])
        self.phone_number = self.header[0]
        self.code = self.header[1]
        self.payload_size = self.header[2]
        self.payload_raw = packet[16:self.payload_size+16]
        self.payload = None

    # used in sign in or for asking to create a connection to send message for another user
    def parse_phone_number_as_payload(self):
        """
        parsed the data from the client to the server for phone number data packets
        sets at the payload the packet with the phone number as payload using a struct

        """
        self.payload = struct.unpack("10s", self.payload_raw)

    def get_public_key_from_user(self):
        """
        parsed the data from the client to the server for public key and hmac data packets
        sets at the payload the packet with the public key and hmac as payload using a struct

        """
        self.payload = struct.unpack("294s32s", self.payload_raw) # public key and hmac

    # used for each boolean return of payload
    # for example if the user is online or if the user got the aes key
    def accept_or_reject_payload(self):
        """
        parsed the data from the client to the server for boolean data packets
        sets at the payload the packet with the boolean value as payload using a struct

        """
        self.payload = struct.unpack("10sB", self.payload_raw)

    def receive_aes_key(self):
        """
        parsed the data from the client to the server for aes key and signature data packets
        sets at the payload the packet with the aes key and signature as payload using a struct

        """
        self.payload = struct.unpack(f"10s{self.payload_size-266}s256s", self.payload_raw)

    def receive_message(self):
        """
        parsed the data from the client to the server for message data packets
        sets at the payload the packet with the message, iv, message size and hmac as payload using a struct

        """
        message_size = struct.unpack(f"10xxsI", self.payload_raw[:16])
        tpl = struct.unpack(f"10sxxI16s32s{message_size[1]}s", self.payload_raw)
        self.payload = {
            "phone_num": tpl[0], "message_size": tpl[1], "iv": tpl[2],
            "hmac": tpl[3], "enc_message": tpl[4]
        }

    def receive_ack(self):
        """
        parsed the data from the client to the server for ack data packets
        sets at the payload the packet with the ack and hmac as payload using a struct

        """
        self.payload = struct.unpack(f"10s32sb", self.payload_raw)
