
import socket

from  ClientParser import ClientParser
from  ClientGenParser import ClientGenParser
from Utilities.RSAHelper import RSAHelper
from Utilities.HmacHelper import HmacHelper
from Utilities.AESHelper import AESHelper


class Client:
    """
    this class create an instance of client and allows the client to sign
    in and send messages to other clients by using the server
    """
    def __init__(self, phone_number):
        """
        this function initializes the client object
        Args:
            phone_number: the phone number we want to register with
        """
        self.aes_key = None
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.phone_number = phone_number


    def read_rsa_keys(self):
        """
        this function reads the rsa keys from the file if they exist
        """
        rsa_helper = RSAHelper(self.phone_number)
        rsa_helper.load_keys_from_file()

    def read_aes_key(self):
        """
        this function reads the aes key from the file
        """
        aes_helper = AESHelper()
        aes_helper.load_aes_key(self.phone_number)
        self.aes_key = aes_helper.key

    def send_message(self, message, s):
        """
        this function sends message to the server
        Args:
            message: the message we want to send
            s: the socket object we want to send the
        """
        try:
            s.sendall(message)
        except socket.error as e:
            print("Error sending message to the server")


    def user_signed_in(self):
        """
        this function checks if the user has signed in or not
        Returns: True if the user has signed in, False otherwise
        """
        try:
            self.read_rsa_keys()
            try:
                self.read_aes_key()
            except FileNotFoundError:
                pass
            return True
        except FileNotFoundError:
            return False

    def relog(self, s):
        """
        this function relog into the account in the user to the server
        Args:
            s: the socket connection to the server
        """
        print("entered relog")
        phone_encoded = self.phone_number.encode('ascii')  # encode the phone number
        gen_parser = ClientGenParser(b'0000000000', 100, 10)
        self.send_message(gen_parser.parse_phone_number_as_payload(phone_encoded),s)  # send the phone number to the server to sign in
        msg = s.recv(4096)
        parsed_data = ClientParser(msg)
        if parsed_data.code == 900:
            print("Connection has been established - user has been registered before")
        else:
            raise "User has not been registered before - please register first"

    def sign_in(self, s):
        """
        this function signs in the user to the server
        Args:
            s: the socket connection to the server
        """
        print("entered sign in")
        phone_encoded = self.phone_number.encode('ascii') # encode the phone number
        gen_parser = ClientGenParser(b'0000000000', 100, 10)
        self.send_message(gen_parser.parse_phone_number_as_payload(phone_encoded), s) # send the phone number to the server to sign in
        msg = s.recv(4096) # wait to receive the otp from the server
        # parse the message:
        parsed_data = ClientParser(msg)
        parsed_data.otp_payload()
        otp = parsed_data.payload[0] # gets the otp from the payload
        rsa_helper = RSAHelper(self.phone_number) # generate rsa keys
        rsa_helper.save_keys_to_file()
        self.rsa_public_key = rsa_helper.public_key
        self.rsa_private_key = rsa_helper.private_key # saves the keys
        salt = HmacHelper.generate_hmac(self.phone_number.encode('ascii'), otp) # generate the salt
        k_temp = HmacHelper.derive_key(otp, salt)
        signature = HmacHelper.generate_hmac(self.rsa_public_key, k_temp)  # generate the signature(hmac)
        gen_parser = ClientGenParser(phone_encoded, 101, 326)
        self.send_message(gen_parser.get_public_key_from_user(self.rsa_public_key, signature), s) # sends the public to the server

        msg = s.recv(4096) # wait to receive the response from the server
        parsed_data = ClientParser(msg)
        if parsed_data.code == 1001: # if the response is 1001 then the sign in was successful
            parsed_data.accept_or_reject_payload()
            if parsed_data.payload[0] == 1: # if the payload is 1 then the sign in was successful
                print("signed in successfully")
            else:  # if the payload is not 1 then the sign in was not successful
                print("sign in has been failed")
        else: # if the response is not 1001 then the sign in was not successful
            print("error")



    def init_switch_key(self,target , s ):
        """
        this function initializes the switch keys between the clients who want to communicate with each other
        Args:
            target: the target phone number
            s: socket connection to the server

        Returns: True if the switch keys was successful, False otherwise

        """
        phone_encoded = self.phone_number.encode('ascii')
        target_encoded = target.encode('ascii')
        gen_parser = ClientGenParser(phone_encoded, 110, 10)
        # send the target phone number to the server to check if it exists
        self.send_message(gen_parser.parse_phone_number_as_payload(target_encoded), s)
        message = s.recv(4096)
        parsed_data = ClientParser(message)
        if parsed_data.code == 1012: # the phone number exists and can communicate
            parsed_data.get_rsa_public_key() # opens the payload to get the public key
            targets_public_key = parsed_data.payload[0] # get the public key
            signature = parsed_data.payload[1] # get the signature
            # verify the signature
            if RSAHelper.verify_signature(targets_public_key, signature, RSAHelper.get_server_public_key()):
                aes_helper = AESHelper() # creates an AES key
                self.aes_key = aes_helper.return_key()
                aes_helper.save_aes_key(self.phone_number) # saves the key to the file
                # encrypt the AES key with the target public key
                target_rsa_helper = RSAHelper(target)
                enc_key = target_rsa_helper.encrypt_with_public_key(targets_public_key, self.aes_key)
                # create a signature for the encrypted key
                rsa_helper = RSAHelper(self.phone_number)
                rsa_helper.set_keys(self.rsa_public_key, self.rsa_private_key)
                signature = rsa_helper.sign_message(enc_key)

                # creates the payload to send to the server with encrypted aes key and signature
                payload_size = len(enc_key) + 266
                gen_parser = ClientGenParser(phone_encoded, 112, payload_size)
                self.send_message(gen_parser.receive_aes_key(target_encoded,enc_key,signature), s)
                message = s.recv(4096) # waits to receive the response from the server and approve the switch keys
                parsed_data = ClientParser(message)
                if parsed_data.code == 1014: # if the response is 1014 then the switch keys was successful
                    print("exchange keys went successfully")
                    return True
                else: # if the response is not 1014 then the switch keys was not successful
                    print("exchange keys has been failed")
                    return False
        else: # if the phone number does not exist
            return False


    def receive_switch_keys(self,parsed_data, s):
        """
        this function receives the switch keys from the other client and verifies the keys
        Args:
            parsed_data: the data after first parsing(without payload parsed)
            s: the socket connection to the server
        """
        parsed_data.get_enc_aes_key() # opens the payload to get data we need
        phone_encoded = self.phone_number.encode('ascii')
        target_number = parsed_data.payload[0].decode("ascii")
        enc_aes_key = parsed_data.payload[1]
        aes_signature = parsed_data.payload[2]
        target_public_key = parsed_data.payload[3]
        public_key_signature = parsed_data.payload[4]

        # verify the signature of the server public key
        if RSAHelper.verify_signature(target_public_key, public_key_signature, RSAHelper.get_server_public_key()):

            rsa_target_pub_key = RSAHelper.get_rsa_public_key_instance_from_bytes(target_public_key)
            # verify the signature of the aes key for the sender client
            if RSAHelper.verify_signature(enc_aes_key, aes_signature, rsa_target_pub_key):
                rsa_helper = RSAHelper(self.phone_number) # creates an RSA key
                rsa_helper.set_keys(self.rsa_public_key, self.rsa_private_key)
                key = rsa_helper.decrypt_with_private_key(self.phone_number, enc_aes_key) # decrypt the aes key with the private key of the client
                self.aes_key = key # saves the key
                aes_helper = AESHelper() # creates an AES key
                aes_helper.set_key(self.aes_key)
                aes_helper.save_aes_key(self.phone_number) # saves the key to the file
                # creates a payload to send to the server to send ack for other client to approve the switch keys
                gen_parser = ClientGenParser(phone_encoded, 113, 11)
                self.send_message(gen_parser.accept_or_reject_payload(target_number.encode('ascii'), True), s)
        else:
            # data rejected:
            gen_parser = ClientGenParser(phone_encoded, 113, 11)
            self.send_message(gen_parser.accept_or_reject_payload(target_number.encode('ascii') ,False), s)


    def send_enc_message_to_server(self, target_number, message, s ):
        """
        this function sends an encrypted message to the server for the target client
        Args:
            target_number: the target phone number
            message: the message we want to send
            s: socket connection to the server
        """
        phone_encoded = self.phone_number.encode('ascii')
        aes_helper = AESHelper() # creates an AES key - by the data in the client
        aes_helper.set_key(self.aes_key)
        # Encrypt the message
        enc_msg = aes_helper.encrypt(message.encode('ascii'))
        signature = HmacHelper.generate_hmac(self.aes_key , message.encode('ascii'))
        iv = aes_helper.iv
        #send encrypt message and signature to other user
        payload_size = len(enc_msg) + 64
        # sends the encrypted message to the server
        gen_parser = ClientGenParser(phone_encoded, 120, payload_size)
        self.send_message(gen_parser.gen_send_message(target_number.encode('ascii'), len(enc_msg), iv, signature ,enc_msg ), s)
        print(f"waiting for data!")
        data = s.recv(4096) # waits for the second user to receive the data.
        parsed_data = ClientParser(data)
        if parsed_data.code == 1021: # if the response is 1021 then the message was received successfully
            parsed_data.get_ack() # opens the payload to get the data we need
            ack_received_number = parsed_data.payload[0]
            received_hmac = parsed_data.payload[1]
            ack = parsed_data.payload[2]
            if ack == 1: # if the ack is 1 then the message was received successfully
                if HmacHelper.verify_hmac(received_hmac, self.aes_key, b'1'): # verify the hmac
                    print(f"[Client] the message has been received successfully from number [{ack_received_number}]")
                else: # if the hmac is not verified as expected
                    print(f"verification failed the hmac is not verified as expected!")
                    return
            else: # if the ack is not 1 then the message was not received successfully
                print(f"en error occurred from sending message to number [{ack_received_number}]")
                return
        else: # if the response is not 1021 then an error occurred
            print("en error occurred please take note!")
            return

    def message_request_from_server(self, parsed_data, s):
        """
        this function received parsed data from the function receive_data_from_server and decrypts the message
        Args:
            parsed_data: the parsed data to get the messages from
            s: the socket connection to the server
        """
        print("starting to get a message")
        parsed_data.get_encrypted_message() # parses the payload to get the data we need
        target_number = parsed_data.payload[0].decode("ascii")
        message_size1 = parsed_data.payload[1]
        message_size2 = parsed_data.payload[2]
        iv = parsed_data.payload[3]
        received_hmac1 = parsed_data.payload[4]
        enc_msg1 = parsed_data.payload[5]

        messages = [[message_size1, received_hmac1, enc_msg1]] # the messages data we ran on
        if message_size2 > 0: # check if we have more then 1 message
            received_hmac2 = parsed_data.payload[6]
            enc_msg2 = parsed_data.payload[7]
            messages.append([message_size2, received_hmac2, enc_msg2])

        # ---------------------------- #
        for message in messages: # moves on all the unread messages
            # parses the list we made before
            message_size = messages[0]
            received_hmac = message[1]
            enc_msg = message[2]

            aes_helper = AESHelper() # creates an AES key with the selected key and IV
            aes_helper.set_key(self.aes_key)
            aes_helper.set_iv(iv)
            msg = aes_helper.decrypt(enc_msg) # decrypts the message
            print(f"[Client] message received from [{target_number}] - {msg.decode('ascii')}")
            if HmacHelper.verify_hmac(received_hmac, self.aes_key, msg): # verifies the hmac
                signature = HmacHelper.generate_hmac(self.aes_key, b"1") # if the hmac is verified then we notify the server
                gen_parser = ClientGenParser(self.phone_number.encode('ascii'), 121, 43)
                self.send_message(gen_parser.send_ack(target_number.encode('ascii'), signature, True), s)
            else:
                signature = HmacHelper.generate_hmac(self.aes_key, b"0") # if the hmac is not verified then we notify the server
                gen_parser = ClientGenParser(self.phone_number.encode('ascii'), 121, 43)
                self.send_message(gen_parser.send_ack(target_number.encode('ascii'), signature, False), s)

    def receive_data_from_server(self, s):
        """
        this function request to receive data from the server
        Args:
            s: the socket connection to the server

        Returns: True if the data was received successfully, False otherwise
        """
        # create a request to receive data from the server
        gen_parser = ClientGenParser(self.phone_number.encode("ascii"), 130, 0)
        self.send_message(gen_parser.send_empty_packet(), s)
        data = s.recv(4096) # waits to receive the data from the server
        parsed_data = ClientParser(data)
        if parsed_data.code == 1013: # if the response is 1013 then the data is request to switch keys
            self.receive_switch_keys(parsed_data, s)
            return True
        elif parsed_data.code == 1020 and self.aes_key is not None: # if the response is 1020 then the data is a message to decrypt
            self.message_request_from_server(parsed_data, s)
            return True
        else: # we did not get any messages from the server
            return False
