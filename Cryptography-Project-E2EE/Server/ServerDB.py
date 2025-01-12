from datetime import datetime
from threading import Lock

class ServerDB:
    def __init__(self):
        """
        Initializes the ServerDB object
        with locks for thread safety.
        """
        self.client_public_key = {}
        self.unread_messages_per_user = {}
        self.request_create_session_per_user = {}
        self.client_pub_key_lock = Lock()
        self.create_session_lock = Lock()
        self.unread_messages_lock = Lock()

    def add_user(self, phone_number, otp, connection):
        """
        Adds a new user to the server database.
        Args:
            phone_number: phone number of the user
            otp: otp created
            connection: connection object
        """

        self.client_pub_key_lock.acquire()
        self.unread_messages_lock.acquire()
        self.create_session_lock.acquire()

        # initialize the user's public key and connection and the other dicts we use
        self.client_public_key[phone_number] = [[otp, datetime.now()], connection]
        self.unread_messages_per_user[phone_number] = []
        self.request_create_session_per_user[phone_number] = None
        print(f"list after adding: {self.client_public_key}")

        self.client_pub_key_lock.release()
        self.unread_messages_lock.release()
        self.create_session_lock.release()


    def check_user_exist(self,phone_number):
        """
        Check if the user exists in the server database.
        Args:
            phone_number: the phone number of the user

        Returns: True if the user exists, False otherwise
        """
        self.client_pub_key_lock.acquire()
        if phone_number in self.client_public_key:
            return_value = True
        else:
            return_value = False
        self.client_pub_key_lock.release()
        return return_value

    def set_public_key(self, phone_number, public_key):
        """
        Set the public key of the user in the server database.
        Args:
            phone_number: phone number of the user
            public_key: the public key of the user
        """
        self.client_pub_key_lock.acquire()

        self.client_public_key[phone_number][0] = public_key
        print(f"list after setting public key: {self.client_public_key}")

        self.client_pub_key_lock.release()

    def get_public_key(self, phone_number):
        """
        gets the public key of the user from the server database.
        Args:
            phone_number: the phone number of the user

        Returns: the public key of the user in bytes

        """
        self.client_pub_key_lock.acquire()
        public_key = self.client_public_key[phone_number][0]
        self.client_pub_key_lock.release()
        return public_key

    def get_user_connection(self, phone_number):
        """
        gets the connection object of the user from the server database.
        Args:
            phone_number: phone number of the user

        Returns: the connection object of the user

        """
        self.client_pub_key_lock.acquire()
        connection = self.client_public_key[phone_number][1]
        self.client_pub_key_lock.release()
        return connection

    def set_user_connection(self, phone_number, connection):
        """
        sets the connection of the users in the server database.
        Args:
            phone_number: phone number of the user
            connection: connection object
        """
        self.client_pub_key_lock.acquire()
        self.client_public_key[phone_number][1] = connection
        self.client_pub_key_lock.release()

    def add_message(self, phone_number, enc_message):
        """
        Adds a message to the user's unread messages list
        Args:
            phone_number: phone number of the target
            enc_message:  encrypted message
        """
        self.unread_messages_lock.acquire()
        if len(self.unread_messages_per_user[phone_number]) > 2 : # if the list is bigger than 2 we remove the oldest message
            self.unread_messages_per_user[phone_number][0] = self.unread_messages_per_user[phone_number][1]
            self.unread_messages_per_user[phone_number][1] = enc_message
        else:
            self.unread_messages_per_user[phone_number].append(enc_message)
        self.unread_messages_lock.release()

    def clear_messages(self, phone_number):
        """
        Clears the unread messages list of the user.
        Args:
            phone_number: phone number of the user
        """
        self.unread_messages_lock.acquire()
        self.unread_messages_per_user[phone_number] = []
        self.unread_messages_lock.release()

    def get_messages(self, phone_number):
        """
        gets all the unread messages of the user.
        Args:
            phone_number: the phone number of the user
        Returns: the dict of unread messages of the user
        """
        self.unread_messages_lock.acquire()
        messages_list = self.unread_messages_per_user[phone_number]
        self.unread_messages_lock.release()
        return messages_list

    def add_aes_key_packet(self,phone_number, genParser):
        """
        Adds the AES key packet to the server database.
        Args:
            phone_number: the target to add it into
            genParser: the AES packet
        """
        self.create_session_lock.acquire()
        self.request_create_session_per_user[phone_number] = genParser
        self.create_session_lock.release()

    def get_aes_key_packet(self,phone_number):
        """
        Gets the AES key packet from the server database and removes it from the database.
        Args:
            phone_number: the phone number of the target

        Returns: the data packet we want to send to the target
        """
        self.create_session_lock.acquire()
        genParser = self.request_create_session_per_user[phone_number]
        self.request_create_session_per_user[phone_number] = None
        self.create_session_lock.release()
        return genParser