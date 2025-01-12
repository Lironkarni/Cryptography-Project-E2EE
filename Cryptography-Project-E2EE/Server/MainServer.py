import socket
import threading
import secrets
from datetime import datetime, timedelta
from Server.ServerDB import ServerDB
from ServerParser import ServerParser
from ServerGenParser import ServerGenParser
from Utilities.HmacHelper import HmacHelper
from Utilities.RSAHelper import RSAHelper

import traceback


# secured channel for OTP
def send_by_secure_channel(otp,conn):
    """
    Send OTP by secure channel - allowed by the requests
    Args:
        otp: otp to send
        conn: connection of the socket
    """
    try:
        conn.sendall(otp)
        print(f"[Server] OTP sent: {otp}")
    except Exception as e:
        print(f"[Server] Error sending OTP: {e}")

def send_message(package,conn):
    """
    Send message to the client
    Args:
        package: the package to send
        conn: connection of the socket
    """
    try:
        conn.sendall(package)
        print(f"[Server] Package sent: {package}")
    except Exception as e:
        print(f"[Server] Error sending Package: {e}")

def phone_number_not_registered(conn):
    """
    Sends error if phone number not registered
    Args:
        conn: connection of the socket

    """
    server_gen_parser = ServerGenParser(999,0)
    send_message(server_gen_parser.empty_payload(),conn)

# create six digits code
def generate_otp():
    """
    Generate 6 digits OTP
    Returns: the otp number
    """
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    return otp

def server_handler(data, connection, server_database):
    """
    Handle the server requests
    Args:
        data: the data packet without parsing at all
        connection: the connection of the socket
        server_database: the server database

    """
    parsed_data = ServerParser(data)
    print(f"[Server] Parsed data phone-number: {parsed_data.phone_number}\ncode: {parsed_data.code}\n payload_size: {parsed_data.payload_size}")
    phone_number = parsed_data.phone_number.decode("ascii")
    # stage one registration
    if parsed_data.code == 100: # registration request to send an OTP
        parsed_data.parse_phone_number_as_payload()
        phone_number = parsed_data.payload[0].decode("ascii")
        otp = generate_otp()
        print(f"[Server] OTP received: {otp}")
        if server_database.check_user_exist(phone_number): # if user already exist
            server_database.set_user_connection(phone_number, connection)
            genParser = ServerGenParser(900, 6)  # send OTP
        else: # create new user
            server_database.add_user(phone_number, otp, connection)
            genParser = ServerGenParser(1000, 6) # send OTP
        send_by_secure_channel(genParser.otp_payload(otp), connection)

    elif parsed_data.code == 101: # get public key from client
        if server_database.check_user_exist(phone_number):
            parsed_data.get_public_key_from_user()
            public_key = parsed_data.payload[0]
            hmac = parsed_data.payload[1]
            otp = server_database.get_public_key(phone_number)[0].encode("ascii") # calculate the hmac of the otp and salt to be sure
            salt = HmacHelper.generate_hmac(parsed_data.phone_number,otp)
            k_temp = HmacHelper.derive_key(otp,salt)
            if datetime.now() - server_database.get_public_key(phone_number)[1] > timedelta(minutes=5): # check if the otp is expired
                valid_hmac = False
                print("[Server] OTP expired")
            else:
                if HmacHelper.verify_hmac(hmac,public_key,k_temp): # verify the hmac
                    valid_hmac = True
                    server_database.set_public_key(phone_number,public_key) # sets the public key
                    print(f"[Server] HMAC verified")
                else:
                    valid_hmac = False

            genParser = ServerGenParser(1001, 1)# sends the accept or reject
            send_message(genParser.accept_or_reject_payload(valid_hmac), connection)
        else:
            phone_number_not_registered(connection)
    elif parsed_data.code == 110: # switch keys initation
        if server_database.check_user_exist(phone_number): # check if the user exist
            parsed_data.parse_phone_number_as_payload()
            if server_database.check_user_exist(parsed_data.payload[0].decode("ascii")): # check if the target user exist
                public_key = server_database.get_public_key(parsed_data.payload[0].decode("ascii"))
                # gets the public key of the target user and signs it with the server private key
                rsa_h = RSAHelper("server")
                rsa_h.save_server_keys()
                signature = rsa_h.sign_message(public_key)
                genParser = ServerGenParser(1012, 550)
                send_message(genParser.get_rsa_public_key(public_key, signature), connection) # sends the public key of the target user to the client
                print("[Server] Public Key Sent to Original Client")
            else:
                genParser = ServerGenParser(1011, 10) # error if the target user does not exist
                send_message(genParser.phone_payload(parsed_data.payload), connection)

        else: # user does not exist
            phone_number_not_registered(connection)
    # stage two switch keys
    elif parsed_data.code == 112: # switch keys client sends encrypted aes key to server for the target user
        parsed_data.receive_aes_key() # parse the aes key
        target_number = parsed_data.payload[0].decode("ascii")
        if server_database.check_user_exist(target_number) and server_database.check_user_exist(phone_number):
            enc_aes_key = parsed_data.payload[1]
            signature = parsed_data.payload[2] # signature of the aes key
            sender_public_key = server_database.get_public_key(phone_number)
            rsa_h = RSAHelper("server")
            rsa_h.save_server_keys()
            signature_pub_key = rsa_h.sign_message( sender_public_key) # signs the aes key with the server private key
            # sends the data to the target
            genParser = ServerGenParser(1013, 816+len(enc_aes_key))
            server_database.add_aes_key_packet(target_number, genParser.get_enc_aes_key(phone_number.encode("ascii"), enc_aes_key,
                                          len(enc_aes_key), signature, sender_public_key,signature_pub_key))
        else:
            phone_number_not_registered(connection)
            return

    elif parsed_data.code == 113: # received ack from the target user for the aes key
        parsed_data.accept_or_reject_payload()
        target_number = parsed_data.payload[0].decode("ascii")
        if server_database.check_user_exist(target_number): # checks if the target exist
            target_connection = server_database.get_user_connection(target_number)
        else:
            phone_number_not_registered(connection)
            return

        genParser = ServerGenParser(1014, 1)
        if parsed_data.payload[1] == b'1': # sends ack to the target
            send_message(genParser.accept_or_reject_payload(True), target_connection)
        else:
            send_message(genParser.accept_or_reject_payload(False), target_connection)
    elif parsed_data.code == 120: # received message from the client
        parsed_data.receive_message()
        target_number = parsed_data.payload['phone_num'].decode("ascii")

        if server_database.check_user_exist(target_number): # checks if the target exist
            server_database.add_message(target_number, parsed_data) # add the message to the database
        else:
            phone_number_not_registered(connection)
            return

    elif parsed_data.code == 121: # received ack from the client
        parsed_data.receive_ack()
        target_number = parsed_data.payload[0].decode("ascii")
        if server_database.check_user_exist(target_number): # checks if user exist
            target_connection = server_database.get_user_connection(target_number)
        else:
            phone_number_not_registered(connection)
            return

        hmac = parsed_data.payload[1]
        ack=parsed_data.payload[2]
        genParser = ServerGenParser(1021, 43) # sends ack to the target
        send_message(genParser.send_ack(ack ,phone_number, hmac), target_connection)
        print(f"[Server] Acknowledge sent to client[{target_number}]")
    elif parsed_data.code == 130: # request for data from server(messages or aes key)
        if server_database.check_user_exist(phone_number): #
            messages = server_database.get_messages(phone_number)
            server_database.clear_messages(phone_number)
            print(messages)
            if len(messages) == 2: # if there are two messages
                message_info1 = messages[0].payload
                message_info2 = messages[1].payload
                # send the messages to the client
                genParser = ServerGenParser(1020, 100+message_info1['message_size']+message_info2['message_size'])
                send_message(genParser.get_encrypted_message(
                    message_info1['enc_message'], message_info1['message_size'],
                    message_info2['enc_message'], message_info2['message_size'],
                    messages[0].phone_number, message_info1['iv'], message_info1['hmac'],
                    message_info2['hmac']), connection)


            elif len(messages) == 1: # if there is only one message
                message_info1 = messages[0].payload
                # send the message to the client
                genParser = ServerGenParser(1020, 68 + message_info1['message_size'])
                send_message(
                    genParser.get_encrypted_message(message_info1['enc_message'], message_info1['message_size'],
                                                    b'', 0,
                                                    messages[0].phone_number, message_info1['iv'],
                                                    message_info1['hmac'], b''), connection)

            else:
                # if there are no messages to send
                key_packet =server_database.get_aes_key_packet(phone_number)
                if key_packet is None: # if there is no aes key to send
                    genParser = ServerGenParser(1022,0)
                    send_message(genParser.empty_payload(), connection)
                else: # if there is an aes key to send
                    send_message(key_packet, connection)

def handle_client(conn, addr, server_database):
    """
    Handle the connection with threads for multiple clients
    Args:
        conn: the connection of the socket
        addr: the address of the client
        server_database: the server database
    """
    print(f"Handling client {addr}")
    try:
        while True:
            data = conn.recv(4096) # tries to get data from the client
            if not data:  # if client disconnects
                print("emtpy packet")
                break
            print(f"Received from {addr}: {data}")

            server_handler(data, conn, server_database)
    except Exception as e: # if there is an error
        print(f"Error with client {addr}: {e}")
        traceback.print_exc()
    finally: # connection closed
        conn.close()
        print(f"Connection with {addr} closed.")

def main():
    HOST = '127.0.0.1'
    PORT = 1258

    # create the server RSA keys
    rsa_helper = RSAHelper("server")
    rsa_helper.save_server_keys()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen() # listen to the port
        print('Server is running...')

        server_database = ServerDB() # create the server database
        threads = []  # To keep track of all threads

        try:
            while True:  # Accept multiple connections
                conn, addr = s.accept() # waits for a connection
                print('Connected by', addr)

                # create a thread for each client when request happens
                thread = threading.Thread(target=handle_client, args=(conn, addr, server_database))
                thread.start()
                threads.append(thread)

                threads = [t for t in threads if t.is_alive()] # remove dead threads
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            for thread in threads: # remove all threads that they are dead
                thread.join()
            print("Server stopped.")


if __name__ == '__main__':
    main()

