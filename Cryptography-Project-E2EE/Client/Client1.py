"""
made by : Eitan Kot - 215628223 and Liron Karni
"""
from MainClient import *

def main():
    HOST = '127.0.0.1' # the address of the server to call
    PORT = 1258
    client = Client("0534441234") # we create a client instance with the phone number 0534441234

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:# we create a socket object
            s.connect((HOST, PORT))
            if client.user_signed_in():
                client.relog(s)
            else:
                client.sign_in(s) # we sign in the client
            if client.aes_key is None:
                client.init_switch_key("0512221234", s) # we initialize the connection and send the public key to the server
            client.send_enc_message_to_server("0512221234", "hello gaming 123", s) # we send an encrypted message to the server

    except:
        raise "Error connecting to the server"


if "__main__" == __name__:
    print("start")
    main()

