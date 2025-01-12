"""
made by : Eitan Kot - 215628223 and Liron Karni
"""
from MainClient import *
import time

# we created here a second client that will connect to the server and receive data from the server
def main():
    HOST = '127.0.0.1'
    PORT = 1258
    client = Client("0512221234")  # we create a client instance with the phone number 0512221234

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            if client.user_signed_in():
                client.relog(s)
            else:
                client.sign_in(s)  # we sign in the client
            value = 0
            while value < 2:
                boolean=client.receive_data_from_server(s) # we wait to receive data from the server
                if boolean:
                    value += 1
                time.sleep(5)

    except:
        raise "Error connecting to the server"


if "__main__" == __name__:
    print("start")
    main()

