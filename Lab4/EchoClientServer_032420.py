#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading
import json
import time

########################################################################

# Read in the config.py file to set various addresses and ports.
from config import *

########################################################################
# Echo-Server class
########################################################################

class Server:

    # HOSTNAME = socket.gethostname()
    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 2048
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"
    
    def __init__(self):
        self.thread_list = []
        self.list_of_chatrooms = []
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Chat Room Directory Server Listening on port {}...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.socket.accept()

                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.connection_handler,
                                              args=(new_client,))
                print("Chat user connection established!")
                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)

        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed (The other end is probably in
                # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
                # server end of the connection and get the next client
                # connection.
                
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                # Decode the received bytes back into strings. Then output
                # them.
                # recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                recvd_str = json.loads(recvd_bytes)
                if (recvd_str[0] == "makeroom"):
                    print("Make Room:", recvd_str)
                    self.list_of_chatrooms.append(recvd_str[1:])
                    print(self.list_of_chatrooms)
                    connection.sendall(recvd_bytes)

                elif (recvd_str[0] == "name"):
                    print("Username added. Please specify chat room you want to enter.")
                    connection.sendall(recvd_bytes)

                elif (recvd_str[0] == "getdir"):
                    print("getdir request approved.")
                    chat_addr = [] 
                    for items in self.list_of_chatrooms:
                        #if(recvd_str[1] == items[0]):
                        chat_addr.append(items)
                        print(chat_addr)
                    # Send the received bytes back to the client.
                    serial_chat_addr = json.dumps(chat_addr)
                    connection.sendall(serial_chat_addr.encode("utf-8"))

                elif (recvd_str[0] == "deleteroom"):
                    for items in self.list_of_chatrooms:
                        if(items[0] == recvd_str[1]):
                            self.list_of_chatrooms.remove(items)
                    print(self.list_of_chatrooms)
                    connection.sendall(recvd_bytes)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

########################################################################
# Echo-Client class
########################################################################

class Client:

    # SERVER_HOSTNAME = socket.gethostname()
    SERVER_HOSTNAME = "0.0.0.0"
    RECV_SIZE = 2048
    
    # MultiCast Parameters
    TIMEOUT = 2
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.get_socket()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            print("Setting up connection with CDRS...")
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input("Input: ")
            if self.input_text != '':
                break
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                input_id = self.input_text.split(" ")

                if (input_id[0] == "connect"):
                    self.connect_to_server()

                elif (input_id[0] == "makeroom"):
                    print("Sending makeroom information")
                    makeroom_info = json.dumps(input_id) # to transform data into a series of bytes
                    self.connection_send(makeroom_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "name"):
                    print("User chat name sent")
                    username_info = json.dumps(input_id)
                    self.username = input_id[1]
                    self.connection_send(username_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "getdir"):
                    getdir_info = json.dumps(input_id)
                    self.connection_send(getdir_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "bye"):
                    print("Client TCP connection closed...")
                    self.socket.close()
                elif(input_id[0] == "deleteroom"):
                    print("Sending deleteroom room information...")
                    del_info = json.dumps(input_id)
                    self.connection_send(del_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "chat"):
                    # print ("Chat request sent\n")
                    # chat_info = json.dumps(input_id)
                    # self.connection_send(chat_info)
                    # self.connection_receive(input_id)
                    pass

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self, input_text):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(input_text.encode(Server.MSG_ENCODING))
            # print("Sent: ", self.input_text)
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def connection_receive(self, input_id):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)
            recvd_bytes_decoded = json.loads(recvd_bytes)

            if len(recvd_bytes) == 0:
                print("Closing client connection ... ")
                self.socket.close()
                sys.exit(1)

            if (input_id[0] == "getdir"):
                print("Received: ", recvd_bytes_decoded)
                
        except Exception as msg:
            print("Hi I break here")
            print(msg)
            sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






