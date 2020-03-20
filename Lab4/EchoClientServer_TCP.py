#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading
import json

########################################################################
# Echo-Server class
########################################################################

class Server:

    # HOSTNAME = socket.gethostname()
    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 1024
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

                elif (recvd_str[0] == "chat"):
                    for items in self.list_of_chatrooms:
                        if(recvd_str[1] == items[0]):
                            chat_addr = json.dumps(items[1:])
                            print("Chat request approved.\n")
                            break 
                    # Send the received bytes back to the client.
                    connection.sendall(chat_addr.encode("utf-8"))

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
    RECV_SIZE = 1024

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
                    print("Sending makeroom information\n")
                    makeroom_info = json.dumps(input_id) # to transform data into a series of bytes
                    self.connection_send(makeroom_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "name"):
                    print("User chat name sent\n")
                    username_info = json.dumps(input_id)
                    self.username = input_id[1]
                    self.connection_send(username_info)
                    self.connection_receive(input_id)
                elif(input_id[0] == "chat"):
                    print ("Chat request sent\n")
                    chat_info = json.dumps(input_id)
                    self.connection_send(chat_info)
                    self.connection_receive(input_id)

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
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)
            if (input_id[0] == "chat"):
                print("Received: ", recvd_bytes_decoded)

        except Exception as msg:
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






