#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading
import json
import time
import os

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
                flag = False
                recvd_str = json.loads(recvd_bytes)
                if (recvd_str[0] == "makeroom"):
                    print("Make Room:", recvd_str)
                    for items in self.list_of_chatrooms:
                        if(items[0] == recvd_str[1]):
                            flag = True
                        else:
                            pass
                    if (flag == False):
                        self.list_of_chatrooms.append(recvd_str[1:])
                        print(self.list_of_chatrooms)
                        msg = "New room is created"
                    else:
                        msg = "Duplicated room name is sent"
                    
                    feedback = json.dumps(msg)
                    connection.sendall(feedback.encode("utf-8"))
                elif (recvd_str[0] == "getdir"):
                    print("getdir request approved.")
                    chat_addr = [] 
                    for items in self.list_of_chatrooms:
                        chat_addr.append(items)
                    # Send the received bytes back to the client.
                    serial_chat_addr = json.dumps(chat_addr)
                    connection.sendall(serial_chat_addr.encode("utf-8"))
                elif (recvd_str[0] == "deleteroom"):
                    for items in self.list_of_chatrooms:
                        if(items[0] == recvd_str[1]):
                            self.list_of_chatrooms.remove(items)
                    print(self.list_of_chatrooms)
                    connection.sendall(recvd_bytes)
                else:
                    pass
                    
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
    TIMEOUT = 1
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.flag_start = True
        self.thread_list_c = []
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
    
    def create_udp_send_socket(self, address_bport):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL)  # this works fine too
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def create_udp_recv_socket(self, address_bport):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.
            bind_address = (Client.SERVER_HOSTNAME, address_bport[1])
            self.udp_socket.bind(bind_address)
            print("Chat Room Directory Server listening on port ", address_bport[1])
            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(address_bport[0])

            print("Multicast Group: ", address_bport[0])

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", address_bport[0],"/", RX_IFACE_ADDRESS)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def udp_handler(self, address_bport):
        self.udp_send(address_bport)
        udp_thread = threading.Thread(target=self.udp_handler,
                                args=(address_bport,))
        #Start the new thread running.
        udp_thread.start()
        self.udp_recv()
    
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
                    print("User chat name is set")
                    self.username = input_id[1]

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
                    for item in self.chatroom_list:
                        if (input_id[1] == item[0]):
                            address_bport = (str(item[1]), int(item[2]))
                    print(address_bport)
                    self.flag_start = True
                    # self.create_udp_send_socket(address_bport)
                    if (self.flag_start):
                        self.create_udp_recv_socket(address_bport)
                    #else:
                    #self.flag_start = True
                        msg = self.username + " has joined the chat."
                        self.udp_socket.sendto(msg.encode("utf-8"), address_bport)
                        udp_thread = threading.Thread(target=self.udp_handler,
                                                args=(address_bport,))
                    # Start the new thread running.
                        udp_thread.start()
                        self.udp_recv()

                else: 
                    pass
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit()

    def udp_send(self, address_bport):
        try:
            # sendmsg = input(self.username + ": ")
            sendmsg = input('')
            sendmsg_encode = sendmsg.encode('ASCII')
            if (sendmsg_encode == b'\x1d'):
                self.flag_start = False
                self.get_socket()
                self.connect_to_server()
                self.send_console_input_forever()
                self.udp_socket.close()
            else:
                message = self.username + ":" + sendmsg
                self.udp_socket.sendto(message.encode("utf-8"), address_bport)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
            print("Closing server connection ...")
            self.udp_socket.close()
            sys.exit()       

    def udp_recv(self):
        while (self.flag_start):
            try:
                # Receive and print out text. The received bytes objects
                # must be decoded into string objects.
                recvd_bytes, address = self.udp_socket.recvfrom(Client.RECV_SIZE)
                recvd_bytes_decoded = recvd_bytes.decode("utf-8")
                # recv will block if nothing is available. If we receive
                # zero bytes, the connection has been closed from the
                # other end. In that case, close the connection on this
                # end and exit.
                if len(recvd_bytes) == 0:
                    print("Closing server connection ... ")
                    self.udp_socket.close()
                    sys.exit(1)
                #if(recvd_bytes_decoded == "/exit"):
                #    self.flag_start = False
                #    self.get_socket()
                #    self.connect_to_server()
                #    self.send_console_input_forever()
                #    self.udp_socket.close()
                #else:
                if(self.flag_start):
                    print(recvd_bytes_decoded)    
                
            except Exception as msg:
                print(msg)
            except KeyboardInterrupt:
                print(); exit()
                
    def connection_send(self, input_text):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def connection_receive(self, input_id):
        self.chatroom_list = []
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
                print("List of rooms: ", recvd_bytes_decoded)
                self.chatroom_list = recvd_bytes_decoded
            elif (input_id[0] == "makeroom"):
                if (recvd_bytes_decoded == "Duplicated room name is sent"):
                    print("This room is already created, please create a different room")
            else:
                pass
                
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






