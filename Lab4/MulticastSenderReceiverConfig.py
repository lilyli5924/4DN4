#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import struct
import json

########################################################################

# Read in the config.py file to set various addresses and ports.
from config import *

########################################################################
# Broadcast Server class
########################################################################

class Client:

    # HOSTNAME = socket.gethostbyname('')
    #HOSTNAME = 'localhost'
    HOSTNAME = "0.0.0.0"

    TIMEOUT = 2
    RECV_SIZE = 256
    
    MSG_ENCODING = "utf-8"
    # MESSAGE =  HOSTNAME + "multicast beacon: "
    MESSAGE = "Chat user connection established from " 
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')
    # OR: TTL_BYTE = struct.pack('B', TTL)

    def __init__(self):
        self.create_listen_socket()
        self.send_messages_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL)  # this works fine too
            # self.socket.bind(("192.168.2.37", 0))  # This line may be needed.
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
   
    def send_messages_forever(self):
        try:
            while True:
                self.get_console_input()
                input_id = self.input_text.split(" ")
                print(input_id)
                if (input_id[0] == "connect"):
                    print("Sending multicast packet (address, port): ", MULTICAST_ADDRESS_PORT)
                    connect_info = json.dumps(input_id)
                    self.socket.sendto(connect_info.encode("utf-8"), MULTICAST_ADDRESS_PORT)
                elif (input_id[0] == "makeroom"):
                    print("Sending makeroom information\n")
                    makeroom_info = json.dumps(input_id) # to transform data into a series of bytes
                    self.socket.sendto(makeroom_info.encode("utf-8"), MULTICAST_ADDRESS_PORT)
                elif(input_id[0] == "name"):
                    print("User chat name sent\n")
                    username_info = json.dumps(input_id)
                    self.username = input_id[1]
                    self.socket.sendto(username_info.encode("utf-8"), MULTICAST_ADDRESS_PORT)
                elif(input_id[0] == "chat"):
                    print ("Chat request sent\n")
                    chat_info = json.dumps(input_id)
                    self.socket.sendto(chat_info.encode("utf-8"), MULTICAST_ADDRESS_PORT)
                    self.connection_receive()
                time.sleep(Client.TIMEOUT)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes, address = self.socket.recvfrom(Client.RECV_SIZE)
            recvd_bytes_decoded = json.loads(recvd_bytes)
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print(recvd_bytes_decoded)
        
            while True:
                sendmsg = input("Message to send: \n")
                message = self.username + ": " + sendmsg
                print (message)
                #self.socket.sendto(message.encode("utf-8"), MULTICAST_ADDRESS_PORT)
        except Exception as msg:
            print(msg)
            sys.exit(1)
########################################################################
# Echo Server class
########################################################################

class Server:

    RECV_SIZE = 256

    def __init__(self):

        print("Bind address/port = ", BIND_ADDRESS_PORT)
        self.list_of_chatrooms = []
        self.get_socket()
        self.receive_forever()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.
            self.socket.bind(BIND_ADDRESS_PORT)
            print("Chat Room Directory Server listening on port ", MULTICAST_PORT)
            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)

            print("Multicast Group: ", MULTICAST_ADDRESS)

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", MULTICAST_ADDRESS,"/", RX_IFACE_ADDRESS)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address_port = self.socket.recvfrom(Server.RECV_SIZE)
                address, port = address_port
                data_decoded = json.loads(data)
                print(data_decoded)
                if(data_decoded[0] == "connect"):
                    print("Received: ", data_decoded, " Address:", address, " Port: ", port)
                elif(data_decoded[0] == "makeroom"):
                    print("Make Room:", data_decoded)
                    self.list_of_chatrooms.append(data_decoded[1:])
                    print(self.list_of_chatrooms)
                elif(data_decoded[0] == "name"):
                    print("Username added. Please specify chat room you want to enter.")
                elif(data_decoded[0] == "chat"):
                    for items in self.list_of_chatrooms:
                        if(data_decoded[1] == items[0]):
                            chat_addr = json.dumps(items[1:])
                            print("Chat request approved.\n")
                            break
                    self.socket.sendto(chat_addr.encode("utf-8"), address_port)
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'server': Server,'client': Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='client or server role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






