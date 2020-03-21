#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading
import json
import time
try:
    import thread 
except ImportError:
    import _thread as thread

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
    RECV_SIZE = 2048
    
    # MultiCast Parameters
    TIMEOUT = 1
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.udp_thread_list = []
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

    def create_recv_socket(self, b_addr, b_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        #self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
        #self.socket.setblocking(False)
        # Bind to an address/port. In multicast, this is viewed as
        # a "filter" that determines what packets make it to the
        # UDP app.
        address_bport = (b_addr,b_port)
        self.socket.bind(address_bport)
        ############################################################
        # The multicast_request must contain a bytes object
        # consisting of 8 bytes. The first 4 bytes are the
        # multicast group address. The second 4 bytes are the
        # interface address to be used. An all zeros I/F address
        # means all network interfaces.
        ###########################################################
        multicast_group_bytes = socket.inet_aton(b_addr)
        # print("Multicast Group: ", address_bport[0])
        # Set up the interface to be used.
        multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
        # Form the multicast request.
        multicast_request = multicast_group_bytes + multicast_if_bytes
        # You can use struct.pack to create the request, but it is more complicated, e.g.,
        # 'struct.pack("<4sl", multicast_group_bytes,
        # int.from_bytes(multicast_if_bytes, byteorder='little'))'
        # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)
        # Issue the Multicast IP Add Membership request.
        # print("Adding membership (address/interface): ", address_bport[0],"/", RX_IFACE_ADDRESS)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        #send_new_thread = threading.Thread(target=self.send_udp_messages_forever, args=(b_addr, b_port))
        recv_new_thread = threading.Thread(target=self.receive_udp_forever, args=(b_addr, b_port))
        
        #send_new_thread.daemon = True
        recv_new_thread.daemon = True

        #send_new_thread.start()
        recv_new_thread.start()

        recv_new_thread.join()
        #send_new_thread.join()

    def receive_udp_forever(self, b_addr, b_port):
        #address_bport = (b_addr,b_port)
        # self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # #self.socket.setblocking(False)
        # # Bind to an address/port. In multicast, this is viewed as
        # # a "filter" that determines what packets make it to the
        # # UDP app.
        
        # self.socket.bind(address_bport)
        # ############################################################
        # # The multicast_request must contain a bytes object
        # # consisting of 8 bytes. The first 4 bytes are the
        # # multicast group address. The second 4 bytes are the
        # # interface address to be used. An all zeros I/F address
        # # means all network interfaces.
        # ###########################################################
        # multicast_group_bytes = socket.inet_aton(b_addr)
        # # print("Multicast Group: ", address_bport[0])
        # # Set up the interface to be used.
        # multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)
        # # Form the multicast request.
        # multicast_request = multicast_group_bytes + multicast_if_bytes
        # # You can use struct.pack to create the request, but it is more complicated, e.g.,
        # # 'struct.pack("<4sl", multicast_group_bytes,
        # # int.from_bytes(multicast_if_bytes, byteorder='little'))'
        # # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)
        # # Issue the Multicast IP Add Membership request.
        # # print("Adding membership (address/interface): ", address_bport[0],"/", RX_IFACE_ADDRESS)
        # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        
        while True:
            try:
                data, address_port = self.socket.recvfrom(Client.RECV_SIZE)
                #address, port = address_port
                print(data.decode('utf-8'))
                #time.sleep(Client.TIMEOUT)
                #self.create_send_socket(b_addr,b_port)
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print("Recv exception!!!")
                print(msg)
                sys.exit(1)
    
    def create_send_socket(self, b_addr, b_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
        
        send_new_thread = threading.Thread(target=self.send_udp_messages_forever, args=(b_addr, b_port))

        send_new_thread.daemon = True
        send_new_thread.start()
        send_new_thread.join()


    def send_udp_messages_forever(self,b_addr,b_port):

        address_bport =  (b_addr,b_port)
        print(address_bport)
        #self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
        #time.sleep(Client.TIMEOUT)
        try:
            while True:
                sendmsg = input("Message to send: ")
                message = self.username + ": " + sendmsg
                print(message)
                self.socket.sendto(message.encode("utf-8"), address_bport)
                #self.create_recv_socket(b_addr,b_port)
                #time.sleep(Client.TIMEOUT)
        except Exception as msg:
            print(msg)
            print("dsjfkdlsfjsk")
        except KeyboardInterrupt:
            print()
        finally:
            print("Breaking here")
            self.socket.close()
            sys.exit(1)
    
    def connection_receive(self, input_id):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)
            recvd_bytes_decoded = json.loads(recvd_bytes)
            #BIND_MULTICAST = (int(recvd_bytes_decoded[0]), int(recvd_bytes_decoded[1]))
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing client connection ... ")
                self.socket.close()
                sys.exit(1)

            if (input_id[0] == "chat"):
                print("Received: ", recvd_bytes_decoded)
                # self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
                #address_bport = (str(recvd_bytes_decoded[0]), int(recvd_bytes_decoded[1]))
                b_addr = str(recvd_bytes_decoded[0])
                b_port = int(recvd_bytes_decoded[1])
                self.create_send_socket(b_addr,b_port)
                self.create_recv_socket(b_addr,b_port)
                #thread.start_new_thread(self.send_udp_messages_forever, (b_addr, b_port))
                #thread.start_new_thread(self.receive_udp_forever, (b_addr, b_port))
                #send_new_thread = threading.Thread(target=self.send_udp_messages_forever,
                #                                args=(b_addr, b_port))
                #recv_new_thread = threading.Thread(target=self.receive_udp_forever,
                #                                args=(b_addr, b_port))                             
                # Record the new thread.
                #self.udp_thread_list.append(send_new_thread)
                # Start the new thread running.
                #send_new_thread.daemon = True
                #recv_new_thread.daemon = True
                #try:
                #    print("hello")
                #send_new_thread.start()
                #except Exception as msg:
                #    print("send Error here")

                # Start the new thread running.

                #try:
                #recv_new_thread.start()
                #except Exception as msg:
                #    print("recv Error here")
                #send_new_thread.join()
                #recv_new_thread.join()
                
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






