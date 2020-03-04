#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import os

########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN  = 24 # 24 byte file size field.

# Packet format when a GET command is sent from a client, asking for a
# file download:

# -------------------------------------------
# | 1 byte GET command  | ... file name ... |
# -------------------------------------------

# When a GET command is received by the server, it reads the file name
# then replies with the following response:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.
CMD = {
    "GET" : 1,
    "PUT" : 2
}

MSG_ENCODING = "utf-8"
CURRENT_DIR = os.getcwd()
#MY_REMOTE_DIR = os.chdir('./Remote')
#MY_LOCAL_DIR = os.chdir('../Local')
########################################################################
# Echo Server class
########################################################################

class Server: #Receiver

    RECV_SIZE = 1024

    HOST = "192.168.2.175"
    BROADCAST_PORT = 30000
    ADDRESS_PORT = (HOST, BROADCAST_PORT)
    
    MSG_ENCODING = "utf-8"

    TCP_PORT = 50000
    SOCKET_TCP_ADDRESS = (HOST, TCP_PORT)
    MAX_CONNECTION_BACKLOG = 20
    
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    
        
   # # This is the file that the client will request using a GET.
   # REMOTE_FILE_NAME = "remotefile.txt"
   # # Get the file size
   # REMOTE_FILE_SIZE = os.path.getsize(REMOTE_FILE_NAME)
    
    def __init__(self):
        self.get_socket() #UDP
        self.receive_forever() #UDP
        #self.create_listen_socket() #TCP
        #self.process_connections_forever() #TCP
    
    def get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Bind to all interfaces and the agreed on broadcast port.
            self.socket.bind(Server.ADDRESS_PORT)
            print("Listening for service discovery messages on SDP port {port_num}".format(port_num = Server.ADDRESS_PORT[1]))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address = self.socket.recvfrom(Server.RECV_SIZE)
                print("Broadcast received: ", 
                      data.decode('utf-8'), address)
                if (data.decode('utf-8') == "Service Discovery"):
                    print("-" * 72)
                    print("Message received from {}.".format(address))
                    msg_bytes = "Lily and Sarah's File Sharing Service"
                    # time.sleep(20) # for attacker.

                    # Echo the received bytes back to the sender.
                    print("address is " + str(address))
                    self.socket.sendto("Lily and Sarah's File Sharing Service".encode('utf-8'), address)
                    self.create_listen_socket()
                    self.process_connections_forever()
                    #exit(1)
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)


    #TCP
    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(Server.SOCKET_TCP_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening for file sharing connections on port {}".format(Server.TCP_PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for accepting incoming
                # connections. When one is accepted, pass the new
                # (cloned) socket reference to the connection handler
                # function.
                self.connection_handler(self.socket.accept())
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
        print("Connection received from {}.".format(address_port))

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
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                if (recvd_str == "rlist"):
                    listing = os.listdir(CURRENT_DIR)

                    for entry in listing:
                        if os.path.isfile(entry):
                            print(entry)
                #print("Received: ", recvd_str)
                
                # Send the received bytes back to the client.
                connection.sendall(recvd_bytes)
                print("Sent: ", recvd_str)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break
        # Read the command and see if it is a GET.
        cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')
        if cmd != CMD["GET"]:
            print("GET command not received!")
            return

        # The command is good. Now read and decode the requested
        # filename.
        filename_bytes = connection.recv(Server.RECV_SIZE)
        filename = filename_bytes.decode(MSG_ENCODING)

        # Open the requested file and get set to send it to the
        # client.
        try:
            file = open(filename, 'r').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()                   
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            # print("Sent packet bytes: \n", pkt)
            print("Sending file: ", Server.REMOTE_FILE_NAME)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
########################################################################
# Echo Client class
########################################################################

class Client: #Sender

    # HOSTNAME = socket.gethostbyname('')
    # HOSTNAME = 'localhost'
    HOSTNAME = '192.168.2.175'

    # Send the broadcast packet periodically. Set the period
    # (seconds).
    BROADCAST_PERIOD = 2

    # Define the message to broadcast.
    MSG_ENCODING = "utf-8"
    MESSAGE =  "Service Discovery"
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255" 
    # BROADCAST_ADDRESS = "192.168.1.255"
    BROADCAST_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)

    UDP_PORT = 40000
    TCP_PORT = 60000 
    #SERVER_ADDRESS_PORT = ('localhost', Server.PORT)
    RECV_SIZE = 1024

    def __init__(self):
        self.create_sender_socket()
        self.send_broadcasts_forever()
       # self.get_tcp_socket() #TCP
       # self.connect_to_server() #TCP

    def create_sender_socket(self):
        try:
            # Set up a UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            ############################################################
            # Set the option for broadcasting.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            ############################################################
            # Bind socket to the client socket address.
            self.socket.bind((Client.HOSTNAME, Client.UDP_PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def send_broadcasts_forever(self):
        try:
            while True:
                print("Sending to {} ...".format(Client.ADDRESS_PORT))
                self.socket.sendto(Client.MESSAGE_ENCODED, Client.ADDRESS_PORT)
                time.sleep(Client.BROADCAST_PERIOD)

                #self.get_socket()
                self.message_receive()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Set socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def send_console_input_forever(self):
        print("hello!")
        while True:
            try:
                #self.get_console_input()
                #self.message_send()
                self.message_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing client socket ...")
                self.socket.close()
                sys.exit(1)

    def message_receive(self):
        try:
            # recvfrom returns bytes received and the identity of the
            # sender.
            recvd_bytes, address = self.socket.recvfrom(Client.RECV_SIZE)
            # print("Received Message Bytes: ", recvd_bytes)
            print("Received Message: ", recvd_bytes.decode(Server.MSG_ENCODING))
            self.get_tcp_socket()
            self.connect_to_server()
            self.send_console_input_forever()
        except Exception as msg:
            print(msg)
            sys.exit(1)

    # TCP
    def get_tcp_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Bind socket to the client socket address.
            self.socket.bind((Client.HOSTNAME, Client.TCP_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.HOSTNAME, Server.TCP_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input("Input: ")
            if (self.input_text == "llist"):
                    listing = os.listdir(CURRENT_DIR)
                    for entry in listing:
                        if os.path.isfile(entry):
                            print(entry)
            if self.input_text != "":
                break

    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

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






