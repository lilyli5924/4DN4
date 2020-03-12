#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import os
import json

########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN = 24 # 24 byte file size field.
FILE_SIZE_FIELD_LEN_S = 24 

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
    "PUT" : 1,
    "GET" : 2
}

CURRENT_DIR = os.getcwd()

########################################################################
# Echo Server class
########################################################################

class Server: #Receiver

    RECV_SIZE = 1024

    RECV_CMD = 1

    HOST = "0.0.0.0"
    BROADCAST_PORT = 30000
    ADDRESS_PORT = (HOST, BROADCAST_PORT)
    
    MSG_ENCODING = "utf-8"

    TCP_PORT = 50000
    SOCKET_TCP_ADDRESS = (HOST, TCP_PORT)
    MAX_CONNECTION_BACKLOG = 20
    
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    
        
   # # This is the file that the client will request using a GET.
    REMOTE_FILE_NAME = "remotefile.txt"
    REMOTE_FILE_NAME_1 = "remotefile_1.txt"
   # # Get the file size
   # REMOTE_FILE_SIZE = os.path.getsize(REMOTE_FILE_NAME)
    
    def __init__(self):
        listing = os.listdir(CURRENT_DIR)
        for entry in listing:
            if os.path.isfile(entry):
                print(entry)
        self.get_socket() #UDP
        self.receive_forever() #UDP
    
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
                    # time.sleep(20) # for attacker.

                    # Echo the received bytes back to the sender.
                    self.socket.sendto("Lily and Sarah's File Sharing Service".encode('utf-8'), address)
                    self.create_listen_socket()
                    self.process_connections_forever()
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

    def get_file_handler(self, connection, filename_bytes):
        filename = filename_bytes.decode(Server.MSG_ENCODING)

        try:
            file = open(filename, 'r').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()                   
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(Server.MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')
        
        pkt = file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", Server.REMOTE_FILE_NAME)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return

    def connection_handler(self, client):
        connection, address_port = client
        print("Connection received from {ip_addr} on port {port_num}.".format(ip_addr = address_port[0], port_num = address_port[1]))

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

                if(recvd_str == "bye"):
                    print("Closing client connection ...")
                    connection.close()
                    break
                
                if (recvd_str == "rlist" or recvd_str == "llist"):
                    if (recvd_str == "rlist"):
                        listing = os.listdir(CURRENT_DIR)

                        for entry in listing:
                            if os.path.isfile(entry):
                                print(entry) 
                    else:
                        pass
                    
                    # Send the received bytes back to the client.
                    connection.sendall(recvd_bytes)          
                
                else:  
                    # Spliting the command field and data field
                    recvd_bytes_0 = recvd_bytes[:1]
                    recvd_bytes_1 = recvd_bytes[1:]

                    # Read the command and see if it is a GET.
                    cmd = int.from_bytes(recvd_bytes_0, byteorder='big')
                    print(str(cmd))
                    if cmd != CMD["GET"]:

                        print("Received {} bytes. Creating file: {}" \
                            .format(len(recvd_bytes_1), Server.REMOTE_FILE_NAME_1))

                        with open(Server.REMOTE_FILE_NAME_1, 'w') as f:
                            f.write(recvd_bytes_1.decode(Server.MSG_ENCODING))
                        
                        print("Finished written.")
                        
                        # List the remote file directory
                        dir_list = []
                        listing_1 = os.listdir(CURRENT_DIR)
                        for entry in listing_1:
                            if os.path.isfile(entry):
                                dir_list.append(entry)
                        serial_list = json.dumps(dir_list)
                        connection.sendall(serial_list.encode(Server.MSG_ENCODING))

                    else:
                        self.get_file_handler(connection,recvd_bytes_1)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break
        
########################################################################
# Echo Client class
########################################################################

class Client: #Sender

    # HOSTNAME = socket.gethostbyname('')
    # HOSTNAME = 'localhost'
    HOSTNAME = '0.0.0.0'

    # Send the broadcast packet periodically. Set the period
    # (seconds).
    BROADCAST_PERIOD = 2

    # Define the message to broadcast.
    MSG_ENCODING = "utf-8"
    MESSAGE =  "Service Discovery"
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

    SCAN_CYCLES = 3
    SCAN_TIMEOUT = 5
    
    SCAN_CMD = "SCAN"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)
    
    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255" 

    BROADCAST_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)

    UDP_PORT = 40000
    TCP_PORT = 60000 
    RECV_SIZE = 1024

    LOCAL_FILE_NAME = "localfile.txt"
    #LOCAL_FILE_NAME_1 = "localfile_1.txt"

    def __init__(self):
        self.create_sender_socket()
        self.send_broadcasts_forever()

    def get_file_entry(self):
        listing = os.listdir(CURRENT_DIR)
        for entry in listing:
            if os.path.isfile(entry):
                print(entry)

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
                self.scan_for_service()

                #self.message_receive()

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
    
    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = []

        # Repeat the scan procedure a preset number of times.
        for i in range(Client.SCAN_CYCLES):

            # Send a service discovery broadcast.
            print("Sending broadcast scan {}".format(i))            
            #self.socket.sendto(Client.SCAN_CMD_ENCODED, Client.ADDRESS_PORT)
            #time.sleep(Client.BROADCAST_PERIOD)
        
            while True:
                # Listen for service responses. So long as we keep
                # receiving responses, keep going. Timeout if none are
                # received and terminate the listening for this scan
                # cycle.
                try:
                    recvd_bytes, address = self.socket.recvfrom(Client.RECV_SIZE)
                    recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)

                    # Record only unique services that are found.
                    if (recvd_msg) not in scan_results:
                        scan_results.append((recvd_msg))
                        if (scan_results[i] == "Lily and Sarah's File Sharing Service"):
                            print("Lily and Sarah's File Sharing Service found at {ip_addr} on port {port_num}.".format(ip_addr = address[0], port_num = address[1]))
                            self.get_tcp_socket()
                            self.send_console_input_forever()
                        else:
                            print("No services found.")    
                        continue
                # If we timeout listening for a new response, we are
                # finished.
                except socket.timeout:
                    break

       # # Output all of our scan results, if any.
       # print(scan_results)
       # if (scan_results):
       #     print("hello")
       #     for result in scan_results:
       #         print(result)
       #         if (result == "Lily and Sarah's File Sharing Service"):
       #             print("Lily and Sarah's File Sharing Service found at {ip_addr} on port {port_num}.".format(ip_addr = address[0], port_num = address[1]))
       #             self.get_tcp_socket()
       #             self.send_console_input_forever()
       # else:
       #     print("No services found.")
    
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
            if (recvd_bytes.decode(Server.MSG_ENCODING) == "Lily and Sarah's File Sharing Service"):
                print("Lily and Sarah's File Sharing Service found at {ip_addr} on port {port_num}.".format(ip_addr = address[0], port_num = address[1]))
                self.get_tcp_socket()
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
                self.get_file_entry()
            if self.input_text != "":
                break

    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.input_id = self.input_text.split(" ")
                # print("input_id is " + str(self.input_id))
                if (self.input_id[0] == "connect"):
                    self.connect_to_server()
                elif (self.input_id[0] == "get"):
                    self.get_file()
                elif (self.input_id[0] == "put"):
                    self.put_file()
                    self.connection_receive()
                else:
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
            self.socket.sendall(self.input_id[0].encode(Server.MSG_ENCODING))
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

            recvd_list = recvd_bytes.decode(Server.MSG_ENCODING)
            print(recvd_list)

        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def socket_recv_size(self, length):
        bytes = self.socket.recv(length)
        if len(bytes) < length:
            self.socket.close()
            exit()
        return(bytes)

    def get_file(self):

        # Create the packet GET field.
        get_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field = self.input_id[1].encode('utf-8')

        # Create the packet.
        pkt = get_field + filename_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        # Read the file size field.
        file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
        if len(file_size_bytes) == 0:
               self.socket.close()
               return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')

        # Receive the file itself.
        recvd_bytes_total = bytearray()
        try:
            # Keep doing recv until the entire file is downloaded. 
            while len(recvd_bytes_total) < file_size:
                recvd_bytes_total += self.socket.recv(Client.RECV_SIZE)

            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), Client.LOCAL_FILE_NAME))

            with open(Client.LOCAL_FILE_NAME, 'w') as f:
                f.write(recvd_bytes_total.decode(Server.MSG_ENCODING))
            
            # List the local file directory
            self.get_file_entry()

        except KeyboardInterrupt:
            print()
            exit(1)
        # If the socket has been closed by the server, break out
        # and close it on this end.
        except socket.error:
            self.socket.close()
    
    def put_file(self):
        put_field = CMD["PUT"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        try:
            file = open(self.input_id[1], 'r').read()
        except FileNotFoundError:
            print(Client.FILE_NOT_FOUND_MSG)   
            self.socket.close()    
            return

        file_bytes = file.encode(Client.MSG_ENCODING)
        print(str(file_bytes))
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN_S, byteorder='big')
        
        pkt = put_field + file_bytes
        
        try:
            self.socket.sendall(pkt)
            print("Sending file: ", self.input_id[1])
        except socket.error:
            print("Closing Server connection ...")
            self.socket.close()
            return


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