#!/usr/bin/python3

"""
Echo Client and Server Classes

T. D. Todd
McMaster University

to create a Client: "python EchoClientServer.py -r client" 
to create a Server: "python EchoClientServer.py -r server" 

or you can import the module into another file, e.g., 
import EchoClientServer

"""

########################################################################

import socket
import argparse
import sys
import hashlib
from getpass import getpass
import csv
import json

########################################################################
# Echo Server class
########################################################################

class Server:

    # Set the server hostname used to define the server socket address
    # binding. Note that 0.0.0.0 or "" serves as INADDR_ANY. i.e.,
    # bind to all local network interface addresses.
    HOSTNAME = "0.0.0.0"
    
    # Set the server port to bind the listen socket to.
    PORT = 50000

    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    # Create server socket address. It is a tuple containing
    # address/hostname and port.
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(Server.SOCKET_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening for connections on port {}".format(Server.PORT))
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
        print("Connection received from {ip_addr} on port {port_num}.".format(ip_addr = address_port[0], port_num = address_port[1]))
        
        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
            
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
                with open('./passwd.csv', 'r') as csvfile:
                    reader = csv.reader(csvfile, delimiter=',')
                    hash_list = []
                    for col in reader:
                        id_number = col[0]
                        password  = col[1]
                        studentID = id_number
                        stored_studentID = hashlib.sha256(studentID.encode("utf-8"))
                        hashed_studentID = stored_studentID.hexdigest()
                        studentPassword = password
                        stored_studentPassword = hashlib.sha256(studentPassword.encode("utf-8"))
                        hashed_studentPassword = stored_studentPassword.hexdigest()
                        combined_csv_hash = hashed_studentID + hashed_studentPassword
                        hash_list.append(combined_csv_hash)
                
                with open('./course_grades.csv', 'r') as csvfile_grades:
                    grades_reader = csv.reader(csvfile_grades, delimiter=',')
                    grades_list = []
                    student_info = []
                    for col in grades_reader:
                        id_num = col[0]
                        last_name = col[1]
                        first_name = col[2]
                        english = col[3]
                        math = col[4]
                        science = col[5]
                        student_info = [id_num,last_name,first_name,english,math,science]
                        grades_list.append(student_info)
                
                if recvd_str in hash_list:
                    id_index = hash_list.index(recvd_str) # list.index(element), returns the index of the first occurence of the element
                    # Send the student information and grades back to the client.
                    print('Correct password, record found for ID ' + str(grades_list[id_index][0]))
                    recorded_id = str(grades_list[id_index][0])
                    serialized_grades_list = json.dumps(grades_list[id_index]) # to transform data into a series of bytes
                    print('Sent grade information to student ID ' + str(grades_list[id_index][0]))
                    print('Student Info: ', str(grades_list[id_index]))
                    connection.sendall(("Received request from ID " + recorded_id + ", password correct.\n" + "Student Info: " + serialized_grades_list).encode("utf-8"))
                else:
                    print("Password failure")
                    connection.sendall(("Student ID and password do not match.").encode("utf-8"))
            
            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

########################################################################
# Echo Client class
########################################################################

class Client:

    # Set the server hostname to connect to. If the server and client
    # are running on the same machine, we can use the current
    # hostname.
#    SERVER_HOSTNAME = socket.gethostbyname('localhost')
    SERVER_HOSTNAME = socket.gethostbyname('')
#    SERVER_HOSTNAME = 'localhost'

    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
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
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        #while True:
        self.input_id = input("ID Number: ")
        self.stored_id = hashlib.sha256(self.input_id.encode("utf-8"))
        self.hashed_id = self.stored_id.hexdigest()
        self.input_password = getpass("Password: ")
        self.stored_password = hashlib.sha256(self.input_password.encode("utf-8"))
        self.hashed_password = self.stored_password.hexdigest()
        self.combined_hash = self.hashed_id + self.hashed_password
        print('ID number ' + str(self.input_id) + ' and password received.')
        print('ID/password hash is ' + str(self.combined_hash))
        #    if self.input_text != "":
        #        break
    
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
            self.socket.sendall(self.combined_hash.encode(Server.MSG_ENCODING))
            print('Sent ID/password hash to server.')
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print(recvd_bytes.decode(Server.MSG_ENCODING))
        
        except Exception as msg:
            print(msg)
            sys.exit(1)

########################################################################
# Process command line arguments if this module is run directly.
########################################################################

# When the python interpreter runs this module directly (rather than
# importing it into another file) it sets the __name__ variable to a
# value of "__main__". If this file is imported from another module,
# then __name__ will be set to that module's name.

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






