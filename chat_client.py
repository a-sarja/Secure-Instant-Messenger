#!/usr/bin/env python3
import argparse
import traceback
from ast import literal_eval

import pb_team11_pb2
import socket
import select
import sys

__author__ = 'Abhiram Sarja'

from utils.crypto_utils import decrypt_client_to_server, encrypt_server_to_client
from utils.srp_utils import create_srp_user


# Read the user console input while listening to the non-blocked socket - with 0.5 seconds interval
def read_input():
    i, o, e = select.select([sys.stdin], [], [], 0.5)
    for s in i:
        if s == sys.stdin:
            input_text = sys.stdin.readline()
            return input_text

    return False


class team11_client:

    def __init__(self, server_ip, server_port, username, password):
        self.server_host = server_ip
        self.server_port = server_port
        self.username = username
        self.password = password
        self.BUFFER_SIZE = 4096
        self.client_socket = None
        self.signin_status = False              # Sign-in status is False by default
        self.request = pb_team11_pb2.Request()  # Protobuf Request message
        self.reply = pb_team11_pb2.Reply()      # Protobuf Reply message
        self.server_client_session_key = None

    def initialise_client_socket(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.setblocking(False)
        client_socket.settimeout(2)
        self.client_socket = client_socket  # Assign this socket to client socket

    def send_message(self):
        self.request.version = 7
        return self.client_socket.send(
            self.request.SerializeToString()
        )  # serialize message to string & send it the server

    def receive_message(self):
        incoming_message = self.client_socket.recv(self.BUFFER_SIZE)
        if incoming_message:
            return self.reply.ParseFromString(incoming_message)  # parse response message

    # auto-execute signin operation upon client start
    def client_signin(self, seq_n, srp_user):

        # Generate the SRP uname, A on client side
        uname, A = srp_user.start_authentication()
        # First three calls between the server & client are for SRP authentication
        self.request.seq_n = seq_n  # set sequence number
        self.request.type = pb_team11_pb2.Request.SIGNIN
        self.request.payload = str((uname, A))

        self.send_message()
        # Server initial response
        self.receive_message()
        s, B = literal_eval(self.reply.payload)
        if not s or not B:
            print('Authentication failed (1)')
            exit(1)

        M = srp_user.process_challenge(bytes_s=s, bytes_B=B)
        if not M:
            print('Authentication failed (2)')
            exit(2)

        seq_n += 1
        self.request.seq_n = seq_n  # set sequence number
        self.request.type = pb_team11_pb2.Request.SIGNIN
        self.request.payload = M.decode('latin-1')

        self.send_message()
        # final server response during authentication phase
        self.receive_message()
        H_AMK = self.reply.payload.encode('latin-1')

        srp_user.verify_session(H_AMK)       # Verify the server response and generate the session key if successful
        if srp_user.authenticated():
            self.signin_status = True
            self.server_client_session_key = srp_user.get_session_key()

            return seq_n

        else:
            print(f'Authentication failed (4): {H_AMK.decode("utf-8")}')
            exit(4)

    def client_processing(self):

        # Create SRP user using user credentials
        srp_user = create_srp_user(username=self.username, password=self.password)

        self.initialise_client_socket()  # Initialise the client before doing anything
        self.client_socket.connect((self.server_host, self.server_port))  # connect to server
        self.request.version = 7

        request_number = 0  # Initialise the sequence number to 0

        # Signin/Authentication
        new_seq_n = self.client_signin(seq_n=request_number, srp_user=srp_user)
        if not self.signin_status or not self.server_client_session_key:
            print('Authentication failed!\n')
            exit(5)

        print("\nWelcome to Network Security Chat Room - in collaboration with the Team AUS! \n\n"
              "Type `list` to get all the online clients and `bye` to leave the chat room!\n")

        request_number = new_seq_n + 1
        while True:
            exit_flag = False
            try:
                self.receive_message()

                # Decrypt the received message using session-key
                self.reply.payload = decrypt_client_to_server(
                    key=self.server_client_session_key,
                    iv=self.reply.initial_vector,
                    tag=self.reply.e_tag,
                    ciphertext=bytes(self.reply.payload, 'latin-1')
                )

                print("Received data > (", self.reply.version, self.reply.seq_n, ") ", self.reply.payload)

            except socket.error:
                pass

            except Exception as ex:
                traceback.print_exception(ex)
                print('[Client Exception]', str(ex))
                exit(6)

            user_input = read_input()
            if user_input:
                try:
                    if user_input.strip().lower() == 'list':
                        self.request.type = pb_team11_pb2.Request.LIST
                    elif user_input.strip().lower() == 'bye':
                        self.request.type = pb_team11_pb2.Request.BYE
                        self.request.payload = self.username
                        exit_flag = True
                    elif user_input.strip().lower().startswith('send'):         # send K{source, target, Nonce} to server to get target's IP and port
                        self.request.type = pb_team11_pb2.Request.SEND
                        target_client_username = user_input.strip().split(" ")[1]

                        # Encrypt the payload before sending
                        iv, ciphertext, tag = encrypt_server_to_client(self.server_client_session_key, target_client_username)
                        self.request.initial_vector = iv
                        self.request.e_tag = tag
                        self.request.payload = ciphertext.decode('latin-1')
                    else:
                        print('Unknown command..')
                        continue

                    self.request.seq_n = request_number  # set sequence number
                    self.send_message()
                    request_number += 1  # Increment the sequence number

                    if exit_flag:
                        raise Exception('Client wants to leave the chat room!')

                except Exception as ex:
                    print('Some internal error - ' + str(ex))
                    self.client_socket.close()
                    break


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", type=str, required=True,
                        help="Username is required. It is the unique name that you identify yourself with.")
    parser.add_argument("-p", "--password", type=str, required=True,
                        help="Password is required")
    parser.add_argument("-sip", "--serverip", type=str, required=True, default="127.0.0.1",
                        help="Server IP is required. Please reach out to system admin if you do not know the Server IP Address.")
    parser.add_argument("-sp", "--serverport", type=int, required=True, default=5050,
                        help="Server's Port number is missing.")
    args = parser.parse_args()

    # Reading values from the arguments
    username = args.username
    password = args.password
    server_ip = args.serverip
    server_port = args.serverport

    client = team11_client(server_ip=server_ip, server_port=server_port, username=username, password=password)
    client.client_processing()
