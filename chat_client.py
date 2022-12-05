#!/usr/bin/env python3
import argparse
import ast
import base64
import traceback
from ast import literal_eval

import pb_team11_pb2
import socket
import select
import sys

__author__ = 'Abhiram Sarja, Simran Sohal'

from utils.crypto_utils import decrypt_client_to_server, encrypt_server_to_client, generate_timestamp
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
        self.BUFFER_SIZE = 65536
        self.client_socket = None
        self.my_socket = None                   # UDP socket to keep listening to incoming messages (from other clients)
        self.signin_status = False              # Sign-in status is False by default

        self.request = pb_team11_pb2.Request()  # Protobuf Request message
        self.reply = pb_team11_pb2.Reply()      # Protobuf Reply message
        self.message = pb_team11_pb2.Message()  # Protobuf Client-to-Client message
        self.send_command = pb_team11_pb2.SendCommand()
        self.send_command_response = pb_team11_pb2.SendCommandResponse()

        self.server_client_session_key = None
        self.clients_connection_secret_keys = {}           # Store the secret_keys for a client after mutual auth
        self.target_nodes_list = {}             # {'username': (IP, port)}

    def initialise_client_socket(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.setblocking(False)
        client_socket.settimeout(2)
        self.client_socket = client_socket  # Assign this socket to client socket

    # Initialise the client UDP socket for incoming messages from other clients
    def initialise_client_udp_socket(self, my_ip, udp_port):
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.my_socket.setblocking(False)
        self.my_socket.bind((my_ip, udp_port))

    def send_udp_message(self, target):
        self.my_socket.sendto(self.message.SerializeToString(), target)

    def receive_udp_message(self):
        incoming_udp_message = self.my_socket.recvfrom(self.BUFFER_SIZE)
        if incoming_udp_message:
            return self.message.ParseFromString(incoming_udp_message[0]), incoming_udp_message[1]

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
              "Type: \n \t `list` to get all the online clients \n \t 'send <username> <message>' to send a message to your friend and \n \t `bye` to leave the chat room!\n")

        my_host_address = self.client_socket.getsockname()
        my_ip = my_host_address[0]
        my_port = my_host_address[1]
        print('YOU ARE CONNECTED FROM : ', my_ip, my_port, '\n')

        # After successful sign-in, create a UDP socket as well to listen to the incoming messages (from other clients)
        self.initialise_client_udp_socket(my_ip=my_ip, udp_port=my_port)

        request_number = new_seq_n + 1      # For TCP connection with the server
        send_flag = False
        message = None

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

                if not send_flag:
                    print("FROM server > ", self.reply.payload)

                if send_flag:
                    self.send_command_response.ParseFromString(bytes(self.reply.payload, 'latin-1'))
                    if int(self.send_command_response.error_code) == 0:

                        # send the message to the client
                        temp = self.send_command_response.destination
                        secret_key = base64.b64decode(bytes(self.send_command_response.secret_key, 'latin-1'))

                        self.clients_connection_secret_keys[self.send_command.destination] = secret_key

                        ticket_to_client = base64.b64decode(bytes(self.reply.ticket_to_client, 'latin-1'))
                        i_v = base64.b64decode(bytes(self.send_command_response.initial_vector, 'latin-1'))
                        e_tag = base64.b64decode(bytes(self.send_command_response.e_tag, 'latin-1'))

                        self.message.seq_n = 0
                        self.message.version = 7
                        self.message.server_iv = i_v.decode('latin-1')
                        self.message.server_e_tag = e_tag.decode('latin-1')
                        self.message.ticket = ticket_to_client.decode('latin-1')

                        nonce_2 = generate_timestamp()
                        iv, ciphertext, etag = encrypt_server_to_client(key=secret_key, plaintext=nonce_2)     # Nonce-2

                        self.message.initial_vector = iv.decode('latin-1')
                        self.message.e_tag = etag.decode('latin-1')
                        self.message.payload = ciphertext.decode('latin-1')

                        target_node = (temp.split(":")[0], int(temp.split(":")[1]))
                        self.target_nodes_list[self.send_command.destination] = target_node

                        self.send_udp_message(target=target_node)

                    send_flag = False

            except socket.error:
                pass

            except Exception as ex:
                # traceback.print_exc()
                print('[Client Error Exception]', str(ex))
                exit(6)

            # Read UDP data (Most probably from other clients)
            try:
                m, source_of_request_udp = self.receive_udp_message()

                if self.message.seq_n > 1:
                    source = self.message.source_uname
                    k = self.clients_connection_secret_keys[self.message.source_uname]
                    plaintext_client_message = decrypt_client_to_server(key=k, iv=bytes(self.message.initial_vector, 'latin-1'), ciphertext=bytes(self.message.payload, 'latin-1'), tag=bytes(self.message.e_tag, 'latin-1'))

                    print('FROM ', source, '> ', plaintext_client_message.decode('latin-1'))

                elif self.message.seq_n == 0:
                    #print('[DEBUG] Received initial connection request from a client!')

                    ticket = bytes(self.message.ticket, 'latin-1')
                    iv = bytes(self.message.server_iv, 'latin-1')
                    etag = bytes(self.message.server_e_tag, 'latin-1')

                    # Decrypt the ticket using my session key to get the secret key
                    ticket_dict = decrypt_client_to_server(key=self.server_client_session_key, iv=iv, ciphertext=ticket, tag=etag)
                    if ticket_dict:
                        ticket_dict = ast.literal_eval(ticket_dict.decode('latin-1'))
                        s = ticket_dict['secret_key']
                        secret_key = base64.b64decode(bytes(s, 'latin-1'))
                        if not secret_key:
                            print('Error in processing the secret key. Let us ignore the request')
                            return

                        source = ticket_dict['source']
                        self.clients_connection_secret_keys[source] = secret_key
                        nonce_2 = decrypt_client_to_server(
                            key=secret_key,
                            iv=bytes(self.message.initial_vector, 'latin-1'),
                            ciphertext=bytes(self.message.payload, 'latin-1'),
                            tag=bytes(self.message.e_tag, 'latin-1')
                        )
                        # Encrypt (Nonce_2-1)
                        iv, ciphertext, tag = encrypt_server_to_client(key=secret_key, plaintext=str(int(nonce_2)-1))

                        self.message.seq_n += 1
                        self.message.payload = ciphertext.decode('latin-1')
                        self.message.initial_vector = iv.decode('latin-1')
                        self.message.e_tag = tag.decode('latin-1')
                        self.message.source_uname = srp_user.get_username()

                        self.send_udp_message(target=source_of_request_udp)
                        self.target_nodes_list[source] = source_of_request_udp      # Add the sender's info to nodes list

                elif int(self.message.seq_n) == 1:

                    secret_key = self.clients_connection_secret_keys[self.send_command.destination]
                    nonce_3 = decrypt_client_to_server(key=secret_key, iv=bytes(self.message.initial_vector, 'latin-1'), ciphertext=bytes(self.message.payload, 'latin-1'), tag=bytes(self.message.e_tag, 'latin-1'))
                    if int(nonce_3) != int(nonce_2) - 1:
                        print('Error in client-client mutual authentication')
                        return

                    #print('[DEBUG] Clients are mutually authenticated!', source_of_request_udp)

                    # Send the first actual message
                    # print('[DEBUG] UDP SQN NUMBER', self.message.seq_n)
                    iv, ciphertext, tag = encrypt_server_to_client(key=secret_key, plaintext=str(message))
                    self.message.seq_n += 1
                    self.message.payload = ciphertext.decode('latin-1')
                    self.message.initial_vector = iv.decode('latin-1')
                    self.message.e_tag = tag.decode('latin-1')

                    # For every subsequent message exchanges between the clients, we must include the `source` username
                    self.message.source_uname = srp_user.get_username()

                    self.send_udp_message(target=source_of_request_udp)

                send_flag = False

            except socket.error:
                pass

            except Exception as ex:
                # traceback.print_exc()
                print('[Client UDP Exception]', str(ex))
                exit(7)

            user_input = read_input()
            if user_input:
                try:
                    if user_input.strip().lower() == 'list':
                        self.request.type = pb_team11_pb2.Request.LIST

                    elif user_input.strip().lower() == 'bye':
                        self.request.type = pb_team11_pb2.Request.BYE
                        self.request.payload = self.username
                        exit_flag = True

                    elif user_input.strip().lower().startswith('send') and len(user_input.strip().split(" ")) > 2:

                        # send 'SEND' command to server to get target's IP and port
                        target_client_username = user_input.strip().split(" ")[1]
                        message = user_input.strip().split(" ")[2:]
                        message = " ".join(message)

                        self.send_command.source = srp_user.get_username()
                        self.send_command.destination = target_client_username
                        self.send_command.nonce = generate_timestamp()

                        if target_client_username == self.username:
                            print('FROM ', self.username, '>', message)
                            continue

                        if self.send_command.destination not in self.clients_connection_secret_keys:

                            # Encrypt 'send_command' object before sending: K{'I am A', 'Want to talk to destination', Nx}
                            iv, ciphertext, tag = encrypt_server_to_client(
                                self.server_client_session_key,
                                self.send_command.SerializeToString()
                            )

                            # Request structure: SEND, iv, e_tag, ciphered_payload
                            self.request.type = pb_team11_pb2.Request.SEND
                            self.request.initial_vector = iv
                            self.request.e_tag = tag
                            self.request.payload = ciphertext.decode('latin-1')

                        else:
                            s_k = self.clients_connection_secret_keys[self.send_command.destination]
                            iv, ciphertext, tag = encrypt_server_to_client(key=s_k, plaintext=str(message))

                            self.message.seq_n += 1
                            self.message.payload = ciphertext.decode('latin-1')
                            self.message.initial_vector = iv.decode('latin-1')
                            self.message.e_tag = tag.decode('latin-1')

                            # For every subsequent message exchanges between the clients, we must include the `source` username
                            self.message.source_uname = srp_user.get_username()
                            target_node_address = self.target_nodes_list[self.send_command.destination]
                            self.send_udp_message(target=target_node_address)

                            continue

                        send_flag = True

                    else:
                        print('Unknown command\n Only LIST, SEND and BYE commands are accepted...')
                        continue

                    self.request.seq_n = request_number     # set sequence number
                    self.send_message()

                    request_number += 1                     # Increment the sequence number
                    if exit_flag:
                        raise Exception('Client has left the chat room!')

                except Exception as ex:
                    # traceback.print_exc()
                    print('Client Message - ' + str(ex))
                    self.client_socket.close()
                    break


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", type=str, required=True,
                        help="Username is required. It is the unique name that you identify yourself with.")
    parser.add_argument("-sip", "--serverip", type=str, required=True, default="127.0.0.1",
                        help="Server IP is required. Please reach out to system admin if you do not know the Server IP Address.")
    parser.add_argument("-sp", "--serverport", type=int, required=True, default=5050,
                        help="Server's Port number is missing.")

    args = parser.parse_args()

    # Reading values from the arguments
    username = args.username
    server_ip = args.serverip
    server_port = args.serverport

    password = input('Please enter your password: ')
    if not password:
        print('Password looks invalid. Please try again!')
        exit(1)

    client = team11_client(server_ip=server_ip, server_port=server_port, username=username, password=password)
    try:
        client.client_processing()

    except Exception as ex:
        print('[Client Error]', ex)
