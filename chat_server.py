#!/usr/bin/env python3

import argparse
import socket
import traceback
from ast import literal_eval
from utils.srp_utils import create_srp_salt_vkey, srp_verifier
import pb_team11_pb2
from multiprocessing import Process, Manager
from utils.crypto_utils import encrypt_server_to_client, decrypt_client_to_server


__author__ = 'Abhiram Sarja, Simran Sohal'


class AuthenticationFailed(Exception):
    pass


# Adding username to the available-clients list
def add_user_to_clients_list(username, address_information, online_clients):
    complete_url = str(address_information[0]) + ":" + str(address_information[1])
    online_clients[username] = complete_url


class team11_server:

    def __init__(self, server_host, server_port, online_clients):
        self.host = server_host
        self.port = server_port
        self.online_clients = online_clients
        self.server_socket = None
        self.BUFFER_SIZE = 4096
        self.request = pb_team11_pb2.Request()  # create protobuf Request message
        self.reply = pb_team11_pb2.Reply()  # create protobuf Reply message

    # Initialise the server socket as UDP
    def initialise_server_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))  # Bind to the port
        self.server_socket.listen()

        print("Server Initialized.. Server is left running..")

        while True:
            conn, address = self.server_socket.accept()
            print(f'New connection request from {address}')

            if address:
                connection_proc = Process(target=self.process_connection, args=(conn, address, self.online_clients))
                connection_proc.start()

    def process_connection(self, conn, source, online_clients):

        global uname, svr, server_client_s_key
        while True:

            try:
                data = conn.recv(self.BUFFER_SIZE)
                if not data:
                    continue

                self.request.ParseFromString(data)  # parse message
                print(f"Received data -> version : {self.request.version}, sequence : {self.request.seq_n}")
                if self.request.version != 7:  # only accept version 7
                    continue

                # use same version and sequence number in the reply
                self.reply.version = self.request.version
                self.reply.seq_n = self.request.seq_n

                if self.request.type == pb_team11_pb2.Request.SIGNIN:  # Log-in request
                    # Before adding the user to the clients_list, verify using SRP
                    if self.request.seq_n == 0:  # (uname, A) from client

                        uname, A = literal_eval(self.request.payload)
                        srp_salt, srp_v_key = create_srp_salt_vkey(user_name=uname)
                        svr = srp_verifier(uname, srp_salt, srp_v_key, A)       # SRP verifier

                        s, B = svr.get_challenge()      # While A is client challenge, B is server challenge
                        if not s or not B:
                            self.reply.payload = '-1000'
                            raise AuthenticationFailed('-1000')

                        self.reply.payload = str((s, B))

                    if self.request.seq_n == 1:  # Client side challenge M is incoming

                        H_AMK = svr.verify_session(bytes(self.request.payload, 'latin-1'))
                        if not H_AMK:
                            self.reply.payload = '-1001'
                            raise AuthenticationFailed('-1001')

                        self.reply.payload = H_AMK.decode('latin-1')
                        if svr.authenticated():
                            print(f'User {uname} authenticated successfully and a session key is created..\n')

                            server_client_s_key = svr.get_session_key()     # Use this key for encrypting further communication between the client and the server
                            add_user_to_clients_list(
                                username=uname,
                                address_information=source,
                                online_clients=online_clients
                            )

                if self.request.type == pb_team11_pb2.Request.LIST:

                    plaintext_payload = str(online_clients.keys())
                    # Encrypt before sending
                    iv, ciphertext, tag = encrypt_server_to_client(server_client_s_key, plaintext_payload)
                    self.reply.initial_vector = iv
                    self.reply.e_tag = tag
                    self.reply.payload = ciphertext.decode('latin1')

                if self.request.type == pb_team11_pb2.Request.SEND:

                    # Decrypt the received message using session-key
                    self.request.payload = decrypt_client_to_server(
                        key=server_client_s_key,
                        iv=self.request.initial_vector,
                        tag=self.request.e_tag,
                        ciphertext=bytes(self.request.payload, 'latin-1')
                    )

                    destination_client = self.request.payload
                    if destination_client in online_clients:
                        plaintext_payload = str(online_clients[destination_client])
                    else:
                        plaintext_payload = 'Client not found!'

                    # Encrypt before sending
                    iv, ciphertext, tag = encrypt_server_to_client(server_client_s_key, plaintext_payload)
                    self.reply.initial_vector = iv
                    self.reply.e_tag = tag
                    self.reply.payload = ciphertext.decode('latin-1')

                if self.request.type == pb_team11_pb2.Request.BYE:
                    conn.close()
                    raise Exception(f'Client {uname} left the chat room!')

                conn.send(self.reply.SerializeToString())  # serialize response into string, send it & wait for the next message from the client

            except AuthenticationFailed as auth_exception:
                conn.send(self.reply.SerializeToString())
                print('[Authentication Error]', str(auth_exception))
                break

            except Exception as e:
                # traceback.print_exception(e)
                print('[Server Exception]', str(e))
                del online_clients[uname]  # Remove the user from the list of online clients
                break


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--serverport", type=int, default=9090, required=True,
                        help="Server's Port number is missing.")
    args = parser.parse_args()

    # Reading values from the arguments
    s_port = args.serverport

    # Maintaining shared information on clients
    manager = Manager()
    clients = manager.dict()

    try:
        server = team11_server(server_host="0.0.0.0", server_port=s_port, online_clients=clients)
        server.initialise_server_socket()

    except Exception as ex:
        print('Some internal error: ' + str(ex))
