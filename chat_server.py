#!/usr/bin/env python3

import argparse
import base64
import socket
import traceback
from ast import literal_eval
from utils.srp_utils import srp_verifier, get_srp_salt_vkey
import pb_team11_pb2
from multiprocessing import Process, Manager
from utils.crypto_utils import encrypt_server_to_client, decrypt_client_to_server, generate_symmetric_keys

__author__ = 'Abhiram Sarja, Simran Sohal'


class AuthenticationFailed(Exception):
    pass


# Adding username to the available-clients list
def add_user_to_clients_list(username, address_information, online_clients):
    complete_url = str(address_information[0]) + ":" + str(address_information[1])
    online_clients[username] = complete_url


# Add the generated secret key : Can be a secure database table in the future
def add_secret_keys_list(username, session_key, secret_keys):
    secret_keys[username] = session_key


class team11_server:

    def __init__(self, server_host, server_port, online_clients, secret_keys):
        self.host = server_host
        self.port = server_port
        self.online_clients = online_clients
        self.secret_keys = secret_keys          # Dict of keys for every user maintained by the server, accessible to all the threads
        self.server_socket = None
        self.BUFFER_SIZE = 65536
        self.request = pb_team11_pb2.Request()  # create protobuf Request message
        self.reply = pb_team11_pb2.Reply()  # create protobuf Reply message
        self.send_command = pb_team11_pb2.SendCommand()
        self.send_command_response = pb_team11_pb2.SendCommandResponse()

    # Initialise the server socket as UDP
    def initialise_server_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))  # Bind to the port
        self.server_socket.listen()

        print("Server Initialized.. Server is up & running..")

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
                        srp_salt, srp_v_key = get_srp_salt_vkey(user_name=uname)
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

                            # Add username to the list of online clients, and session key to the confidential `secret_keys`
                            add_user_to_clients_list(username=uname, address_information=source, online_clients=online_clients)
                            add_secret_keys_list(username=uname, session_key=server_client_s_key, secret_keys=secret_keys)

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

                    self.send_command.ParseFromString(bytes(self.request.payload, 'latin-1'))

                    request_source = self.send_command.source
                    destination_client = self.send_command.destination
                    nonce = self.send_command.nonce
                    '''
                        TODO: verify the request source with the source have in the config may be?
                    '''
                    self.send_command_response.nonce = nonce  # Respond nonce (Nx) back to client
                    if destination_client in online_clients:
                        client_to_client_key = generate_symmetric_keys()

                        # Generate a ticket here (this can be decrypted only by the receiver, not the requester!)
                        iv, ticket_to_receiver, tag = generate_ticket(
                            symmetric_key=client_to_client_key,
                            source_of_requester=request_source,
                            receiver=destination_client,
                            nonce=nonce
                        )

                        self.send_command_response.destination = str(online_clients[destination_client])
                        self.send_command_response.secret_key = base64.b64encode(client_to_client_key).decode('latin-1')     # 256 bits symmetric key to be used between the clients

                        # Send ticket as well (ticket in reply, IV and TAG in command response)
                        self.reply.ticket_to_client = base64.b64encode(ticket_to_receiver).decode('latin-1')
                        self.send_command_response.initial_vector = base64.b64encode(iv).decode('latin-1')
                        self.send_command_response.e_tag = base64.b64encode(tag).decode('latin-1')
                        self.send_command_response.error_code = 0
                    else:
                        # Dummy data
                        self.send_command_response.destination = str(online_clients)
                        self.send_command_response.secret_key = base64.b64encode(bytes(nonce, 'latin-1')).decode('latin-1')
                        self.send_command_response.initial_vector = base64.b64encode(bytes(nonce, 'latin-1')).decode('latin-1')
                        self.send_command_response.e_tag = base64.b64encode(bytes(nonce, 'latin-1')).decode('latin-1')

                        self.send_command_response.error_code = 100

                    # Encrypt before sending
                    iv, ciphertext, tag = encrypt_server_to_client(server_client_s_key, self.send_command_response.SerializeToString())
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


def generate_ticket(symmetric_key, source_of_requester, receiver, nonce):

    if receiver in secret_keys:

        session_key_receiver = secret_keys[receiver]
        ticket_object = {
            'source': source_of_requester,
            'secret_key': base64.b64encode(symmetric_key).decode('latin-1'),
            'nonce': nonce
        }

        return encrypt_server_to_client(
            key=session_key_receiver,
            plaintext=str(ticket_object)
        )


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--serverport", type=int, default=9090, required=True,
                        help="Server's Port number is missing.")
    args = parser.parse_args()

    # Reading values from the arguments
    s_port = args.serverport

    # Maintaining shared information on clients
    manager = Manager()
    clients = manager.dict()        # Dynamically updated list by various `client` threads
    secret_keys = manager.dict()    # To be forgotten after TTL

    try:
        server = team11_server(server_host="0.0.0.0", server_port=s_port, online_clients=clients, secret_keys=secret_keys)
        server.initialise_server_socket()

    except Exception as ex:
        print('Some Internal error: ' + str(ex))