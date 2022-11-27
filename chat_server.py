#!/usr/bin/env python3

import argparse
import os
import random
import socket
import traceback

import config.config
import pb_team11_pb2
from multiprocessing import Process, Manager

__author__ = 'Abhiram Sarja'

from dh_utils import calculate_dh_component


class team11_server:

    def __init__(self, server_host, server_port, online_clients):
        self.host = server_host
        self.port = server_port
        self.online_clients = online_clients
        self.server_socket = None
        self.BUFFER_SIZE = 4096
        self.request = pb_team11_pb2.Request()  # create protobuf Request message
        self.reply = pb_team11_pb2.Reply()      # create protobuf Reply message

    # Initialise the server socket as UDP
    def initialise_server_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))     # Bind to the port
        self.server_socket.listen()

        print("Server Initialized.. Server is left running..")

        while True:
            conn, address = self.server_socket.accept()
            print(f'New connection from ', str(address))

            if address:
                connection_proc = Process(target=self.process_connection, args=(conn, address, self.online_clients))
                connection_proc.start()

    # Adding username to the available-clients list
    def add_user_to_clients_list(self, username, address_information, online_clients):
        complete_url = str(address_information[0]) + ":" + str(address_information[1])
        online_clients[username] = complete_url

    def process_connection(self, conn, source, online_clients):

        # Server's DH component `b`
        b = random.randint(0, 10)

        while True:

            try:
                data = conn.recv(self.BUFFER_SIZE)
                if not data:
                    continue

                print("Received data...")

                self.request.ParseFromString(data)  # parse message
                print(self.request.version, self.request.seq_n)
                if self.request.version != 7:  # only accept version 7
                    continue

                # use same version and sequence number in the reply
                self.reply.version = self.request.version
                self.reply.seq_n = self.request.seq_n

                if self.request.type == pb_team11_pb2.Request.SIGNIN:  # Log-in request
                    self.add_user_to_clients_list(
                        username=self.request.payload,
                        address_information=source,
                        online_clients=online_clients
                    )

                    self.reply.payload = "Welcome to Network Security (in collaboration with the Team AUS) Chat Room! " \
                                         "(Successfully signed in!)\n\n " \
                                         "Type `list` to get all the online clients and `bye` to leave the chat room!"

                    self.reply.dh_component = pow(9, b) + calculate_dh_component(g=9, p=23, power=config.config.secure_storage[self.request.payload])
                    self.reply.u_number = os.urandom(32)
                    # temp = os.urandom(32)
                    # self.reply.u_number = int.from_bytes(temp, byteorder='little')

                if self.request.type == pb_team11_pb2.Request.LIST:
                    self.reply.payload = str(online_clients.keys())

                if self.request.type == pb_team11_pb2.Request.SEND:
                    destination_client = self.request.payload
                    self.reply.payload = str(online_clients[destination_client])

                if self.request.type == pb_team11_pb2.Request.BYE:
                    conn.close()
                    raise Exception('Client wants to leave the chat room!')

                conn.send(self.reply.SerializeToString())  # serialize response into string, send it & wait for the next message from the client

            except Exception as e:
                traceback.print_exception(e)
                print('[Server Exception]', str(e))
                del online_clients[self.request.payload]    # Remove the user from the list of online clients
                break


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--serverport", type=int, default=9090, required=True, help="Server's Port number is missing.")
    args = parser.parse_args()

    # Reading values from the arguments
    s_port = args.serverport

    # Maintaining shared information on clients
    manager = Manager()
    online_clients = manager.dict()

    try:
        server = team11_server(server_host="0.0.0.0", server_port=s_port, online_clients=online_clients)
        server.initialise_server_socket()

    except Exception as ex:
        print('Some internal error: ' + str(ex))
