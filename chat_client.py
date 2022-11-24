#!/usr/bin/env python3
import argparse

import pb_team11_pb2
import socket
import select
import sys

__author__ = 'Abhiram Sarja'


# Read the user console input while listening to the non-blocked socket - with 0.5 seconds interval
def read_input():
    i, o, e = select.select([sys.stdin], [], [], 0.5)
    for s in i:
        if s == sys.stdin:
            input_text = sys.stdin.readline()
            return input_text

    return False


class team11_client:

    def __init__(self, server_ip, server_port, username):
        self.server_host = server_ip
        self.server_port = server_port
        self.username = username
        self.BUFFER_SIZE = 4096
        self.client_socket = None
        self.request = pb_team11_pb2.Request()      # Protobuf Request message
        self.reply = pb_team11_pb2.Reply()          # Protobuf Reply message

    def initialise_client_socket(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.setblocking(False)
        client_socket.settimeout(2)

        self.client_socket = client_socket      # Assign this socket to client socket

    # auto-execute signin command upon client start
    def client_signin(self, seq_n):

        self.request.version = 7
        self.request.seq_n = seq_n  # set sequence number
        self.request.type = pb_team11_pb2.Request.SIGNIN
        self.request.payload = self.username

        self.client_socket.send(self.request.SerializeToString())  # serialize message to string & send it to server

    def client_processing(self):
        # Initialise the client before doing anything
        self.initialise_client_socket()

        self.client_socket.connect((self.server_host, self.server_port))  # connect to server
        # self.request.version = 7

        request_number = 0      # Initialise the sequence number to 0

        # Auto signin
        self.client_signin(seq_n=request_number)
        request_number += 1

        while True:
            exit_flag = False
            try:
                incoming_message = self.client_socket.recv(self.BUFFER_SIZE)
                self.reply.ParseFromString(incoming_message)        # parse response message

                print("Received data > (", self.reply.version, self.reply.seq_n, ") ", self.reply.payload)

            except socket.error:
                pass

            user_input = read_input()
            if user_input:
                try:
                    if user_input.strip().lower() == 'list':
                        self.request.type = pb_team11_pb2.Request.LIST
                    elif user_input.strip().lower() == 'bye':
                        self.request.type = pb_team11_pb2.Request.BYE
                        self.request.payload = self.username
                        exit_flag = True
                    else:
                        print('Unknown command..')
                        continue

                    self.request.seq_n = request_number  # set sequence number
                    self.client_socket.send(self.request.SerializeToString())   # serialize message to string & send it the server
                    request_number += 1     # Increment the sequence number

                    if exit_flag:
                        raise Exception('Client wants to leave the chat room!')

                except Exception as ex:
                    print('Some internal error - ' + str(ex))
                    self.client_socket.close()
                    break


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", type=str, required=True, help="Username is required. It is the unique name that you identify yourself with.")
    parser.add_argument("-sip", "--serverip", type=str, required=True, default="127.0.0.1", help="Server IP is required. Please reach out to system admin if you do not know the Server IP Address.")
    parser.add_argument("-sp", "--serverport", type=int, required=True, default=5050, help="Server's Port number is missing.")
    args = parser.parse_args()

    # Reading values from the arguments
    username = args.username
    server_ip = args.serverip
    server_port = args.serverport

    client = team11_client(server_ip=server_ip, server_port=server_port, username=username)
    client.client_processing()
