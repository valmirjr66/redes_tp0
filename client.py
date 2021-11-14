#!/usr/bin/env python3

import socket
import sys
from struct import pack, unpack

HOST = sys.argv[1]
PORT = int(sys.argv[2])
COMMAND_NAME = sys.argv[3]
COMMAND_ARG_1 = sys.argv[4]
COMMAND_ARG_2 = sys.argv[5]


def individual_auth():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        flag = pack("!h", 1)
        registration = pack("!i", int(COMMAND_ARG_1))
        identifier = pack("!i", int(COMMAND_ARG_2))
        message = flag + registration + identifier

        socket_instance.sendall(message)

        received_data = socket_instance.recv(1024)

        print(unpack("!hii64s", received_data))

        socket_instance.close()


if COMMAND_NAME == "rsaa":
    individual_auth()
