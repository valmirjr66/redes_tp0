#!/usr/bin/env python3

import socket
import sys
from struct import pack, unpack

VALID_COMMANDS = ["rsaa", "vsaa", "rsag", "vsag"]

HOST = sys.argv[1]
PORT = int(sys.argv[2])
COMMAND_NAME = sys.argv[3]
COMMAND_ARGS = sys.argv[4:]

if COMMAND_NAME == "rsaa" and len(sys.argv) < 6:
    raise Exception("Invalid input format.")

if COMMAND_NAME not in VALID_COMMANDS:
    raise Exception("Invalid command.")


def individual_auth():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        flag = pack("!h", 1)
        registration = pack("!i", int(COMMAND_ARGS[0]))
        identifier = pack("!i", int(COMMAND_ARGS[1]))
        message = flag + registration + identifier

        socket_instance.sendall(message)

        received_data = unpack("!hii64s", socket_instance.recv(1024))

        auth_code = received_data[3].decode()

        received_data = [str(data) for data in received_data[0:3]]
        received_data.append(auth_code)

        response = (":").join(received_data[1:])
        print(response)

        socket_instance.close()


def individual_validate():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        saa = COMMAND_ARGS[0].split(":")

        registration_raw = saa[0]
        identifier_raw = saa[1]
        auth_code_raw = saa[2]

        flag = pack("!h", 3)
        registration = pack("!i", int(registration_raw))
        identifier = pack("!i", int(identifier_raw))
        auth_code = pack("!64s", auth_code_raw.encode("utf-8"))
        message = flag + registration + identifier + auth_code

        socket_instance.sendall(message)

        received_data = unpack("!hii64sb", socket_instance.recv(1024))

        validation_result = received_data[4]

        print(validation_result)

        socket_instance.close()


if COMMAND_NAME == "rsaa":
    individual_auth()
elif COMMAND_NAME == "vsaa":
    individual_validate()
