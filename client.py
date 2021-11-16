#!/usr/bin/env python3

import socket
import sys
from struct import pack, unpack
import numpy as np

VALID_COMMANDS = ["rsaa", "vsaa", "rsag", "vsag"]

HOST = sys.argv[1]
PORT = int(sys.argv[2])
COMMAND_NAME = sys.argv[3]
COMMAND_ARGS = sys.argv[4:]

if COMMAND_NAME not in VALID_COMMANDS:
    raise Exception("Invalid command.")

if COMMAND_NAME == "rsaa" and len(sys.argv) != 6:
    raise Exception("Invalid input format.")

if COMMAND_NAME == "vsaa" and len(sys.argv) != 5:
    raise Exception("Invalid input format.")

if COMMAND_NAME == "rsag":
    saa_quantity = int(COMMAND_ARGS[0])
    if len(sys.argv) != (5 + saa_quantity):
        raise Exception("Invalid input format.")


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


def colective_auth():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        flag = pack("!h", 5)
        saa_quantity_raw = int(COMMAND_ARGS[0])
        saa_quantity = pack("!h", saa_quantity_raw)
        raw_saa_list = COMMAND_ARGS[1:]

        saa_list = []
        for unsplitted_saa in raw_saa_list:
            saa = unsplitted_saa.split(":")

            registration_raw = saa[0]
            identifier_raw = saa[1]
            auth_code_raw = saa[2]

            registration = pack("!i", int(registration_raw))
            identifier = pack("!i", int(identifier_raw))
            auth_code = pack("!64s", auth_code_raw.encode("utf-8"))

            saa_list.append(registration)
            saa_list.append(identifier)
            saa_list.append(auth_code)

        message = flag + saa_quantity

        for saa in saa_list:
            message += saa

        response_pattern = "!hh"
        for i in range(saa_quantity_raw):
            response_pattern += "ii64s"
        response_pattern += "64s"

        socket_instance.sendall(message)

        received_data = np.asarray(
            unpack(response_pattern, socket_instance.recv(1024))).tolist()
        auth_code = received_data.pop().decode()

        received_data = received_data[2:]

        array_response = []
        for item in np.array_split(received_data, saa_quantity_raw):
            decoded_item = []
            for sub_item in item:
                decoded_item.append(sub_item.decode())

            array_response += [(":").join(decoded_item)]

        response = ("+").join(array_response)
        response += "+" + auth_code

        print(response)


def colective_validate():
    print("a")


if COMMAND_NAME == "rsaa":
    individual_auth()
elif COMMAND_NAME == "vsaa":
    individual_validate()
elif COMMAND_NAME == "rsag":
    colective_auth()
elif COMMAND_NAME == "vsag":
    individual_validate()
