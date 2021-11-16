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

if COMMAND_NAME == "vsaa" and len(sys.argv) != 5:
    raise Exception("Invalid input format.")


def check_error(response):
    if(len(response) == 4):
        unpacked_error = unpack("!hh", response)[1]

        if(unpacked_error == 1):
            raise Exception("Invalid message code.")
        elif(unpacked_error == 2):
            raise Exception("Incorrect message length.")
        elif(unpacked_error == 3):
            raise Exception("Invalid parameter.")
        elif(unpacked_error == 4):
            raise Exception("Invalid single token.")
        elif(unpacked_error == 5):
            raise Exception("ASCII decode error.")


def individual_auth():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        flag = pack("!h", 1)
        registration = pack("!i", int(COMMAND_ARGS[0]))
        identifier = pack("!i", int(COMMAND_ARGS[1]))
        message = flag + registration + identifier

        socket_instance.sendall(message)

        socket_response = socket_instance.recv(1024)
        check_error(socket_response)

        received_data = unpack("!hii64s", socket_response)

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

        socket_response = socket_instance.recv(1024)
        check_error(socket_response)

        received_data = unpack("!hii64sb", socket_response)

        validation_result = received_data[-1]

        print(validation_result)


def collective_auth():
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

        socket_response = socket_instance.recv(1024)
        check_error(socket_response)

        received_data = np.asarray(
            unpack(response_pattern, socket_response)).tolist()
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


def collective_validate():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_instance:
        socket_instance.connect((HOST, PORT))

        args_list = COMMAND_ARGS[0].split("+")
        collective_auth_code_raw = args_list.pop()

        flag = pack("!h", 7)
        validation_size = pack("!h", len(args_list))
        message = flag + validation_size

        for arg in args_list:
            saa = arg.split(":")

            registration_raw = saa[0]
            identifier_raw = saa[1]
            individual_auth_code_raw = saa[2]

            registration = pack("!i", int(registration_raw))
            identifier = pack("!i", int(identifier_raw))
            individual_auth_code = pack(
                "!64s", individual_auth_code_raw.encode("utf-8"))

            message += registration + identifier + individual_auth_code

        collective_auth_code = pack(
            "!64s", collective_auth_code_raw.encode("utf-8"))
        message += collective_auth_code

        socket_instance.sendall(message)

        response_pattern = "!hh"
        for i in range(len(args_list)):
            response_pattern += "ii64s"
        response_pattern += "64sb"

        socket_response = socket_instance.recv(1024)
        check_error(socket_response)
        received_data = unpack(response_pattern, socket_response)

        validation_result = received_data[-1]

        print(validation_result)


if COMMAND_NAME == "rsaa":
    individual_auth()
elif COMMAND_NAME == "vsaa":
    individual_validate()
elif COMMAND_NAME == "rsag":
    collective_auth()
elif COMMAND_NAME == "vsag":
    collective_validate()
