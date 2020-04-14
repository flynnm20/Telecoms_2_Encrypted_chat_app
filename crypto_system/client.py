import socket
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
from cryptography.hazmat.primitives import serialization
import sys
# import errno
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# GLOABALS
# chats that you have keys for.
keys = dict({})  # chatname:key

# blocked users
block_users = ()  # list of blocked users by username.

HEADER_LENGTH = 10

# group_chats you are a part of.
group_chats = []

IP = "127.0.0.1"
PORT = 1234


# generate new rsa keys for symmetric key transfer
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    return private_key

# encrypt a given message


def encrypt_message(a_message, publickey):
    encrypted_msg = publickey.encrypt(a_message, 32)[0]
    # base64 encoded strings are database friendly
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

# decrypt a message


def decrypt_message(encoded_encrypted_msg, privatekey):
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg


def sendMessage(message):
    # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message)


# initialise a new user
private_key = generate_keys()  # generate key
public_key = private_key.public_key()  # get the public key
pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                              format=serialization.PublicFormat.SubjectPublicKeyInfo)  # change public key to a string for sending.
my_username = input("Username: ")
username = my_username
# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
my_username = my_username.encode('utf-8')
my_username_header = f"{len(my_username):<{HEADER_LENGTH}}".encode('utf-8')
username_header = my_username
client_socket.send(my_username_header + my_username)
# send rsa token.
sendMessage(pem)

while True:
    secure_chat = False
    chat = ""
    # Wait for user to input a message
    message = input(f'{my_username} > ')

    # If message is not empty - send it
    if message:
        if 'secure' in message:
            chatroom = message.split(": ")[1]
            secure_chat = True
            fernet_key = keys.get(chatroom)
            print(f'You have entered secure chatroom {chatroom}')
            chatroom = chatroom + ">-"
            message = input(f'{my_username} : {chatroom}> ')
            message = message.encode('utf-8')
            chatroom = chatroom.encode('utf-8')
            message = chatroom + fernet_key.encrypt(message)
        else:
            message = message.encode('utf-8')
        sendMessage(message)
    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                print('Connection closed by the server')
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            # insert a pice to read keys
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length).decode('utf-8')
            if ';added to chat room:' in message:  # recieved a key header
                key_header = client_socket.recv(HEADER_LENGTH)
                key_len = int(key_header.decode('utf-8').strip())
                chatname = message.split(':')[1]  # got the chatname
                group_chats.append(chatname)
                key_cipher = client_socket.recv(key_len)
                key = Fernet(private_key.decrypt(key_cipher, padding.OAEP(mgf=padding.MGF1(
                    algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))  # now have been added to a group chat
                keys[chatname] = key
                print(
                    f'You have been added to groupchat {chatname}')
            elif 'Removed from' in message:
                chat_removed = message.split(": ")[1]
                del keys[chat_removed]
            elif ">-" in message:
                chatroom = message.split(">-")[0]
                if chatroom in keys.keys():
                    key = keys.get(chatroom)
                    message = message.split(">-")[1]
                    message = message.encode('utf-8')
                    message_decrypt = key.decrypt(message)
                    message_decrypt = message_decrypt.decode('utf-8')
                    print(
                        f'{username} > {chatroom} > {message_decrypt}')
                else:
                    print(f'{username} > {message}')
            else:
                print(f'{username} > {message}')
    except IOError as e:
        # print(e)
        # sys.exit()
        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print(e)
        sys.exit()
