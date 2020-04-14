import socket
import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64
from cryptography.hazmat.primitives import serialization
import sys
# import errno
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = dict({})
# store data with username
usrname_data = dict({})
# dict of clients and their public keys
clients_keys = dict({})
# keep track of the secure groups.
secure_groups = dict({})

print(f'Listening for connections on {IP}:{PORT}...')

# handle public keys it recieves:


def check_public_key(msg, username):
    # Handles message receiving
    if '-----BEGIN PUBLIC KEY-----' in msg.decode('utf-8'):
        # load the key form pem format data
        key = load_pem_public_key(msg, backend=default_backend())
        clients_keys[username] = key
        return True  # this is a public key so there is no need to clog up the messaging
    return False  # this is just a regular message and can simply be forwarded.


def remove_from_chat(message, username):
    return False

# generate Fernet Key and send to all users of a secure room:


def send_Fernet_keys(chat_id):
    # key has been generated. a new one is generated every time a new member is added or an old one is removed
    print("Createing new key")
    print(chat_id)
    fkey = Fernet.generate_key()
    list_of_members = secure_groups.get(chat_id)
    print(list_of_members)
    for member in list_of_members:
        pub_key = clients_keys.get(member)
        client_socket = usrname_data.get(member)
        encrypted_key = pub_key.encrypt(fkey, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))  # we have the key encrypted as bytes.
        alert_message = ";added to chat room:"
        # add the chatname to the message
        alert_message = alert_message + chat_id
        msg = alert_message.encode('utf-8')
        # create header for message
        username = member.encode('utf-8')
        username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
        message_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
        key_header = f"{len(encrypted_key):<{HEADER_LENGTH}}".encode('utf-8')
        fullmessage = username_header + username + \
            message_header + msg + key_header + encrypted_key
        client_socket.send(fullmessage)
        # send message

# remove user


def send_removal_message(username, chat):
    client_socket = usrname_data.get(username)
    alert_message = "Removed from: "
    alert_message = alert_message + chat
    msg = alert_message.encode('utf-8')
    # create header for message
    username = "server".encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    message_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    fullmessage = username_header + username + \
        message_header + msg
    client_socket.send(fullmessage)


def remove_from_chat(message, username):
    # format  = command:chat:username
    if "remove_from_group" in message:
        # check is that user part of the group
        chatroom = message.split(': ')[1]
        removed_user = message.split(': ')[2]
        print(chatroom)
        if (chatroom) in secure_groups.keys():
            # add user to chat
            guestlist = secure_groups.get(chatroom)
            guestlist.remove(removed_user)
            print(guestlist)
            # send new key to users
            send_Fernet_keys(chatroom)
            send_removal_message(removed_user, chatroom)
            return True
        else:
            return False
    else:
        return False

# add user


def add_to_chat(message, username):
    # format  = command:chat:username
    if "add_to_group" in message:
        # check is that user part of the group
        chatroom = message.split(': ')[1]
        added_user = message.split(': ')[2]
        print(chatroom)
        if (chatroom) in secure_groups.keys():
            # add user to chat
            guestlist = secure_groups.get(chatroom)
            guestlist[len(guestlist):] = [added_user]
            print(guestlist)
            secure_groups[chatroom] = guestlist
            # send new key to users
            send_Fernet_keys(chatroom)
            return True
        else:
            return False
    else:
        return False

# see if the user is creating a secure chat room


def check_secure_chat_room(message, username):
    if 'create private chat' in message:
        # create a list of secure users for that user.
        name_users = message.split(": ")[1]
        split_name_of_chat = name_users.split("; ")
        name_of_chat = split_name_of_chat[0]  # get the name of the chat room
        # username and chatroom name are used to identify the room.
        print(name_of_chat)
        chat_id = (name_of_chat)
        secure_clients = split_name_of_chat[1].split(
            ", ")  # get the list of users
        # add to list of secure chat rooms.
        secure_clients.append(username)
        secure_groups[chat_id] = (secure_clients)  # created a new secure group
        send_Fernet_keys(chat_id)
        return True
    else:
        return False

# handle incomming messages


def receive_message(client_socket):
    try:
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False
        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}
    except:
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        return False


while True:
    read_sockets, _, exception_sockets = select.select(
        sockets_list, [], sockets_list)
    # Iterate over notified sockets
    for notified_socket in read_sockets:
        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            user = receive_message(client_socket)
            if user is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user
            usrname_data[user['data'].decode('utf-8')] = client_socket
            print('Accepted new connection from {}:{}, username: {}'.format(
                *client_address, user['data'].decode('utf-8')))

        # Else existing socket is sending a message
        else:
            # Receive message
            message = receive_message(notified_socket)
            # If False, client disconnected, cleanup
            if message is False:
                print('Closed connection from: {}'.format(
                    clients[notified_socket]['data'].decode('utf-8')))
                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)
                # Remove from our list of users
                del clients[notified_socket]
                continue
            # Get user by notified socket, so we will know who sent the message
            user = clients[notified_socket]
            # check did we receive a public key
            if check_public_key(
                    message['data'], user["data"].decode("utf-8")) == True:  # check is it a change in public keys
                print(
                    f'Recieved a public key from {user["data"].decode("utf-8")}')
            elif check_secure_chat_room(message['data'].decode('utf-8'), user["data"].decode("utf-8")) == True:
                # check if user is creating a secure chat room
                print('Groupchat was successfully created')
            # check has a new user been added
            elif add_to_chat(message['data'].decode('utf-8'), user["data"].decode("utf-8")) == True:
                print('Added to user')
            elif remove_from_chat(message['data'].decode('utf-8'), user["data"].decode("utf-8")) == True:
                print("Removed user")
            else:
                print(
                    f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')
                # Iterate over connected clients and broadcast message
                for client_socket in clients:
                    # But don't sent it to sender
                    if client_socket != notified_socket:
                        # Send user and message (both with their headers)
                        # We are reusing here message header sent by sender, and saved username header send by user when he connected
                        client_socket.send(
                            user['header'] + user['data'] + message['header'] + message['data'])
                for notified_socket in exception_sockets:
                    # Remove from list for socket.socket()
                    sockets_list.remove(notified_socket)
                    # Remove from our list of users
                    del clients[notified_socket]
