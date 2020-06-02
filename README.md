# Telecoms_2_Encrypted_chat_app
How to run:
Run the server file first. The serversocket is set to 1234. The ip of the server is set to localhost.
The server terminal will keep track of what is happening and handle any special commands that are entered.

Run client next. Enter the name you wish to use. You should see the persons name aooear on the server terminal.
The Server should also recieve a public key when a new user connects.
You must press enter in order to recieve any messages in the client.

Creating a chat room:
When a user wants to create a secure chat they type in: “create private chat: chat_name; usertoadd1, usertoadd2…” The server will receive this message and using the public keys of all users that the creator wishes to add send an encrypted Fernet key to all added users. This key is then decrypted using each users' private key and stored in a dictionary of keys for chats they are a member of.
Sending a secure message
Once a user has been added they may type “secure: chatroom_name” hit enter then type in a message they want to send securely to chatroom_name. The ciphertext can be observed from the server terminal and will be received and deciphered by all members of the chat while non-members will receive ciphertext. 
Adding a user to the secure chat:
To add a user to a chat you must be a member of that chat. If you are type “add_to_group: group_name: userToAdd” a new Fernet key will be generated and send it to all members of the chat again. 
Removing a user:
If a user wants to remove a user the must type “remove_from_group: group_name: userToRemove” the user will be removed from the group chat and a new key will be sent to all current members.
Note: Make sure to press enter after every command/update in all user terminals to keep everything up to date.  It can lead to errors with clients having the wrong keys for things. If a client attempts to access a chat which they haven’t been added to they will be immediately kicked from the server.
