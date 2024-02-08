import socket
import threading
from typing import Dict, Tuple, List, Optional, Pattern
import secrets
import re
from modules.SecurityToolkit import hash_data


class ChatServer:
    def __init__(self, host: str, port: int, bytesize: int=1024) -> None:
        # Configurations
        self.SERVER_HOST: str = host
        self.SERVER_PORT: int = port

        # Message byte size
        self.MESSAGE_BYTES: int = bytesize

        # Initialize the server socket
        self.server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.SERVER_HOST, self.SERVER_PORT))
        self.server.listen()
        
        # Dictionaries to store clients, rooms, and their information
        self.clients: Dict[socket.socket, Tuple[str, str]] = {} # stores clients nickname and room key - client: (nickname, room_key)
        self.rooms: Dict[str, List[Tuple[socket.socket, str]]] = {} # stores rooms clients and their nicknames - room_key: [(client,nickname)]
        self.room_passwords : Dict[str,str] = {} # stores hashed passwords for rooms - room_key: password
    
    
    # Function to blacklist clients for causing recursion errors
    def blacklisted(self, client:socket.socket) -> None:
        '''Blacklists clients for causing recursion errors'''

        while True:
            try:
                # Client cannot interact with rooms or any functionality
                client.recv(self.MESSAGE_BYTES).decode('utf-8')
                client.send('\nYou are currently blacklisted for sending an unusual amount of requests'.encode('utf-8'))

            except:
                # In case the client disconnects
                print(f'Client disconnected {client}')
                break


    # Function for users to set their nickname
    def enter_nickname(self, client: socket.socket, room_key: Optional[str] = None) -> str:
        ''' Function to get a unique nickname from the client using recursion '''
        
        try:
            # Ensure the client's name is safe
            MAX_NICKNAME_LEN: int = 16
            MIN_NICKNAME_LEN: int = 1

            # Get the client's nickname
            client.send('Enter your nickname (nickname must be between 1-16 characters and cannot contain spaces): '.encode('utf-8'))
            nickname: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')  # Receive the client's nickname decoded from bytes
            nickname: str = nickname.strip()  # Remove leading and trailing whitespaces

            # Input validation
            if nickname == '' or ' ' in nickname or len(nickname) < MIN_NICKNAME_LEN or len(nickname) > MAX_NICKNAME_LEN:
                client.send("\nERROR: Please enter a valid nickname between 1-16 characters with no spaces\n ".encode('utf-8'))
                return self.enter_nickname(client)

            nickname_taken: int = 0  # Flag to check if the nickname is already taken

            # If room_key flag is set, then check if nickname is already in the room
            if room_key:
                # Check if the nickname is already in use
                for room_clients in self.rooms[room_key]:
                    if room_clients[1].strip() == nickname:
                        client.send(f"\nERROR: Nickname '{nickname}' is already in use, please enter a different nickname\n ".encode('utf-8'))
                        nickname_taken += 1 # set flag to 1 if the nickname is already taken
                        return self.enter_nickname(client, room_key=room_key)

            # If the nickname is valid
            if nickname_taken == 0: # If nickname is 0 the nickname is not taken
                client.send(f'\nYour nickname is {nickname}'.encode('utf-8'))  # Send the nickname to the client
                return nickname
        except RecursionError: # Catch recursion errors and blacklist user from accessing any rooms
            client.send(f'\nRate limit exceeded, you are now blacklisted\n'.encode('utf-8'))
            print(f'\n(Blacklist) Unusual traffic coming from client: {client}')
            self.blacklisted(client)
    
    # Function which uses recursion to create a new room key
    def generate_room_key(self) -> str:
        ''' Uses recursion to generates a new random room key '''
        
        room_key: str = secrets.token_urlsafe(20)  # Generate a random room key
        if room_key in self.rooms.keys(): # ensure that the room key is unique
            return self.generate_room_key()
        return room_key
    
    # Function to allow password creation for new rooms
    def create_room_password(self, client:socket.socket, room_key:str) -> None:
        ''' Function to allow user to create a password for their room upon creation'''
        
        try:
            # create password validation mechanism
            password_validator: Pattern = r'(?=[A-Za-z-_@=+!?.,£$%^*/|()]*\d)(?=[A-Z-_@=+!?.,£$%^*/|()\d]*[a-z])(?=[a-z-_@=+!?.,£$%^*/|()\d]*[A-Z])[A-Za-z\d@=+!?.,£$%^*/|()_-]{8,20}$'
        
            # get the password from the client
            client.send('\nCreate a password for your room\nThe password must be 8-20 characters and contain at least:\nOne number, one capital letter, one lowercase letter and no spaces.\nSpecial characters allowed: @=+!?.,£$%^*/|()_-: '.encode('utf-8'))
            password: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')
            # allow client to re enter the password
            client.send('\nRe-enter the password: '.encode('utf-8'))
            re_password: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')
        
            # if password is valid then hash the password and store it 
            if re.match(password_validator,password):
                # check if re_password matches the password
                if re_password == password:
                    hashed_password: str = hash_data(password) # hash the password for safe storage
                    self.room_passwords[room_key] = hashed_password
                    client.send('\nThe password for the room has successfully been set'.encode('utf-8'))
                else:
                    client.send('\nError: The re-entered password does not match the original password for the room'.encode('utf-8'))
                    return self.create_room_password(client,room_key)
            else:
                client.send("\nError: Password must be 8-20 characters and contain at least:\nOne number, one capital letter, one lowercase letter and no spaces.\nSpecial characters allowed: @=+!?.,£$%^*/|()_-".encode('utf-8'))
                return self.create_room_password(client,room_key)
        except RecursionError: # Catch recursion errors and blacklist user from accessing any rooms
            client.send(f'\nRate limit exceeded, you are now blacklisted\n'.encode('utf-8'))
            print(f'\n(Blacklist) Unusual traffic coming from client: {client}')
            self.blacklisted(client)
    
    # Function to ensure user must enter the password to access a room
    def enter_room_password(self, client:socket.socket, room_key:str) -> bool:
        ''' Function to ensure user must enter the password to access a room '''
        try:
            client.send('\nEnter the password for the room: '.encode('utf-8'))
            entered_password: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')
            hashed_password: str = self.room_passwords[room_key]

            if hash_data(entered_password) == hashed_password:
                return True
            else:
                client.send('\nPassword incorrect'.encode('utf-8'))
                return False
        except RecursionError: # Catch recursion errors and blacklist user from accessing any rooms
            client.send(f'\nRate limit exceeded, you are now blacklisted\n'.encode('utf-8'))
            print(f'\n(Blacklist) Unusual traffic coming from client: {client}')
            self.blacklisted(client)

    # Function to allow user to join or create a room
    def room_handler(self, client: socket.socket) -> str:
        ''' Recursive function which acts as a full room handler to handle
            creating and joining rooms, 
    
            works by calling all functions associated to creating and joining rooms '''
        
        try:
            client.send('Enter 1 to join a room, Enter 2 to create a room: '.encode('utf-8'))
            option: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')
            option: str = option.strip()

            # Join a room
            if option == '1':
                # Get the entered room key from the client
                client.send('Enter room key: '.encode('utf-8'))
                room_key: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')
                room_key: str = room_key.strip()

                # Check if the room exists
                if room_key in self.rooms.keys():
                    # Ensure user knows the password for the room
                    if self.enter_room_password(client, room_key):
                        # Add client to the room
                        nickname: str = self.enter_nickname(client, room_key=room_key)
                        self.rooms[room_key].append((client, nickname))
                        self.clients[client] = (nickname, room_key)
                
                        client.send(f'\nYou have successfully joined the room\n'.encode('utf-8'))
                        return nickname
                    else:
                        return self.room_handler(client)
                else:
                    client.send('\nERROR: Invalid room key '.encode('utf-8'))
                    return self.room_handler(client) 

            # Create a room
            elif option == '2':
                room_key: str = self.generate_room_key()

                # Create a new room and add the client to it
                nickname: str = self.enter_nickname(client)
                self.create_room_password(client,room_key) # create password for the room
                self.rooms[room_key] = [(client, nickname)]
                self.clients[client] = (nickname, room_key)
                client.send(f'\nYou have successfully created and joined the room '.encode('utf-8'))
                client.send(
                    f'\nYour room key is: {room_key}\nIf there are no users left in the room then the room will be deleted\n\n'.encode(
                        'utf-8'))
                return nickname

            else:
                client.send('\nERROR: Please input a valid option'.encode('utf-8'))
            return self.room_handler(client)
        except RecursionError: # Catch recursion errors and blacklist user from accessing any rooms
            client.send(f'\nRate limit exceeded, you are now blacklisted\n'.encode('utf-8'))
            print(f'\n(Blacklist) Unusual traffic coming from client: {client}')
            self.blacklisted(client)

    
    # Handle sending messages to the clients room
    def broadcast_message(self, client: socket.socket, message: str, nickname: Optional[str] = None) -> None:
        ''' Function to broadcast a message to all clients in the room '''
        
        # Get client room key
        client_information: Tuple[str, str] = self.clients[client]
        room_key: str = client_information[1]
        room: List[Tuple[socket.socket, str]] = self.rooms[room_key]
        message = message.strip()

        if nickname:
            # Broadcast the message with prefix 'nickname: ' if nickname flag is set
            full_message: bytes = f'{nickname}: {message}'.encode('utf-8')
            for all_clients in room:
                all_clients[0].send(full_message)
        else:
            # Broadcast the message
            full_message: bytes = f'{message}'.encode('utf-8')
            for all_clients in room:
                all_clients[0].send(full_message)

    # Handle communication between clients
    def receive_and_send(self, client: socket.socket) -> broadcast_message:
        ''' Function to receive a message from a client then
            call the broadcast_message function to send the message'''
        
        nickname: str = self.clients[client][0]
        message: str = client.recv(self.MESSAGE_BYTES).decode('utf-8')  # Receive message from client
        self.broadcast_message(client, message, nickname=nickname)  # Broadcast the message to all clients


    # Handling client disconnection
    def disconnect(self, client: socket.socket) -> str:
        ''' Function to handle disconnection from the server '''
    
        # Get client information and remove it
        client_information: Tuple[str, str] = self.clients[client]
        nickname: str = client_information[0]
        room_key: str = client_information[1]

        self.rooms[room_key].remove((client, nickname))  # Remove client info from room
        self.broadcast_message(client, f'{nickname} has left the chat') # Broadcast that the client has left the chat
        self.clients.pop(client)  # Remove client info from clients dictionary
        client.close()  # Close connection with the client

        # If the room is empty, delete the room 
        if len(self.rooms[room_key]) == 0:
            self.rooms.pop(room_key) # delete the room
            self.room_passwords.pop(room_key) # delete the rooms password

        return f'{client} A user has disconnected from the server, their nickname was {nickname}'

    
    # Handle client interactions with the server
    def handle_client(self, client: socket.socket) -> receive_and_send:
        ''' Function to handle client interactions with the server
             
            This includes the client sending messages and disconnecting
            from the server'''

        while True:
            try:
                self.receive_and_send(client)

            except:
                # In case the client disconnects
                print(self.disconnect(client))
                break
 

    # Handle client joining a room
    def client_setup(self, client:socket.socket, address:Tuple[str:int]) -> handle_client:
        ''' Function to handle client setting everything up to create or join a chat '''

        try: 
            # Create or join a room for the client
            client.send(f'\nSuccessfully connected to the server\n'.encode('utf8'))
            nickname: str = self.room_handler(client)

            # Broadcast that the client has joined the chat
            print(f'\nConnected with {str(address)}, their nickname is: {nickname}')
            self.broadcast_message(client, f'{nickname} has joined the chat')
            self.handle_client(client)
        except RecursionError: # Catch recursion errors and blacklist user from accessing any rooms
            print(f'\n(Blacklist) Unusual traffic coming from client: {client} with IP address {address[0]} on port {address[1]}')
            client.send(f'\nRate limit exceeded, you are now blacklisted\n'.encode('utf-8'))
            self.blacklisted(client)
        except Exception as e:
            print(f'\nError: exception occured {e}, clients information is - IP: {address[0]} port: {address[1]}')

    # Handle client connection
    def chat_connect(self) -> client_setup:
        ''' Function to handle connecting to the chat '''

        while True:
            # Accept a connection request
            client, address = self.server.accept()

            # Create a new thread for the client
            thread = threading.Thread(target=self.client_setup, args=(client, address), daemon=True)
            thread.start()
                

    # Start the server
    def start_server(self) -> chat_connect:
        
        ''' Function to start the server '''
        print('Server is successfully running, any events will show here...')
        try:
            self.chat_connect()
        finally:
            # Close the server socket
            self.server.close()


# Start the application
if __name__ == '__main__':
    chat_server = ChatServer('127.0.0.1', 55555)
    chat_server.start_server()
