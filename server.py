import socket
import json
import threading
import time
from cryptography.fernet import Fernet
import hashlib

class Server:
    def __init__(self, host='localhost', port=5000):
        self.users = {}  # Now includes location data
        self.friends = {}  # {username: [friend1, friend2, ...]}
        self.friend_requests = {}  # {username: [pending_requests]}
        self.locations = {}  # {username: (x, y)}
        self.messages = {}  # {username: [messages]}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))

    def start(self):
        self.sock.listen()
        print("Server started on localhost:5000")
        while True:
            conn, addr = self.sock.accept()
            print(f"New connection from {addr}")
            thread = threading.Thread(target=self.handle_client, args=(conn,))
            thread.start()

    def handle_client(self, conn):
        try:
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break
                print(f"Received: {data}")
                msg = json.loads(data)
                response = self.process_message(msg)
                print(f"Sending: {response}")
                conn.send(json.dumps(response).encode())
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

    def process_message(self, msg):
        try:
            action = msg.get('action')
            if action == 'register':
                return self.register_user(msg['username'], msg['password'])
            elif action == 'login':
                return self.login_user(msg['username'], msg['password'])
            elif action == 'update_location':
                return self.update_location(msg['username'], msg['x'], msg['y'])
            elif action == 'get_cell':
                return self.get_cell(msg['username'])
            elif action == 'send_friend_request':
                return self.send_friend_request(msg['from_user'], msg['to_user'])
            elif action == 'accept_friend_request':
                return self.accept_friend_request(msg['from_user'], msg['to_user'])
            elif action == 'get_friend_requests':
                return self.get_friend_requests(msg['username'])
            elif action == 'get_friends':
                return self.get_friends(msg['username'])
            elif action == 'send_message':
                return self.send_message(msg['from_user'], msg['to_user'], msg['content'])
            elif action == 'get_messages':
                return self.get_messages(msg['username'])
            return {'status': 'error', 'message': 'Invalid action'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def register_user(self, username, password):
        if username in self.users:
            return {'status': 'error', 'message': 'Username already exists'}
        
        self.users[username] = {
            'password': hashlib.sha256(password.encode()).hexdigest(),
            'key': Fernet.generate_key()
        }
        self.friends[username] = []
        self.friend_requests[username] = []
        self.messages[username] = []
        self.locations[username] = (0, 0)  # Default location
        return {'status': 'success', 'message': 'Registration successful'}

    def login_user(self, username, password):
        if username not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        
        if self.users[username]['password'] != hashlib.sha256(password.encode()).hexdigest():
            return {'status': 'error', 'message': 'Invalid password'}
        
        return {'status': 'success', 'message': 'Login successful'}

    def update_location(self, username, x, y):
        if username not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        
        if not (0 <= x <= 99999 and 0 <= y <= 99999):
            return {'status': 'error', 'message': 'Coordinates out of bounds'}
            
        self.locations[username] = (x, y)
        return {'status': 'success', 'message': 'Location updated'}

    def get_cell(self, username):
        if username not in self.locations:
            return {'status': 'error', 'message': 'User location not found'}
        
        x, y = self.locations[username]
        cell_x = x // 1000
        cell_y = y // 1000
        return {'status': 'success', 'cell': (cell_x, cell_y)}

    def send_friend_request(self, from_user, to_user):
        if from_user not in self.users or to_user not in self.users:
            return {'status': 'error', 'message': 'User not found'}
            
        if to_user in self.friends[from_user]:
            return {'status': 'error', 'message': 'Already friends'}
            
        if from_user in self.friend_requests[to_user]:
            return {'status': 'error', 'message': 'Friend request already sent'}
            
        self.friend_requests[to_user].append(from_user)
        return {'status': 'success', 'message': 'Friend request sent'}

    def accept_friend_request(self, from_user, to_user):
        if from_user not in self.users or to_user not in self.users:
            return {'status': 'error', 'message': 'User not found'}
            
        if from_user not in self.friend_requests[to_user]:
            return {'status': 'error', 'message': 'No friend request found'}
            
        self.friend_requests[to_user].remove(from_user)
        self.friends[to_user].append(from_user)
        self.friends[from_user].append(to_user)
        return {'status': 'success', 'message': 'Friend request accepted'}

    def get_friend_requests(self, username):
        if username not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        return {'status': 'success', 'requests': self.friend_requests[username]}

    def get_friends(self, username):
        if username not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        return {'status': 'success', 'friends': self.friends[username]}

    def send_message(self, from_user, to_user, content):
        if from_user not in self.users or to_user not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        if to_user not in self.friends[from_user]:
            return {'status': 'error', 'message': 'Not friends with user'}
        
        message = {
            'from': from_user,
            'content': content,
            'timestamp': time.time()
        }
        self.messages[to_user].append(message)
        return {'status': 'success', 'message': 'Message sent'}

    def get_messages(self, username):
        if username not in self.users:
            return {'status': 'error', 'message': 'User not found'}
        messages = self.messages[username]
        self.messages[username] = []
        return {'status': 'success', 'messages': messages}

if __name__ == '__main__':
    server = Server()
    server.start()