import socket
import threading
import json
import os
import time
from base64 import b64encode
from argon2 import PasswordHasher
from threading import RLock

ph = PasswordHasher()

SERVER = "127.0.0.1"
PORT = 65432

# ----- Data Classes -----


class ClientSession:
    def __init__(self, connection, username, public_key=None):
        self.connection = connection
        self.username = username
        self.public_key = public_key
        self.session_key = os.urandom(32)
        self.last_activity = time.time()


class PendingRequest:
    def __init__(self, from_user, to_user):
        self.from_user = from_user
        self.to_user = to_user
        self.timestamp = time.time()


class ServerState:
    def __init__(self, users_file="users.txt", friends_file="friends.txt"):
        self.users_file = users_file
        self.friends_file = friends_file

        # Shared resources
        self.users = {}            # username -> hashed_password
        self.friends = {}          # username -> list of friends
        self.clients = {}          # username -> ClientSession
        self.pending_requests = {} # username -> list of PendingRequest
        self.message_queues = {}   # username -> list of messages

        # Use RLock to allow nested acquisitions
        self.users_lock = RLock()
        self.friends_lock = RLock()
        self.clients_lock = RLock()
        self.pending_requests_lock = RLock()
        self.message_queues_lock = RLock()

        # Documented lock order: users_lock -> friends_lock -> clients_lock -> pending_requests_lock -> message_queues_lock
        self.lock_order = {
            'users_lock': 1,
            'friends_lock': 2,
            'clients_lock': 3,
            'pending_requests_lock': 4,
            'message_queues_lock': 5
        }

        self.load_all_data()

    def load_all_data(self):
        self.load_users()
        self.load_friends()

    def load_users(self):
        with self.users_lock:
            self.users = {}
            if os.path.exists(self.users_file):
                try:
                    with open(self.users_file, "r") as f:
                        # Expecting JSON format for atomicity
                        self.users = json.load(f)
                except Exception as e:
                    print(f"Error loading users: {e}")
                    self.users = {}
    def load_friends(self):
        with self.friends_lock:
            self.friends = {}
            if os.path.exists(self.friends_file):
                try:
                    with open(self.friends_file, "r") as f:
                        self.friends = json.load(f)
                except Exception as e:
                    print(f"Error loading friends: {e}")

    def _save_data_atomic(self, filename, data):
        temp_file = filename + ".tmp"
        try:
            with open(temp_file, "w") as f:
                json.dump(data, f)
            os.replace(temp_file, filename)
        except Exception as e:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            print(f"Error saving {filename}: {e}")

    def save_users(self):
        with self.users_lock:
            self._save_data_atomic(self.users_file, self.users)

    def save_friends(self):
        with self.friends_lock:
            self._save_data_atomic(self.friends_file, self.friends)

    # Client session operations
    def add_client(self, username, session):
        with self.clients_lock:
            self.clients[username] = session

    def remove_client(self, username):
        with self.clients_lock:
            if username in self.clients:
                try:
                    self.clients[username].connection.close()
                except Exception as e:
                    print(f"Error closing connection for {username}: {e}")
                del self.clients[username]

    def get_client(self, username):
        with self.clients_lock:
            return self.clients.get(username)

    def handle_connection_error(self, username):
        with self.clients_lock:
            if username in self.clients:
                try:
                    self.clients[username].connection.close()
                except Exception:
                    pass
                del self.clients[username]
                print(f"Handled connection error for {username}")

    def handle_get_public_key(self, message):
        target = message["target"]
        with self.users_lock:
            user_data = self.users.get(target)
            if user_data and "public_key" in user_data:
                return {
                    "type": "public_key_response",
                    "public_key": user_data["public_key"],
                    "key_created": user_data["key_created"]
                }
            return {"type": "error", "message": "Public key not found"}

    # Pending requests
    def add_pending_request(self, to_user, request):
        with self.pending_requests_lock:
            if to_user not in self.pending_requests:
                self.pending_requests[to_user] = []
            self.pending_requests[to_user].append(request)

    def remove_pending_request(self, to_user, from_user):
        with self.pending_requests_lock:
            if to_user in self.pending_requests:
                self.pending_requests[to_user] = [
                    r for r in self.pending_requests[to_user] if r.from_user != from_user
                ]

    # Message queue operations
    def add_message(self, username, message):
        with self.message_queues_lock:
            if username not in self.message_queues:
                self.message_queues[username] = []
            self.message_queues[username].append(message)

    def get_messages(self, username):
        with self.message_queues_lock:
            messages = self.message_queues.get(username, [])
            self.message_queues[username] = []
            return messages

# ----- Client Handler -----

def handle_client(conn, addr, server_state: ServerState):
    print(f"Connected by {addr}")
    username = None
    try:
        while True:
            data = conn.recv(4096).decode("utf-8")
            if not data:
                break  # Connection closed by client

            try:
                message = json.loads(data)
                print(f"Received: {message}")
                message_type = message.get("type")

                if message_type == "register":
                    username = message["username"]
                    password = message["password"]
                    identity_pubkey = message["identity_public_key"]
                    key_created = message.get("key_created", int(time.time()))

                    with server_state.users_lock:
                        if username in server_state.users:
                            response = {"type": "registration_failed", "message": "Username already exists."}
                        else:
                            try:
                                hashed_password = ph.hash(password)
                                # Store as dictionary instead of just password hash
                                server_state.users[username] = {
                                    "password": hashed_password,
                                    "public_key": identity_pubkey,
                                    "key_created": key_created
                                }
                                server_state.save_users()
                                response = {"type": "registration_success", "message": "Registration successful."}
                            except Exception as e:
                                response = {"type": "registration_failed", "message": f"Error during registration: {e}"}
                        conn.sendall(json.dumps(response).encode("utf-8"))
                elif message_type == "login":
                    username = message["username"]
                    password = message["password"]
                    session_public_key  = message.get("session_public_key")
                    with server_state.users_lock:
                        user_data = server_state.users.get(username)
                        if user_data and "password" in user_data:
                            try:
                                ph.verify(user_data["password"], password)
                                session = ClientSession(conn, username, session_public_key)
                                server_state.add_client(username, session)
                                with server_state.friends_lock:
                                    friend_list = server_state.friends.get(username, [])
                                response = {
                                    "type": "login_success",
                                    "message": "Login successful.",
                                    "username": username,
                                    "friends": friend_list,
                                    "session_key": b64encode(session.session_key).decode("utf-8")
                                }
                            except Exception:
                                response = {"type": "login_failed", "message": "Invalid username or password."}
                        else:
                            response = {"type": "login_failed", "message": "Invalid username or password."}
                            
                        try:
                            server_state.users[username]["public_key"] = message['public_key']
                            server_state.save_users()
                        except Exception as e:
                            response = {"type": "login_success", "message": f"Error during login: {e}"}
                    conn.sendall(json.dumps(response).encode("utf-8"))

                elif message_type == "request_location":
                    target_client_id = message["target_client_id"]
                    requesting_client_id = message["client_id"]
                    request_data = message.get("request_data", {})

                    # Add friendship check
                    with server_state.friends_lock:
                        if (requesting_client_id not in server_state.friends.get(target_client_id, []) or
                                target_client_id not in server_state.friends.get(requesting_client_id, [])):
                            response = {"type": "error", "message": "You must be friends to request location"}
                            conn.sendall(json.dumps(response).encode("utf-8"))
                            continue  # Use continue instead of return to keep connection open

                    # Forward the request if users are friends
                    target_session = server_state.get_client(target_client_id)
                    if target_session:
                        request_message = {
                            "type": "location_request",
                            "from_client_id": requesting_client_id,
                            "request_data": request_data  # Include the complete request data
                        }
                        try:
                            target_session.connection.sendall(json.dumps(request_message).encode("utf-8"))
                            print(f"Sent location request to client {target_client_id}")
                        except Exception as e:
                            print(f"Error notifying location request: {e}")
                            server_state.handle_connection_error(target_client_id)
                    else:
                        response = {"type": "error", "message": f"User {target_client_id} is offline."}
                        conn.sendall(json.dumps(response).encode("utf-8"))

                elif message_type == "location_response":
                    requesting_client_id = message["to_client_id"]
                    location_data = message["location"]
                    target_session = server_state.get_client(requesting_client_id)
                    if target_session:
                        response_message = {
                            "type": "location_data",
                            "location": location_data,
                            "timestamp": time.time()
                        }
                        try:
                            target_session.connection.sendall(json.dumps(response_message).encode("utf-8"))
                            print(f"Sent location data to client {requesting_client_id}")
                        except Exception as e:
                            print(f"Error sending location data: {e}")
                            server_state.handle_connection_error(requesting_client_id)
                    else:
                        print(f"Requesting client {requesting_client_id} not found.")

                elif message_type == "add_friend":
                    user = message["username"]
                    friend_to_add = message["friend_username"]
                    with server_state.users_lock:
                        if friend_to_add not in server_state.users:
                            response = {"type": "error", "message": f"User {friend_to_add} not found."}
                        else:
                            with server_state.friends_lock:
                                if user not in server_state.friends:
                                    server_state.friends[user] = []
                                if friend_to_add in server_state.friends[user]:
                                    response = {"type": "error", "message": f"{friend_to_add} is already in {user}'s friend list."}
                                else:
                                    server_state.friends[user].append(friend_to_add)
                                    server_state.save_friends()
                                    response = {"type": "friend_added", "friend_username": friend_to_add, "message": f"{friend_to_add} added to {user}'s friend list."}
                    conn.sendall(json.dumps(response).encode("utf-8"))
                elif message_type == "view_friends":
                    response_message = {"type": "view_friends", "friends": server_state.friends.get(message["username"], [])}
                    conn.sendall(json.dumps(response_message).encode("utf-8"))
                elif message_type == "friend_request":
                    from_user = message["from"]
                    to_user = message["to"]
                    if from_user == to_user:
                        response = {"type": "error", "message": "Cannot add yourself."}
                        conn.sendall(json.dumps(response).encode("utf-8"))
                        continue
                    with server_state.users_lock:
                        if to_user not in server_state.users or from_user not in server_state.users:
                            response = {"type": "error", "message": "Invalid user specified."}
                            conn.sendall(json.dumps(response).encode("utf-8"))
                            continue
                    with server_state.friends_lock:
                        if to_user in server_state.friends and from_user in server_state.friends[to_user]:
                            response = {"type": "error", "message": "Already friends."}
                            conn.sendall(json.dumps(response).encode("utf-8"))
                            continue
                    with server_state.pending_requests_lock:
                        pending = server_state.pending_requests.get(to_user, [])
                        if any(r.from_user == from_user for r in pending):
                            response = {"type": "error", "message": "Request already pending."}
                            conn.sendall(json.dumps(response).encode("utf-8"))
                            continue
                        new_request = PendingRequest(from_user, to_user)
                        server_state.add_pending_request(to_user, new_request)
                    target_session = server_state.get_client(to_user)
                    if target_session:
                        try:
                            notify = {"type": "friend_request_received", "from": from_user}
                            target_session.connection.sendall(json.dumps(notify).encode("utf-8"))
                        except Exception as e:
                            print(f"Error notifying friend request: {e}")
                            server_state.handle_connection_error(to_user)
                    response = {"type": "success", "message": "Friend request sent."}
                    conn.sendall(json.dumps(response).encode("utf-8"))

                elif message_type == "accept_friend_request":
                    from_user = message["from"]
                    to_user = message["to"]
                    with server_state.pending_requests_lock:
                        pending = server_state.pending_requests.get(to_user, [])
                        if not any(r.from_user == from_user for r in pending):
                            response = {"type": "error", "message": "No pending request found."}
                            conn.sendall(json.dumps(response).encode("utf-8"))
                            continue
                        server_state.remove_pending_request(to_user, from_user)
                    with server_state.friends_lock:
                        if to_user not in server_state.friends:
                            server_state.friends[to_user] = []
                        if from_user not in server_state.friends:
                            server_state.friends[from_user] = []
                        if from_user not in server_state.friends[to_user]:
                            server_state.friends[to_user].append(from_user)
                        if to_user not in server_state.friends[from_user]:
                            server_state.friends[from_user].append(to_user)
                        server_state.save_friends()
                    session_from = server_state.get_client(from_user)
                    if session_from:
                        try:
                            notify = {"type": "friend_request_accepted", "by": to_user, "friends": server_state.friends.get(from_user, [])}
                            session_from.connection.sendall(json.dumps(notify).encode("utf-8"))
                        except Exception as e:
                            print(f"Error notifying friend acceptance: {e}")
                            server_state.handle_connection_error(from_user)
                    session_to = server_state.get_client(to_user)
                    if session_to:
                        try:
                            update = {
                                "type": "view_friends",
                                "friends": server_state.friends.get(to_user, []),
                                "message": "Friend list updated after accepting request"
                            }
                            session_to.connection.sendall(json.dumps(update).encode("utf-8"))
                        except Exception as e:
                            print(f"Error updating friend list: {e}")
                            server_state.handle_connection_error(to_user)

                elif message_type == "message_user":
                    from_client_id = message["from_client_id"]
                    to_client_id = message["to_client_id"]
                    message_data = message["content"]
                    target_session = server_state.get_client(to_client_id)
                    if target_session:
                        try:
                            forward = {"type": "received_message", "from_client_id": from_client_id, "content": message_data}
                            target_session.connection.sendall(json.dumps(forward).encode("utf-8"))
                            print(f"Sent message to client {to_client_id}")
                        except Exception as e:
                            print(f"Error forwarding message: {e}")
                            server_state.handle_connection_error(to_client_id)
                    else:
                        server_state.add_message(to_client_id, {"from": from_client_id, "content": message_data, "timestamp": time.time()})
                        response = {"type": "message_stored", "message": "Message stored for offline delivery."}
                        conn.sendall(json.dumps(response).encode("utf-8"))

                elif message_type == "get_messages":
                    username = message["username"]
                    messages = server_state.get_messages(username)
                    response = {"type": "queued_messages", "messages": messages}
                    conn.sendall(json.dumps(response).encode("utf-8"))
                    conn.sendall(json.dumps(response).encode("utf-8"))
                elif message_type == "get_public_key":
                    target = message["target"]
                    with server_state.users_lock:
                        user_data = server_state.users.get(target)
                        if user_data and "public_key" in user_data:
                            response = {
                                "type": "public_key_response",
                                "public_key": user_data["public_key"],
                                "key_created": user_data["key_created"]
                            }
                        else:
                            response = {"type": "error", "message": "Public key not found"}
                    conn.sendall(json.dumps(response).encode("utf-8"))
                elif message_type == "get_friend_requests":
                    username = message["username"]
                    with server_state.pending_requests_lock:
                        pending = server_state.pending_requests.get(username, [])
                        # Create a list of requestor usernames
                        request_list = [r.from_user for r in pending]
                    response = {"type": "friend_requests", "requests": request_list}
                    conn.sendall(json.dumps(response).encode("utf-8"))
                else:
                    response = {"type": "error", "message": "Invalid message type."}
                    conn.sendall(json.dumps(response).encode("utf-8"))

                # Update session last activity if username is provided in the message
                if "username" in message:
                    with server_state.clients_lock:
                        session = server_state.clients.get(message["username"])
                        if session:
                            session.last_activity = time.time()

            except json.JSONDecodeError:
                print(f"Received invalid JSON data: {data}")
            except Exception as e:
                print(f"Error processing message: {e}")

    except Exception as e:
        print(f"Error communicating with client: {e}")

    finally:
        # Comprehensive cleanup for client session and associated resources
        with server_state.clients_lock:
            to_remove = None
            for uname, session in list(server_state.clients.items()):
                if session.connection == conn:
                    to_remove = uname
                    break
            if to_remove:
                server_state.remove_client(to_remove)
                print(f"Cleaned up resources for {to_remove}")
        try:
            conn.close()
        except Exception as e:
            print(f"Error closing connection: {e}")


# ----- Session Cleanup Task -----
def session_cleanup_task(server_state, timeout=3600, interval=60):
    while True:
        time.sleep(interval)
        current_time = time.time()
        with server_state.clients_lock:
            for username, session in list(server_state.clients.items()):
                if current_time - session.last_activity > timeout:
                    try:
                        session.connection.close()
                    except Exception as e:
                        print(f"Error closing session for {username}: {e}")
                    del server_state.clients[username]
                    print(f"Session timeout for {username}")


# ----- Server Startup -----
def start_server(server_state, host=SERVER, port=PORT):
    cleanup_thread = threading.Thread(target=session_cleanup_task, args=(server_state,), daemon=True)
    cleanup_thread.start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            try:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr, server_state), daemon=True)
                client_thread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

# ----- Main Execution -----

if __name__ == "__main__":
    server_state = ServerState()
    start_server(server_state)
