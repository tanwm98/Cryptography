import socket
import threading
import json
import os


# Server configuration
HOST = "127.0.0.1"
PORT = 65432
USERS_FILE = "users.txt"
FRIENDS_FILE = "friends.txt"

# Dictionary to store client connections (username: connection)
clients = {}


# Load user accounts from file
def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            for line in f:
                username, password = line.strip().split(":")

                users[username] = password
    return users


# Save user accounts to file
def save_users(users):
    with open(USERS_FILE, "w") as f:
        for username, password in users.items():
            f.write(f"{username}:{password}\n")


# Load friends data from file
def load_friends():
    friends = {}
    if os.path.exists(FRIENDS_FILE):
        with open(FRIENDS_FILE, "r") as f:
            for line in f:
                try:
                    user, friend_list_str = line.strip().split(":")
                    friend_list = friend_list_str.split(",") if friend_list_str else []
                    friends[user] = friend_list
                except ValueError:
                    print(f"Invalid line in friends file: {line}")
    return friends


# Save friends data to file
def save_friends(friends):
    with open(FRIENDS_FILE, "w") as f:
        for user, friend_list in friends.items():
            f.write(f"{user}:{','.join(friend_list)}\n")


# Handle client communication
def handle_client(conn, addr):
    print(f"Connected by {addr}")
    users = load_users()  # Load users at the start of each connection
    friends = load_friends()

    try:
        while True:
            data = conn.recv(1024).decode("utf-8")
            if not data:
                break

            try:
                message = json.loads(data)
                print(f"Received: {message}")

                if message["type"] == "register":
                    username = message["username"]
                    password = message["password"]

                    if username in users:
                        response_message = json.dumps(
                            {
                                "type": "registration_failed",
                                "message": "Username already exists.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))
                    else:
                        users[username] = password
                        save_users(users)
                        friends[username] = []  # Initialize friend list for new user
                        save_friends(friends)
                        response_message = json.dumps(
                            {
                                "type": "registration_success",
                                "message": "Registration successful.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))
                        print(f"User {username} registered.")

                elif message["type"] == "login":
                    username = message["username"]
                    password = message["password"]

                    if username in users and users[username] == password:
                        clients[username] = conn  # Store the connection
                        response_message = json.dumps(
                            {
                                "type": "login_success",
                                "message": "Login successful.",
                                "username": username,
                                "friends": friends.get(
                                    username, []
                                ),  # Send friend list to client
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))
                        print(f"User {username} logged in.")
                    else:
                        response_message = json.dumps(
                            {
                                "type": "login_failed",
                                "message": "Invalid username or password.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))

                elif message["type"] == "request_location":
                    target_client_id = message["target_client_id"]
                    requesting_client_id = message["client_id"]

                    if target_client_id in clients:
                        # Forward the location request to the target client
                        target_conn = clients[target_client_id]
                        request_message = json.dumps(
                            {
                                "type": "location_request",
                                "from_client_id": requesting_client_id,
                            }
                        )
                        target_conn.sendall(request_message.encode("utf-8"))
                        print(f"Sent location request to client {target_client_id}")

                    else:
                        # Client not found
                        response_message = json.dumps(
                            {
                                "type": "error",
                                "message": f"Client {target_client_id} not found.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))

                elif message["type"] == "location_response":
                    # Forward the location data to the requesting client
                    requesting_client_id = message["to_client_id"]
                    location_data = message["location"]

                    if requesting_client_id in clients:
                        requesting_conn = clients[requesting_client_id]
                        response_message = json.dumps(
                            {"type": "location_data", "location": location_data}
                        )
                        requesting_conn.sendall(response_message.encode("utf-8"))
                        print(f"Sent location data to client {requesting_client_id}")
                    else:
                        print(f"Requesting client {requesting_client_id} not found.")

                elif message["type"] == "add_friend":
                    user = message["username"]
                    friend_to_add = message["friend_username"]

                    if friend_to_add in users:
                        if user not in friends:
                            friends[user] = []
                        if friend_to_add not in friends[user]:
                            friends[user].append(friend_to_add)
                            save_friends(friends)
                            response_message = json.dumps(
                                {
                                    "type": "friend_added",
                                    "message": f"{friend_to_add} added to {user}'s friend list.",
                                }
                            )
                            conn.sendall(response_message.encode("utf-8"))
                            print(f"{friend_to_add} added to {user}'s friend list.")
                        else:
                            response_message = json.dumps(
                                {
                                    "type": "error",
                                    "message": f"{friend_to_add} is already in {user}'s friend list.",
                                }
                            )
                            conn.sendall(response_message.encode("utf-8"))
                    else:
                        response_message = json.dumps(
                            {
                                "type": "error",
                                "message": f"User {friend_to_add} not found.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))

                elif message["type"] == "view_friend":
                    response_message = json.dumps(
                        {
                            "type": "view_friends",
                            "friends": friends.get(
                                username, []
                            ),  # Send friend list to client
                        }
                    )
                    conn.sendall(response_message.encode("utf-8"))

                elif message["type"] == "message_user":
                    from_client_id = message["from_client_id"]
                    to_client_id = message["to_client_id"]
                    message_data = message["content"]

                    if to_client_id in clients:
                        # Forward the location request to the target client
                        target_conn = clients[to_client_id]
                        request_message = json.dumps(
                            {
                                "type": "message_user",
                                "from_client_id": from_client_id,
                                "content": message_data,
                            }
                        )
                        target_conn.sendall(request_message.encode("utf-8"))
                        print(f"Sent location request to client {to_client_id}")

                    else:
                        # Client not found
                        response_message = json.dumps(
                            {
                                "type": "error",
                                "message": f"Client {to_client_id} not found.",
                            }
                        )
                        conn.sendall(response_message.encode("utf-8"))

            except json.JSONDecodeError:
                print(f"Received invalid JSON data: {data}")
            except Exception as e:
                print(f"Error processing message: {e}")

    except Exception as e:
        print(f"Error communicating with client: {e}")
    finally:
        # Clean up when the client disconnects
        for username, connection in list(clients.items()):
            if connection == conn:
                del clients[username]
                print(f"Client {username} disconnected.")
                break
        conn.close()


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    start_server()
