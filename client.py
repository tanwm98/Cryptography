import socket
import json
import threading
import time
from math import sqrt

# Client configuration
HOST = "127.0.0.1"
PORT = 65432
EUCLIDEAN_DISTANCE = 10000


class Client:
    def __init__(self):
        self.username = None  # Username is not known until login
        self.x = 0
        self.y = 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_running = True
        self.is_logged_in = False
        self.friends = []

    def set_location(self):
        try:
            x = int(input("Enter your x coordinate (0-99999): "))
            y = int(input("Enter your y coordinate (0-99999): "))
            if 0 <= x <= 99999 and 0 <= y <= 99999:
                self.x = x
                self.y = y
            else:
                raise ValueError
        except ValueError:
            print("Those are not valid coordinates!")
        except Exception as e:
            print("Something went wrong!")

    def connect(self):
        try:
            self.socket.connect((HOST, PORT))
            print("Connected to server.")

            threading.Thread(target=self.receive_messages, daemon=True).start()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            self.is_running = False
            return False

    def register(self, username, password):

        message = json.dumps(
            {"type": "register", "username": username, "password": password}
        )
        self.socket.sendall(message.encode("utf-8"))

    def login(self, username, password):
        message = json.dumps(
            {"type": "login", "username": username, "password": password}
        )
        self.socket.sendall(message.encode("utf-8"))

    def receive_messages(self):
        while self.is_running:
            try:
                data = self.socket.recv(1024).decode("utf-8")
                if not data:
                    break

                message = json.loads(data)
                # print(f"Received: {message}")

                if message["type"] == "registration_success":

                    print(message["message"])
                elif message["type"] == "registration_failed":
                    print(message["message"])
                elif message["type"] == "login_success":
                    print(message["message"])
                    self.username = message["username"]
                    self.is_logged_in = True
                    self.friends = message.get("friends", [])
                    print(f"Logged in as {self.username}. Friends: {self.friends}")
                elif message["type"] == "login_failed":
                    print(message["message"])
                elif message["type"] == "location_request":
                    from_client_id = message["from_client_id"]
                    self.send_location(from_client_id)
                elif message["type"] == "location_data":
                    location = message["location"]
                    if self.proximity_check_cell(location):
                        print("Friend is nearby! (Same Cell)")
                    if self.proximity_check_euclidean(location):
                        print("Friend is nearby! (in Range)")
                    else:
                        print("Friend is far away!")
                elif message["type"] == "error":
                    print(f"Error: {message['message']}")
                elif message["type"] == "friend_added":
                    print(message["message"])
                    # Update friend list locally
                    self.friends.append(message["message"].split()[0])
                elif message["type"] == "view_friends":
                    self.friends = message.get("friends", [])
                    print(f"Friends: {self.friends}")
                elif message["type"] == "message_user":
                    from_client_id = message["from_client_id"]
                    message_data = message["content"]
                    print(f"{from_client_id}: {message_data}")

            except json.JSONDecodeError:
                print(f"Received invalid JSON data: {data}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

        print("Stopped receiving messages.")
        self.close()

    def request_location(self, target_client_id):
        if not self.is_logged_in:
            print("You must log in before requesting a location.")
            return

        elif target_client_id is self.username:
            print(
                f"Your current location is ({self.x}, {self.y}) in cell ({self.x // 1000}, {self.y // 1000})"
            )
            return

        elif target_client_id not in self.friends:
            print("You must be friends to view their location, Creep!")
            return

        request_message = json.dumps(
            {
                "type": "request_location",
                "client_id": self.username,
                "target_client_id": target_client_id,
            }
        )
        self.socket.sendall(request_message.encode("utf-8"))
        print(f"Requested location from client {target_client_id}")

    def send_location(self, to_client_id):
        location_data = {"x": self.x, "y": self.y}
        response_message = json.dumps(
            {
                "type": "location_response",
                "to_client_id": to_client_id,
                "location": location_data,
            }
        )
        self.socket.sendall(response_message.encode("utf-8"))
        print(f"Sent location to server for client {to_client_id}")

    def proximity_check_cell(self, location):
        if (self.x // 1000) == (location["x"] // 1000) and (self.y // 1000) == (
            location["y"] // 1000
        ):
            return True
        else:
            return False

    def proximity_check_euclidean(self, location):
        distance = 0
        distance += (self.x - location["x"]) ** 2
        distance += (self.y - location["y"]) ** 2

        if sqrt(distance) <= EUCLIDEAN_DISTANCE:
            return True
        else:
            return False

    def add_friend(self, friend_username):
        if not self.is_logged_in:
            print("You must log in before adding a friend.")
            return

        message = json.dumps(
            {
                "type": "add_friend",
                "username": self.username,
                "friend_username": friend_username,
            }
        )
        self.socket.sendall(message.encode("utf-8"))

    def view_friend(self):
        if not self.is_logged_in:
            print("You must log in before adding a friend.")
            return

        message = json.dumps({"type": "view_friend", "username": self.username})
        self.socket.sendall(message.encode("utf-8"))

    def msg_user(self, to_client_id, message_data):
        response_message = json.dumps(
            {
                "type": "message_user",
                "from_client_id": self.username,
                "to_client_id": to_client_id,
                "content": message_data,
            }
        )
        self.socket.sendall(response_message.encode("utf-8"))
        print(f"Sent message to client {to_client_id}")

    def close(self):
        self.is_running = False
        self.socket.close()
        print("Connection closed.")


if __name__ == "__main__":
    client = Client()
    if not client.connect():
        exit()
    while not client.is_logged_in:
        action = input("Register (r) or Login (l)? ")
        if action.lower() == "r":
            username = input("Enter new username: ")
            password = input("Enter new password: ")
            client.register(username, password)
        elif action.lower() == "l":
            username = input("Enter username: ")
            password = input("Enter password: ")
            client.login(username, password)
        else:
            print("Invalid action.")
            break

        time.sleep(0.5)  # Give the server time to respond

    client.set_location()

    try:
        while True:
            action = input(
                "Enter 'request [client_id]' to request location\n'add [friend_id]' to add a friend\n'view' to view friends\n'msg [client id]' to send a message\n'exit' to quit\n==> "
            )
            if action.startswith("request"):
                try:
                    target_client_id = action.split()[1]
                    client.request_location(target_client_id)
                except IndexError:
                    print("Invalid request format. Use 'request [client_id]'.")
            elif action.startswith("add"):
                try:
                    friend_username = action.split()[1]
                    client.add_friend(friend_username)
                except IndexError:
                    print("Invalid add format. Use 'add [friend_id]'.")
            elif action.startswith("view"):
                try:
                    client.view_friend()
                except IndexError:
                    print("Invalid add format. Use 'view'.")
            elif action.startswith("msg"):
                try:
                    message = input("Message: ")
                    friend_username = action.split()[1]
                    client.msg_user(friend_username, message)
                except IndexError:
                    print("Invalid add format. Use 'msg [friend_id]'.")
            elif action == "exit":
                break
            else:
                print("Invalid action.")
    finally:
        client.close()
