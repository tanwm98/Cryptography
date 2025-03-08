import socket
import json
import threading
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from argon2 import PasswordHasher
import time
from elgamal import PierreProtocol, serialize_public_key, deserialize_public_key
import random

ph = PasswordHasher()

# Client configuration
HOST = "127.0.0.1"
PORT = 65432


class NetworkError(Exception):
    pass


# --- Updated Config with Atomic File Operations ---
class Config:
    def __init__(self):
        self.lock = threading.RLock()
        self.settings = {}
        self.load_config()

    def load_config(self):
        with self.lock:
            try:
                with open("config.json", "r") as f:
                    self.settings = json.load(f)
            except FileNotFoundError:
                self.settings = {}

    def get(self, key, default=None):
        with self.lock:
            return self.settings.get(key, default)

    def save_config(self):
        with self.lock:
            temp_file = "config.json.tmp"
            try:
                with open(temp_file, "w") as f:
                    json.dump(self.settings, f)
                os.replace(temp_file, "config.json")
            except Exception as e:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                raise e


class SecureGridLocation:
    def __init__(self, resolution=1000):
        self.resolution = resolution
        self.key = None

    def coordinates_to_cell(self, x, y):
        """Convert exact coordinates to grid cell coordinates"""
        cell_x = x // self.resolution
        cell_y = y // self.resolution
        return cell_x, cell_y

    def set_key(self, key):
        """Set encryption key"""
        self.key = key


# --- Updated Client Class with Thread Safety and Enhanced Error Handling ---
class Client:
    def __init__(self):
        self.temp_private_key = None  # For storing temporary ElGamal private key
        self.last_request_data = None  # For storing location requests
        self.username = None
        self.x = 0
        self.y = 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_running = True
        self.is_logged_in = False
        self.friends = []
        self.private_key = None
        self.session_key = None
        self.grid_location = None
        # Thread safety locks
        self.friends_lock = threading.RLock()
        self.connection_lock = threading.RLock()
        self.stop_flag = threading.Event()  # Flag to signal the thread to stop

    # --- Connection Management Methods ---
    def send_message(self, message):
        with self.connection_lock:
            try:
                if not self.check_connection():
                    raise NetworkError("Connection lost")
                self.socket.sendall(message.encode("utf-8"))
            except socket.error as e:
                self.handle_connection_error()
                raise NetworkError(f"Failed to send message: {e}")

    def check_connection(self):
        try:
            # Send heartbeat (empty bytes)
            self.socket.sendall(b"")
            return True
        except Exception:
            return False

    def handle_connection_error(self):
        self.is_running = False
        try:
            self.socket.close()
        except Exception:
            pass
        print("Connection error detected. Session terminated.")

    # --- Session Management ---
    def start_session(self):
        with self.connection_lock:
            if self.session_key:
                try:
                    self.grid_location = SecureGridLocation()
                    self.grid_location.set_key(self.session_key)
                    return True
                except Exception as e:
                    print(f"Failed to start session: {e}")
                    return False
            return False

    def end_session(self):
        with self.connection_lock:
            self.session_key = None
            self.grid_location = None
            self.is_logged_in = False

    # --- Secure Location Updates ---
    def set_location(self):
        try:
            x = int(input("Enter your x coordinate (0-99999): "))
            y = int(input("Enter your y coordinate (0-99999): "))
            if 0 <= x <= 99999 and 0 <= y <= 99999:
                print(f"New coordinates: ({x}, {y})")

                self.x = x
                self.y = y
                cell = self.grid_location.coordinates_to_cell(x, y)
                print(f"New cell: ({cell[0]}, {cell[1]})")
                print("Location updated locally")
                return True
            else:
                raise ValueError
        except ValueError:
            print("Those are not valid coordinates!")
            return False
        except Exception as e:
            print(f"Something went wrong: {e}")
            return False

    # --- Other Client Methods ---
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
        if not hasattr(self, "socket") or not self.socket:
            print("Not connected to server. Please connect first.")
            return False

        try:
            # Generate long-term identity keypair
            identity_private_key = ec.generate_private_key(ec.SECP256K1())
            identity_public_key = identity_private_key.public_key()

            # Store private key locally
            self.identity_private_key = identity_private_key

            # Serialize public key for transmission
            public_pem = identity_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            message = json.dumps(
                {
                    "type": "register",
                    "username": username,
                    "password": password,
                    "identity_public_key": b64encode(public_pem).decode("utf-8"),
                    "key_created": int(time.time()),
                }
            )
            self.socket.sendall(message.encode("utf-8"))
            return True
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def login(self, username, password):
        if not hasattr(self, "socket") or not self.socket:
            print("Not connected to server. Please connect first.")
            return False

        try:
            # Generate keypair for this session
            self.private_key = ec.generate_private_key(ec.SECP256K1())
            public_key = self.private_key.public_key()

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_key = self.private_key.public_key()

            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            message = json.dumps(
                {
                    "type": "login",
                    "username": username,
                    "password": password,
                    "public_key": b64encode(public_pem).decode("utf-8"),
                }
            )
            self.socket.sendall(message.encode("utf-8"))
            # Response will be handled by receive_messages thread
            return True
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def receive_messages(self):
        while self.is_running:
            try:
                data = self.socket.recv(8192).decode("utf-8")
                if not data:
                    self.stop_flag.set()
                    print("Server connection closed")
                    self.is_running = False
                    break

                message = json.loads(data)
                message_type = message.get("type", "")
                signature = message.get("signature")

                if message_type == "registration_success":
                    print(message["message"])
                elif message_type == "registration_failed":
                    print(message["message"])
                elif message_type == "login_success":
                    print(message["message"])
                    self.username = message["username"]
                    self.is_logged_in = True
                    self.friends = message.get("friends", [])
                    session_key = b64decode(message["session_key"])
                    self.session_key = session_key
                    self.grid_location = SecureGridLocation()
                    self.grid_location.key = session_key
                    print(f"Logged in as {self.username}. Friends: {self.friends}")
                elif message_type == "login_failed":
                    print(message["message"])
                elif message_type == "friend_requests":
                    requests = message.get("requests", [])
                    print("Pending friend requests:", requests)
                elif message_type == "friend_added":
                    print(message["message"])
                    if "friend_username" in message:
                        if message["friend_username"] not in self.friends:
                            self.friends.append(message["friend_username"])
                elif message_type == "friend_request_received":
                    print(f"Friend request received from: {message['from']}")
                elif message_type == "friend_request_accepted":
                    print(f"Friend request accepted by: {message['by']}")
                    self.friends = message.get("friends", [])
                elif message_type == "view_friends":
                    self.friends = []
                    friend_data = message.get("friends", [])

                    # Initialize friend public keys dictionary if not exists
                    if not hasattr(self, "friend_public_keys"):
                        self.friend_public_keys = {}

                    # Process friend list with public keys
                    for friend_info in friend_data:
                        username = friend_info.get("username")
                        public_key = friend_info.get("public_key")

                        if username:
                            self.friends.append(username)

                            # Store public key if provided
                            if public_key:
                                try:
                                    pem_data = b64decode(public_key)
                                    key_obj = serialization.load_pem_public_key(
                                        pem_data
                                    )
                                    self.friend_public_keys[username] = key_obj
                                except Exception as e:
                                    print(
                                        f"Error processing {username}'s public key: {e}"
                                    )

                    if self.friends:
                        print("\nYour friends:", ", ".join(self.friends))
                    else:
                        print("\nYou have no friends yet.")
                elif message_type == "request_location":
                    # Extract the signature
                    signature = message.get("signature")
                    if not signature:
                        print(
                            "Warning: Received unsigned location_request message - discarding"
                        )
                        continue

                    # Identify the sender from the message
                    sender = message.get("client_id")
                    if not sender or sender not in self.friends:
                        print(
                            f"Warning: Message from unknown or non-friend sender: {sender}"
                        )
                        continue

                    # Prepare a copy without the signature for verification
                    verify_msg = message.copy()
                    verify_msg.pop("signature", None)

                    # Request the sender's public key if not already available
                    if (
                        not hasattr(self, "friend_public_keys")
                        or sender not in self.friend_public_keys
                    ):
                        self.request_friend_public_key(sender)
                        print(
                            f"Don't have public key for {sender}, cannot verify message"
                        )
                        continue

                    # Verify the signature
                    if not self.verify_signature(
                        verify_msg, signature, self.friend_public_keys[sender]
                    ):
                        print(
                            f"Warning: Invalid signature from {sender} - discarding message"
                        )
                        continue

                    print(f"✓ Verified location_request from {sender}")

                    # Process the location request
                    if "request_data" in message:
                        self.last_request_data = message.get("request_data", {})
                        self.last_request_signature = signature  # Optionally store signature for later verification
                        self.send_location(sender)
                    else:
                        print(f"Received location request without data from {sender}")

                elif message_type == "location_response":
                    # Extract the signature
                    signature = message.get("signature")
                    if not signature:
                        print(
                            "Warning: Received unsigned location_data message - discarding"
                        )
                        continue

                    # For location_data, extract the sender from the response payload
                    location_info = message.get("location", {})
                    response_payload = location_info.get("response_payload", {})
                    sender = response_payload.get("from_client_id")
                    if not sender or sender not in self.friends:
                        print(
                            f"Warning: Message from unknown or non-friend sender: {sender}"
                        )
                        continue

                    # Prepare a copy without the signature for verification
                    verify_msg = message.copy()
                    verify_msg.pop("signature", None)

                    # Ensure we have the sender's public key
                    if (
                        not hasattr(self, "friend_public_keys")
                        or sender not in self.friend_public_keys
                    ):
                        self.request_friend_public_key(sender)
                        print(
                            f"Don't have public key for {sender}, cannot verify message"
                        )
                        continue

                    # Verify the signature
                    if not self.verify_signature(
                        verify_msg, signature, self.friend_public_keys[sender]
                    ):
                        print(
                            f"Warning: Invalid signature from {sender} - discarding message"
                        )
                        continue

                    print(f"✓ Verified location_data from {sender}")

                    # Process the location data message
                    location = message.get("location")
                    start_time = time.time()  # Start timer
                    is_same_cell = self.proximity_check_cell(location)
                    end_time = time.time()  # End timer
                    print(f"Proximity check took {end_time - start_time:.6f} seconds")

                    if is_same_cell:
                        print("Friend is nearby!")
                    else:
                        print("Friend is not nearby!")

                elif message_type == "friend_public_key":
                    friend_username = message.get("friend_username")
                    public_key_data = message.get("public_key")

                    if friend_username and public_key_data:
                        # Initialize friend_public_keys if it doesn't exist
                        if not hasattr(self, "friend_public_keys"):
                            self.friend_public_keys = {}

                        # Store the public key
                        try:
                            # Convert from PEM format to cryptography's public key object
                            pem_data = b64decode(public_key_data)
                            friend_public_key = serialization.load_pem_public_key(
                                pem_data
                            )
                            self.friend_public_keys[friend_username] = friend_public_key
                            print(
                                f"Received and stored public key for {friend_username}"
                            )
                        except Exception as e:
                            print(f"Error processing friend's public key: {e}")

                elif message_type == "error":
                    print(f"Error: {message['message']}")
                elif message_type == "location_update_success":
                    print("Location updated successfully")
                elif message_type == "success":
                    print(message["message"])
                elif message_type == "friend_request_accepted":
                    print(f"Friend request accepted by: {message['by']}")
                    # Update friends list for both users
                    self.friends = message.get("friends", [])
                    print(f"Updated friends list: {self.friends}")
                else:
                    print(f"Unknown message type received: {message_type}")

            except json.JSONDecodeError as e:
                print(f"Invalid JSON received: {e}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

        print("Stopped receiving messages.")
        self.close()

    def request_friend_public_key(self, friend_username):
        """Request a friend's public key from the server"""
        if not self.is_logged_in:
            return False

        request = {
            "type": "get_friend_public_key",
            "username": self.username,
            "friend_username": friend_username,
        }

        try:
            self.send_message(json.dumps(request))
            return True
        except Exception as e:
            print(f"Error requesting friend's public key: {e}")
            return False

    def request_location(self, target_client_id):
        if not self.is_logged_in:
            print("You must log in before requesting a location.")
            return
        if target_client_id == self.username:
            print(
                f"Your location is ({self.x}, {self.y}) in cell {self.grid_location.coordinates_to_cell(self.x, self.y)}"
            )
            return
        elif target_client_id not in self.friends:
            print(
                f"You must be friends with {target_client_id} to request their location."
            )
            return

        # Initialize Pierre protocol and generate ephemeral key pair for this request
        pierre = PierreProtocol(resolution=1000)
        public_key, private_key = pierre.generate_keypair()
        self.temp_private_key = private_key  # Store for later use

        # Prepare request data (includes encrypted grid data)
        request_data, _ = pierre.prepare_request(
            self.x, self.y, public_key, private_key
        )
        request_data["public_key"] = serialize_public_key(public_key)

        # Create the request message dictionary
        request_message_dict = {
            "type": "request_location",
            "client_id": self.username,
            "target_client_id": target_client_id,
            "request_data": request_data,
        }

        # Sign the request message (the signature covers the entire payload)
        signature = self.sign_message(request_message_dict)
        request_message_dict["signature"] = signature

        # Serialize and send the message
        request_message = json.dumps(request_message_dict)
        self.send_message(request_message)
        print(f"Location request sent to {target_client_id}")

    def send_location(self, from_client_id):
        try:
            # Retrieve the last received request data
            if not hasattr(self, "last_request_data") or not self.last_request_data:
                print("No location request data available")
                return

            # Verify the request signature if not already verified in receive_messages
            if not hasattr(self, "last_request_signature"):
                print("Missing signature for request, cannot verify")
                return

            request_data = self.last_request_data

            # Obtain the requester's public key
            public_key_data = request_data.get("public_key")
            if not public_key_data:
                print("Missing public key in request data")
                return

            from_public_key = deserialize_public_key(public_key_data)
            if not from_public_key:
                print("Failed to deserialize public key")
                return

            # Initialize Pierre protocol and process the request to generate response data
            pierre = PierreProtocol(resolution=1000)
            response_data = pierre.process_request(
                self.x, self.y, request_data, from_public_key
            )

            # Build the response payload
            response_payload = {
                "from_client_id": self.username,
                "to_client_id": from_client_id,
                "timestamp": int(time.time()),  # Add timestamp for freshness
                "response_data": response_data,
            }

            # Create the response message dictionary
            response_message_dict = {
                "type": "location_response",
                "to_client_id": from_client_id,
                "location": {"response_payload": response_payload},
            }

            # Sign the response message using our identity key
            signature = self.sign_message(response_message_dict)
            response_message_dict["signature"] = signature

            # Serialize and send the response
            response_message = json.dumps(response_message_dict)
            self.send_message(response_message)
            print(f"Location response sent to {from_client_id}")

        except Exception as e:
            print(f"Error in send_location: {e}")

    # In the proximity_check_cell method, update to handle all three responses:
    def proximity_check_cell(self, location_data):
        try:
            response_payload = location_data.get("response_payload", {})

            # Get the response data
            response_data = response_payload.get("response_data", {})

            # Initialize Pierre protocol
            pierre = PierreProtocol(resolution=1000)

            # Check all three proximity levels
            response_0_serialized = response_data.get("response_0", {})
            response_1_serialized = response_data.get("response_1", {})
            response_2_serialized = response_data.get("response_2", {})

            # Deserialize the ciphertexts
            response_0 = pierre.deserialize_ciphertext(response_0_serialized)
            response_1 = pierre.deserialize_ciphertext(response_1_serialized)
            response_2 = pierre.deserialize_ciphertext(response_2_serialized)

            # Decrypt using the temporary private key
            start_time = time.time()  # Start timer

            # Response will return 0 if Same, Adjacent or in Diagonal cell respectively
            same_cell_result = pierre.decrypt(self.temp_private_key, response_0)
            adjacent_cell_result = pierre.decrypt(self.temp_private_key, response_1)
            diagonal_cell_result = pierre.decrypt(self.temp_private_key, response_2)

            end_time = time.time()  # End timer
            print(f"Proximity check took {end_time - start_time:.6f} seconds")

            # Check the results
            if not same_cell_result:
                print("\nFriend is in the Same Cell!")
                return True
            elif not adjacent_cell_result:
                print("\nFriend is in an Adjacent Cell!")
                return True
            elif not diagonal_cell_result:
                print("\nFriend is in a Diagonal Cell!")
                return True
            else:
                print("\nFriend is not nearby!")
                return False

        except Exception as e:
            print(f"Error in proximity check: {e}")
            import traceback

            traceback.print_exc()
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
        self.send_message(message)

    def view_friend(self):
        if not self.is_logged_in:
            print("You must log in before viewing friends.")
            return
        message = json.dumps({"type": "view_friends", "username": self.username})
        self.send_message(message)

    def sign_message(self, message):
        if not self.private_key:
            raise ValueError("No private key available - not logged in?")

        # Check if it's an EC key
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            # EC keys use a different signing mechanism
            signature = self.private_key.sign(
                json.dumps(message).encode(), ec.ECDSA(hashes.SHA256())
            )
        else:
            # RSA keys use PSS padding
            signature = self.private_key.sign(
                json.dumps(message).encode(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        return b64encode(signature).decode("utf-8")

    def verify_signature(self, message, signature, sender_public_key):
        try:
            # Check if it's an EC key
            if isinstance(sender_public_key, ec.EllipticCurvePublicKey):
                sender_public_key.verify(
                    b64decode(signature),
                    json.dumps(message).encode(),
                    ec.ECDSA(hashes.SHA256()),
                )
            else:
                sender_public_key.verify(
                    b64decode(signature),
                    json.dumps(message).encode(),
                    asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            return True
        except Exception:
            return False

    def send_friend_request(self, friend_username):
        message = json.dumps(
            {"type": "friend_request", "from": self.username, "to": friend_username}
        )
        self.send_message(message)

    def view_friend_requests(self):
        message = json.dumps({"type": "get_friend_requests", "username": self.username})
        self.send_message(message)

    def accept_friend_request(self, requestor):
        message = json.dumps(
            {"type": "accept_friend_request", "from": requestor, "to": self.username}
        )
        self.send_message(message)

    def close(self):
        self.is_running = False
        try:
            self.socket.close()
        except Exception:
            pass
        print("Connection closed.")


if __name__ == "__main__":
    client = Client()
    connected = False

    while True:
        if not client.is_running:
            break

        if not client.is_logged_in:
            print("\nWelcome!")
            print("1. Connect to server")
            print("2. Register")
            print("3. Login")
            print("4. Exit")

            try:
                choice = input("Choose an option: ")

                if choice == "1":
                    if client.connect():
                        print("Connected to server successfully!")
                        connected = True
                    else:
                        print("Connection failed!")

                elif choice == "2":
                    if not connected:
                        print("Please connect to server first (Option 1)")
                        continue
                    username = input("Enter new username: ")
                    password = input("Enter new password: ")
                    if not client.register(username, password):
                        print("Registration failed. Please try again.")

                elif choice == "3":
                    if not connected:
                        print("Please connect to server first (Option 1)")
                        continue
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    if not client.login(username, password):
                        print("Login failed. Please try again.")

                elif choice == "4":
                    break

            except Exception as e:
                print(f"Error: {e}")
        else:
            print("\n" + "=" * 50)  # Add separator line
            print("Main Menu, logged in as:", client.username)
            print("4. Update Location")
            print("5. Check Cell")
            print("6. Send Friend Request")
            print("7. View Friend Requests")
            print("8. Accept Friend Request")
            print("9. View Friends")
            print("10. Exit")
            print("=" * 50 + "\n")  # Add separator line
            try:
                choice = input("Choose an option: ")
                if choice == "4":
                    client.set_location()
                elif choice == "5":
                    friend = input("Enter friend's username to check cell: ")
                    client.request_location(friend)
                elif choice == "6":
                    friend = input("Enter username to send friend request: ")
                    client.send_friend_request(friend)
                elif choice == "7":
                    client.view_friend_requests()
                elif choice == "8":
                    requestor = input("Enter username to accept their request: ")
                    client.accept_friend_request(requestor)
                elif choice == "9":
                    client.view_friend()
                elif choice == "10":
                    break
            except Exception as e:
                print(f"Error: {e}")
    client.close()
