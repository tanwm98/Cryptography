import socket
import json
import threading
import time
from math import sqrt
import os
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from argon2 import PasswordHasher

ph = PasswordHasher()

# Client configuration
HOST = "127.0.0.1"
PORT = 65432
EUCLIDEAN_DISTANCE = 10000


class NetworkError(Exception):
    pass


# --- Updated MessageQueue with Locking ---
class MessageQueue:
    def __init__(self):
        self.messages = {}
        self.lock = threading.RLock()

    def add_message(self, to_user, message):
        with self.lock:
            if to_user not in self.messages:
                self.messages[to_user] = []
            self.messages[to_user].append({
                'content': message,
                'timestamp': time.time()
            })

    def get_messages(self, user):
        with self.lock:
            messages = self.messages.get(user, [])
            self.messages[user] = []  # Clear after reading
            return messages


# --- Updated Config with Atomic File Operations ---
class Config:
    def __init__(self):
        self.lock = threading.RLock()
        self.settings = {}
        self.load_config()

    def load_config(self):
        with self.lock:
            try:
                with open('config.json', 'r') as f:
                    self.settings = json.load(f)
            except FileNotFoundError:
                self.settings = {}

    def get(self, key, default=None):
        with self.lock:
            return self.settings.get(key, default)

    def save_config(self):
        with self.lock:
            temp_file = 'config.json.tmp'
            try:
                with open(temp_file, 'w') as f:
                    json.dump(self.settings, f)
                os.replace(temp_file, 'config.json')
            except Exception as e:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                raise e


# --- SecureGridLocation remains largely the same ---
class SecureGridLocation:
    def __init__(self, resolution=1000):
        self.resolution = resolution

    def coordinates_to_cell(self, x, y):
        return (x // self.resolution, y // self.resolution)

    def generate_cell_proof(self, x, y, timestamp, key):
        cell = self.coordinates_to_cell(x, y)
        h = hmac.HMAC(key, hashes.SHA256())
        msg = f"{cell[0]},{cell[1]},{timestamp}".encode()
        h.update(msg)
        return b64encode(h.finalize()).decode('utf-8')

    def verify_cell_proof(self, cell_x, cell_y, proof, timestamp, key):
        try:
            print("\nDEBUG - Starting cell proof verification")
            print(f"DEBUG - Checking cell ({cell_x}, {cell_y})")
            print(f"DEBUG - Timestamp: {timestamp}")

            # Add timestamp freshness check
            current_time = int(time.time())
            max_age = 30  # 30 seconds
            if abs(current_time - timestamp) > max_age:
                print(f"DEBUG - ✗ Timestamp too old: {current_time - timestamp} seconds")
                return False

            h = hmac.HMAC(key, hashes.SHA256())
            msg = f"{cell_x},{cell_y},{timestamp}".encode()
            print(f"DEBUG - Verification message: {msg}")

            h.update(msg)
            try:
                h.verify(b64decode(proof))
                print("DEBUG - ✓ Cell proof verification successful")
                return True
            except InvalidKey:
                print("DEBUG - ✗ Cell proof verification failed - Invalid key")
                return False
            except Exception as e:
                print(f"DEBUG - ✗ Cell proof verification failed: {e}")
                return False

        except Exception as e:
            print(f"DEBUG - ✗ Error in verify_cell_proof: {e}")
            return False


# --- Updated Client Class with Thread Safety and Enhanced Error Handling ---
class Client:
    def __init__(self):
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
        self.message_queue_lock = threading.RLock()
        self.connection_lock = threading.RLock()
        # Use an instance of MessageQueue for queued messages
        self.message_queue = MessageQueue()

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
            self.socket.sendall(b'')
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
                print("\nDEBUG - Setting local location")
                print(f"DEBUG - New coordinates: ({x}, {y})")

                self.x = x
                self.y = y
                cell = self.grid_location.coordinates_to_cell(x, y)
                print(f"DEBUG - New cell: ({cell[0]}, {cell[1]})")
                print("DEBUG - Location updated locally")
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
        if not hasattr(self, 'socket') or not self.socket:
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
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            message = json.dumps({
                "type": "register",
                "username": username,
                "password": password,
                "identity_public_key": b64encode(public_pem).decode('utf-8'),
                "key_created": int(time.time())
            })
            self.socket.sendall(message.encode("utf-8"))
            return True
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def login(self, username, password):
        if not hasattr(self, 'socket') or not self.socket:
            print("Not connected to server. Please connect first.")
            return False

        try:
            # Generate keypair for this session
            self.private_key = ec.generate_private_key(ec.SECP256K1())
            public_key = self.private_key.public_key()

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key = self.private_key.public_key()

            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            message = json.dumps({
                "type": "login",
                "username": username,
                "password": password,
                "public_key": b64encode(public_pem).decode('utf-8')
            })
            self.socket.sendall(message.encode("utf-8"))
            # Response will be handled by receive_messages thread
            return True
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def receive_messages(self):
        while self.is_running:
            try:
                data = self.socket.recv(1024).decode("utf-8")
                if not data:
                    print("Server connection closed")
                    self.is_running = False
                    break

                message = json.loads(data)
                message_type = message.get("type", "")

                # Print all server responses for debugging
                print(f"\nServer response: {message}")

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
                    self.friends = message.get("friends", [])
                    if self.friends:
                        print("\nYour friends:", ", ".join(self.friends))
                    else:
                        print("\nYou have no friends yet.")
                elif message_type == "friend_request_accepted":
                    self.friends = message.get("friends", [])
                    print("\nFriend list updated:", ", ".join(self.friends))
                elif message_type == "received_message":
                    print(f"\nMessage from {message['from_client_id']}: {message['content']}")
                elif message_type == "location_request":
                    from_client_id = message["from_client_id"]
                    self.send_location(from_client_id)
                elif message_type == "location_data":
                    location = message["location"]
                    is_nearby, is_same_cell = self.proximity_check_cell(location)
                    if is_same_cell:
                        print("Friend is nearby! (Same Cell)")
                    elif is_nearby:
                        print("Friend is nearby! (Adjacent Cell)")
                    else:
                        print("Friend is not nearby!")
                elif message_type == "error":
                    print(f"Error: {message['message']}")
                elif message_type == "queued_messages":
                    messages = message.get("messages", [])
                    if messages:
                        print("\nQueued messages:")
                        for msg in messages:
                            print(f"From {msg['from']}: {msg['content']}")
                    else:
                        print("No queued messages")
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

    # def handle_message(self, message):
    #     # Process incoming messages as before.
    #     if message["type"] == "public_key_response":
    #         # Store in cache if needed
    #         pass  # Handled in get_public_key method
    #     elif message["type"] == "registration_success":
    #         print(message["message"])
    #     elif message["type"] == "registration_failed":
    #         print(message["message"])
    #     elif message["type"] == "login_success":
    #         print(message["message"])
    #         self.username = message["username"]
    #         self.is_logged_in = True
    #         with self.friends_lock:
    #             self.friends = message.get("friends", [])
    #         session_key = b64decode(message["session_key"])
    #         self.session_key = session_key
    #         self.grid_location = SecureGridLocation()
    #         self.grid_location.set_key(session_key)
    #         print(f"Logged in as {self.username}. Friends: {self.friends}")
    #     elif message["type"] == "login_failed":
    #         print(message["message"])
    #     elif message["type"] == "location_request":
    #         from_client_id = message["from_client_id"]
    #         self.send_location(from_client_id)
    #     elif message["type"] == "location_data":
    #         location = message["location"]
    #         if self.proximity_check_cell(location):
    #             print("Friend is nearby! (Same or Adjacent Cell)")
    #         else:
    #             print("Friend is not nearby!")
    #     elif message["type"] == "error":
    #         print(f"Error: {message['message']}")
    #     elif message["type"] == "friend_added":
    #         print(message["message"])
    #         with self.friends_lock:
    #             self.friends.append(message["message"].split()[0])
    #     elif message["type"] == "view_friends":
    #         with self.friends_lock:
    #             self.friends = message.get("friends", [])
    #         print(f"Friends: {self.friends}")
    #     elif message["type"] == "message_user":
    #         sender = message["from_client_id"]
    #         message_data = message["content"]
    #         print(f"{sender}: {message_data}")
    #     elif message["type"] == "received_message":
    #         sender = message["from_client_id"]
    #         content = message["content"]
    #         print(f"\nMessage from {sender}: {content}")

    def request_location(self, target_client_id):
        if not self.is_logged_in:
            print("You must log in before requesting a location.")
            return
        if target_client_id == self.username:
            print(f"Your current location is ({self.x}, {self.y}) in cell ({self.x // 1000}, {self.y // 1000})")
            return
        with self.friends_lock:
            if target_client_id not in self.friends:
                print("You must be friends to view their location.")
                return
        request_message = json.dumps({
            "type": "request_location",
            "client_id": self.username,
            "target_client_id": target_client_id,
        })
        self.send_message(request_message)
        print(f"Requested location from client {target_client_id}")

    def send_location(self, to_client_id):
        if not self.grid_location:
            print("Error: Grid location system not initialized")
            return
        try:
            timestamp = int(time.time())
            cell = self.grid_location.coordinates_to_cell(self.x, self.y)

            # Get recipient's public key first
            try:
                recipient_public_key = self.get_public_key(to_client_id)
            except Exception as e:
                print(f"Failed to get verified public key: {e}")
                return

            # Generate ephemeral key and derive shared key
            ephemeral_private = ec.generate_private_key(ec.SECP256K1())
            shared_key = ephemeral_private.exchange(
                ec.ECDH(),
                recipient_public_key
            )

            # Derive key for both encryption and proof
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing',
            ).derive(shared_key)

            # Generate location data with proof using derived key
            location_data = {
                "cell_x": cell[0],
                "cell_y": cell[1],
                "timestamp": timestamp,
                "proof": self.grid_location.generate_cell_proof(self.x, self.y, timestamp, derived_key)
            }

            # Encrypt location data
            encrypted_location = self.encrypt_for_recipient(to_client_id, location_data, ephemeral_private,
                                                            recipient_public_key)

            response_message = json.dumps({
                "type": "location_response",
                "to_client_id": to_client_id,
                "location": encrypted_location,
            })
            self.send_message(response_message)

        except Exception as e:
            print(f"DEBUG - Error in send_location: {e}")

    def proximity_check_cell(self, encrypted_location):
        try:
            print("\nDEBUG - Starting proximity check with detailed logging")
            print(f"DEBUG - My current location: cell ({self.x // 1000}, {self.y // 1000})")
            print("DEBUG - Steps:")

            # Step 1: Load ephemeral key
            print("DEBUG - 1. Loading ephemeral public key...")
            ephemeral_public_key_pem = b64decode(encrypted_location["ephemeral_public_key"])
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_pem)
            print("DEBUG - ✓ Ephemeral key loaded successfully")

            # Step 2: Generate shared key
            print("DEBUG - 2. Generating shared key...")
            shared_key = self.private_key.exchange(
                ec.ECDH(),
                ephemeral_public_key
            )
            print("DEBUG - ✓ Shared key generated")

            # Step 3: Derive separate keys
            print("DEBUG - 3. Deriving separate keys using HKDF...")
            encryption_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing-encryption',
            ).derive(shared_key)

            proof_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing-proof',
            ).derive(shared_key)
            print("DEBUG - ✓ Keys derived successfully")

            # Step 4: Decrypt with GCM
            print("DEBUG - 4. Starting GCM decryption and authentication...")
            try:
                nonce = b64decode(encrypted_location["nonce"])
                ciphertext = b64decode(encrypted_location["encrypted"])
                tag = b64decode(encrypted_location["tag"])

                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.GCM(nonce, tag)
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                location = json.loads(decrypted.decode())
                print("DEBUG - ✓ GCM authentication and decryption successful")
            except Exception as e:
                print(f"DEBUG - ✗ GCM authentication or decryption failed: {e}")
                return False, False

            # Step 5: Verify proof using proof_key
            print("DEBUG - 5. Verifying location proof...")
            try:
                if not self.grid_location.verify_cell_proof(
                        location["cell_x"],
                        location["cell_y"],
                        location["proof"],
                        location["timestamp"],
                        proof_key  # Use proof_key here
                ):
                    print("DEBUG - ✗ Location proof verification failed")
                    return False, False
                print("DEBUG - ✓ Location proof verified")
            except Exception as e:
                print(f"DEBUG - ✗ Error during proof verification: {e}")
                return False, False

            # Step 6: Check proximity
            print("DEBUG - 6. Checking cell proximity...")
            my_cell = self.grid_location.coordinates_to_cell(self.x, self.y)
            their_cell = (location["cell_x"], location["cell_y"])
            dx = abs(my_cell[0] - their_cell[0])
            dy = abs(my_cell[1] - their_cell[1])

            print(f"DEBUG - My cell: {my_cell}")
            print(f"DEBUG - Their cell: {their_cell}")
            print(f"DEBUG - Cell distance: dx={dx}, dy={dy}")

            is_same_cell = dx == 0 and dy == 0
            is_nearby = dx <= 1 and dy <= 1
            return is_nearby, is_same_cell

        except Exception as e:
            print("\nDEBUG - Unexpected error in proximity_check_cell:")
            print(f"DEBUG - Error type: {type(e).__name__}")
            print(f"DEBUG - Error message: {str(e)}")
            print(f"DEBUG - Error location: {e.__traceback__.tb_frame.f_code.co_name}")
            return False, False

    def add_friend(self, friend_username):
        if not self.is_logged_in:
            print("You must log in before adding a friend.")
            return
        message = json.dumps({
            "type": "add_friend",
            "username": self.username,
            "friend_username": friend_username,
        })
        self.send_message(message)

    def view_friend(self):
        if not self.is_logged_in:
            print("You must log in before viewing friends.")
            return
        message = json.dumps({"type": "view_friends", "username": self.username})
        self.send_message(message)

    def msg_user(self, to_client_id, message_data):
        response_message = json.dumps({
            "type": "message_user",
            "from_client_id": self.username,
            "to_client_id": to_client_id,
            "content": message_data,
        })
        self.send_message(response_message)
        print(f"Sent message to client {to_client_id}")

    def check_messages(self):
        message = json.dumps({
            "type": "get_messages",
            "username": self.username
        })
        self.send_message(message)

    def encrypt_for_recipient(self, to_client_id, data, ephemeral_private, recipient_public_key):
        try:
            # Generate shared secret using ECDH
            shared_key = ephemeral_private.exchange(
                ec.ECDH(),
                recipient_public_key
            )

            # Derive separate keys for encryption and proof
            encryption_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing-encryption',
            ).derive(shared_key)

            proof_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing-proof',
            ).derive(shared_key)

            # Generate random nonce for GCM
            nonce = os.urandom(12)

            # Create GCM cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce)
            )
            encryptor = cipher.encryptor()

            # Generate location proof using proof_key
            data['proof'] = self.grid_location.generate_cell_proof(
                self.x, self.y,
                data['timestamp'],
                proof_key  # Use proof_key here
            )

            # Convert data to bytes and encrypt
            data_bytes = json.dumps(data).encode()
            ciphertext = encryptor.update(data_bytes) + encryptor.finalize()

            return {
                "encrypted": b64encode(ciphertext).decode('utf-8'),
                "nonce": b64encode(nonce).decode('utf-8'),
                "tag": b64encode(encryptor.tag).decode('utf-8'),
                "ephemeral_public_key": b64encode(ephemeral_private.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8')
            }
        except Exception as e:
            print(f"DEBUG - Error in encrypt_for_recipient: {e}")
            raise

    def decrypt_location(self, encrypted_data):
        try:
            # Load ephemeral public key
            ephemeral_public_key_pem = b64decode(encrypted_data["ephemeral_public_key"])
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_pem)

            # Generate shared secret
            shared_key = self.private_key.exchange(
                ec.ECDH(),
                ephemeral_public_key
            )

            # Derive encryption key
            encryption_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'location-sharing-encryption',
            ).derive(shared_key)

            # Decode components
            nonce = b64decode(encrypted_data["nonce"])
            ciphertext = b64decode(encrypted_data["encrypted"])
            tag = b64decode(encrypted_data["tag"])

            # Create GCM cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce, tag)
            )
            decryptor = cipher.decryptor()

            # Decrypt and verify in one step
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Error decrypting location data: {e}")
            raise

    def sign_message(self, message):
        if not self.private_key:
            raise ValueError("No private key available - not logged in?")
        signature = self.private_key.sign(
            json.dumps(message).encode(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature, sender_public_key):
        try:
            sender_public_key.verify(
                b64decode(signature),
                json.dumps(message).encode(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def get_public_key(self, username):
        request = json.dumps({
            "type": "get_public_key",
            "target": username
        })
        self.send_message(request)
        response = json.loads(self.socket.recv(1024).decode("utf-8"))

        if response["type"] != "public_key_response":
            raise Exception("Failed to get public key")

        # Verify key timestamp
        key_created = response["key_created"]
        if not isinstance(key_created, int):
            raise Exception("Invalid key timestamp")

        public_key_pem = b64decode(response["public_key"])
        return serialization.load_pem_public_key(public_key_pem)

    def send_friend_request(self, friend_username):
        message = json.dumps({
            "type": "friend_request",
            "from": self.username,
            "to": friend_username
        })
        self.send_message(message)

    def view_friend_requests(self):
        message = json.dumps({
            "type": "get_friend_requests",
            "username": self.username
        })
        self.send_message(message)

    def accept_friend_request(self, requestor):
        message = json.dumps({
            "type": "accept_friend_request",
            "from": requestor,
            "to": self.username
        })
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
            print("\n" + "="*50)  # Add separator line
            print("Main Menu")
            print("4. Update Location")
            print("5. Check Cell")
            print("6. Send Friend Request")
            print("7. View Friend Requests")
            print("8. Accept Friend Request")
            print("9. View Friends")
            print("10. Send Message")
            print("11. Check Messages")
            print("12. Exit")
            print("="*50 + "\n")  # Add separator line
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
                    friend = input("Enter friend's username: ")
                    msg = input("Enter message: ")
                    client.msg_user(friend, msg)
                elif choice == "11":
                    client.check_messages()
                elif choice == "12":
                    break
            except Exception as e:
                print(f"Error: {e}")
    client.close()
