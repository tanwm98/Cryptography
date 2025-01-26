import socket
import json

class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.username = None
        
    def connect(self, host='localhost', port=5000):
        try:
            self.sock.connect((host, port))
            self.connected = True
            return True
        except:
            return False

    def send_request(self, data):
        try:
            if not self.connected:
                return {'status': 'error', 'message': 'Not connected to server'}
            self.sock.send(json.dumps(data).encode())
            response = self.sock.recv(1024).decode()
            return json.loads(response)
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

def main():
    client = Client()
    
    while True:
        print("\nLocation Privacy App")
        print("1. Connect to server")
        print("2. Register")
        print("3. Login")
        print("4. Update Location")
        print("5. Check Cell")
        print("6. Send Friend Request")
        print("7. View Friend Requests")
        print("8. Accept Friend Request")
        print("9. View Friends")
        print("10. Send Message")
        print("11. Check Messages")
        print("12. Exit")
        
        choice = input("Enter choice (1-12): ")
        
        if choice == '1':
            if client.connect():
                print("Connected to server")
            else:
                print("Connection failed")
                
        elif choice == '2':
            username = input("Username: ")
            password = input("Password: ")
            response = client.send_request({
                'action': 'register',
                'username': username,
                'password': password
            })
            print(response['message'])
            if response['status'] == 'success':
                client.username = username
            
        elif choice == '3':
            username = input("Username: ")
            password = input("Password: ")
            response = client.send_request({
                'action': 'login',
                'username': username,
                'password': password
            })
            print(response['message'])
            if response['status'] == 'success':
                client.username = username
                
        elif choice == '4':
            if not client.username:
                print("Please login first")
                continue
            try:
                x = int(input("X coordinate (0-99999): "))
                y = int(input("Y coordinate (0-99999): "))
                response = client.send_request({
                    'action': 'update_location',
                    'username': client.username,
                    'x': x,
                    'y': y
                })
                print(response['message'])
            except ValueError:
                print("Invalid coordinates")
                
        elif choice == '5':
            if not client.username:
                print("Please login first")
                continue
            response = client.send_request({
                'action': 'get_cell',
                'username': client.username
            })
            if response['status'] == 'success':
                print(f"Current cell: {response['cell']}")
            else:
                print(response['message'])

        elif choice == '6':
            if not client.username:
                print("Please login first")
                continue
            to_user = input("Enter username to send friend request: ")
            response = client.send_request({
                'action': 'send_friend_request',
                'from_user': client.username,
                'to_user': to_user
            })
            print(response['message'])

        elif choice == '7':
            if not client.username:
                print("Please login first")
                continue
            response = client.send_request({
                'action': 'get_friend_requests',
                'username': client.username
            })
            if response['status'] == 'success':
                if not response['requests']:
                    print("No pending friend requests")
                else:
                    print("Pending friend requests from:")
                    for user in response['requests']:
                        print(f"- {user}")
            else:
                print(response['message'])

        elif choice == '8':
            if not client.username:
                print("Please login first")
                continue
            from_user = input("Enter username to accept friend request from: ")
            response = client.send_request({
                'action': 'accept_friend_request',
                'from_user': from_user,
                'to_user': client.username
            })
            print(response['message'])

        elif choice == '9':
            if not client.username:
                print("Please login first")
                continue
            response = client.send_request({
                'action': 'get_friends',
                'username': client.username
            })
            if response['status'] == 'success':
                if not response['friends']:
                    print("No friends yet")
                else:
                    print("Friends list:")
                    for friend in response['friends']:
                        print(f"- {friend}")
            else:
                print(response['message'])
            
        elif choice == '10':
            if not client.username:
                print("Please login first")
                continue
            to_user = input("Enter username to send message to: ")
            content = input("Enter message: ")
            response = client.send_request({
                'action': 'send_message',
                'from_user': client.username,
                'to_user': to_user,
                'content': content
            })
            print(response['message'])

        elif choice == '11':
            if not client.username:
                print("Please login first")
                continue
            response = client.send_request({
                'action': 'get_messages',
                'username': client.username
            })
            if response['status'] == 'success':
                if not response['messages']:
                    print("No new messages")
                else:
                    print("\nMessages:")
                    for msg in response['messages']:
                        print(f"From {msg['from']}: {msg['content']}")
            else:
                print(response['message'])

        elif choice == '12':
            break

if __name__ == '__main__':
    main()