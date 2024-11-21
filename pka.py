import socket
import json
import os
import traceback

class PublicKeyAuthority:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.public_keys = {}
        self.keys_dir = 'public_keys'
        
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Public key authority server running on {self.host}:{self.port}")

        while True:
            conn, addr = server_socket.accept()
            
            try:
                data = conn.recv(1024).decode('utf-8')
                request = json.loads(data)
                
                if request['type'] == 'register':
                    self.register_public_key(request['username'], request['public_key'], conn)
                elif request['type'] == 'get_public_key':
                    self.send_public_key(request['username'], conn)
            
            except Exception as e:
                print(f"Error: {e}")
                traceback.print_exc()  
                conn.send(json.dumps({"error": str(e)}).encode('utf-8'))
            
            conn.close()

    def register_public_key(self, username, public_key, conn):
        try:
            with open(os.path.join(self.keys_dir, f"{username}_public_key.json"), 'w') as f:
                json.dump(public_key, f)
            
            self.public_keys[username] = public_key
            print(f"Public key for {username} has been registered")
            conn.send(json.dumps({"status": "success"}).encode('utf-8'))
        except Exception as e:
            print(f"Registration error: {e}")
            conn.send(json.dumps({"error": str(e)}).encode('utf-8'))

    def send_public_key(self, username, conn):
        try:
            
            file_path = os.path.join(self.keys_dir, f"{username}_public_key.json")
            
            if not os.path.exists(file_path):

                error_response = json.dumps({
                    "error": f"Public key for {username} not found"
                })
                conn.send(error_response.encode('utf-8'))
                print(f"Public key {username} not found")
                return

            with open(file_path, 'r') as f:
                public_key = json.load(f)
            
            conn.send(json.dumps(public_key).encode('utf-8'))
        except Exception as e:
            print(f"Error key delivery: {e}")
            error_response = json.dumps({
                "error": f"Failed to retrieve key: {str(e)}"
            })
            conn.send(error_response.encode('utf-8'))

if __name__ == "__main__":
    pka_server = PublicKeyAuthority()
    pka_server.start_server()