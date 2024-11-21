import socket
import des
import json
import rsa

class SecureServer:
    def __init__(self, username, private_key, public_key, pka_host='localhost', pka_port=5000, host='localhost', port=6000):
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.host = host
        self.port = port

        self.des_key = None
        self.rk = None

        self.register_to_pka()

    def register_to_pka(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pka_host, self.pka_port))
            
            register_request = {
                "type": "register",
                "username": self.username,
                "public_key": self.public_key
            }
            
            sock.send(json.dumps(register_request).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            print(f"Public key authority response: {response}")

    def get_public_key(self, username):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pka_host, self.pka_port))
            
            request = {
                "type": "get_public_key",
                "username": username
            }
            
            sock.send(json.dumps(request).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            response_data = json.loads(response)
            
            if 'error' in response_data:
                print(f"Error: {response_data['error']}")
                raise Exception(response_data['error'])
            
            return response_data

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Server {self.username} waiting for connection...")

        try:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr}")

            payload = conn.recv(1024).decode()
            payload_data = json.loads(payload)
            
            sender = payload_data['sender']
            encrypted_des_key = int(payload_data['encrypted_des_key'])
            
            print(f"Encrypted DES key received from {sender}: {encrypted_des_key}")

            target_public_key = self.get_public_key(sender)
            print(f"Public key {sender} (from public key authority): {target_public_key}")

            self.des_key = rsa.decrypt(encrypted_des_key, self.private_key)

            print(f"Decrypted DES key: {self.des_key}")

            self.rkb, self.rk = des.generate_keys(self.des_key)

            print(f"A secure session with {sender} has been created")

            self.handle_communication(conn, sender)

        except Exception as e:
            print(f"An error occured: {e}")
            conn.close()
            server_socket.close()

    def handle_communication(self, conn, sender):
        while True:
            encrypted_msg = conn.recv(1024).decode()
            print(f"Encrypted message from {sender}: {encrypted_msg}")
            
            decrypted_msg = des.decrypt(encrypted_msg, self.rkb, self.rk, is_ascii=True)
            print(f"Decrypted message from {sender}: {decrypted_msg}")

            reply = input(f"Reply message to {sender}: ")
            
            encrypted_reply = des.encrypt(reply, self.rkb, self.rk, is_ascii=True)
            
            print(f"Encrypted message to {sender}: {encrypted_reply}")

            conn.send(encrypted_reply.encode())

if __name__ == "__main__":
    username = input("Enter server username: ")
    
    p, q = 97, 89
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    e = rsa.generate_e(phi_n)
    d = rsa.mod_inverse(e, phi_n)
    
    private_key = {"d": d, "n": n}
    public_key = {"e": e, "n": n}
    
    print(f"Server private key ({username}): {private_key}")
    print(f"Server public key ({username}): {public_key}")
    
    server = SecureServer(username, private_key, public_key)
    server.start_server()
