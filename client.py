import socket
import json
import rsa
import des


class SecureClient:

    def __init__(self, username, pka_host='localhost', pka_port=5000):
        self.username = username
        self.pka_host = pka_host
        self.pka_port = pka_port
        
 
        self.generate_rsa_keys()
        
        self.register_to_pka()

    def generate_rsa_keys(self):
        p, q = 93, 89
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        e = rsa.generate_e(phi_n)
        d = rsa.mod_inverse(e, phi_n)
        
        self.public_key = {"e": e, "n": n}
        self.private_key = {"d": d, "n": n}
        
        print(f"Public key {self.username}: {self.public_key}")
        print(f"Private key {self.username}: {self.private_key}")

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

    def get_public_key(self, target_username):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pka_host, self.pka_port))
            
            request = {
                "type": "get_public_key",
                "username": target_username
            }
            
            sock.send(json.dumps(request).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            
            response_data = json.loads(response)
            
            if 'error' in response_data:
                print(f"Error: {response_data['error']}")
                raise Exception(response_data['error'])
            
            return response_data

    def establish_secure_session(self, target_username, host='localhost', port=6000):
        des_key = "0000000000000ABC"  

        print(f"DES key generated: {des_key}")
        
        target_public_key = self.get_public_key(target_username)
        print(f"Public key {target_username}: {target_public_key}")
        
        encrypted_des_key = rsa.encrypt(des_key.encode(), target_public_key)
        print(f"Encrypted DES key: {encrypted_des_key}")
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        
        payload = json.dumps({
            "sender": self.username,
            "encrypted_des_key": str(encrypted_des_key)
        })
        client_socket.send(payload.encode())
        print(f"DES key has been sent to {target_username}.")
        
        rkb, rk = des.generate_keys(des_key)
        
        while True:
            message = input(f"Message to {target_username} (type 'exit' to exit): ")
            
            if message.lower() == 'exit':
                break
            
            encrypted_msg = des.encrypt(message, rkb, rk, is_ascii=True)
            print(f"Encrypted message to {target_username}: {encrypted_msg}")
            client_socket.send(encrypted_msg.encode())
            
            encrypted_response = client_socket.recv(1024).decode()
            response = des.decrypt(encrypted_response, rkb, rk, is_ascii=True)
            print(f"Decrypted message from {target_username}: {response}")
            
        
        client_socket.close()

if __name__ == "__main__":
    username = input("Enter your username: ")
    client = SecureClient(username)
    
    target = input("Enter destination username: ")
    client.establish_secure_session(target)
