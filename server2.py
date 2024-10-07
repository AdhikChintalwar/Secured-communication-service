import socket
import threading
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#This code will act as the server. 
#The server will handle receiving information fron a client on a network, as well as connecting.
#server.py will ask for the port to be listening on. Please input the port that you would like this server to listen onto.
#Ref: 
#https://realpython.com/python-sockets/
#chatGPT (debugging)
def generate_shared_key(seed="Manishkk".encode('utf-8'), key_length=16):
    # Generating a random seed if not provided
    if seed is None:
        seed = os.urandom(32)  # 32 bytes for a strong seed
    # Using SHA-256 hash function to derive a fixed-length key
    hashed_seed = hashlib.sha256(seed).digest()
    # Truncating the hash to the desired key length
    shared_key = hashed_seed[:key_length]
    return shared_key

shared_key = generate_shared_key()

nonce = b'\x00' * 16
associated_data = b'CS645/745 Modern Cryptography: Secure Messaging'

def decrypt_message(ciphertext, key, nonce, associated_data):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext.decode()

def listenForMessage(client_socket):
    while True:
        ciphertext = client_socket.recv(1024)
        if not ciphertext:
            break
        print(f"Received ciphertext from client: {ciphertext}")
        # Decrypting the ciphertext
        plaintext = decrypt_message(ciphertext, shared_key, nonce, associated_data)
        print(f"Decrypted message: {plaintext}")
        response = "Message received."
        client_socket.send(response.encode('utf-8'))
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   #This is where you will select what port you would like the server.py on this pc to listen on.
    port_str = input("Enter the port you would like to lsiten on: ")
    port = int(port_str)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print("[*] Listening on 0.0.0.0:" + port_str)

    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
        messageListnening = threading.Thread(target=listenForMessage, args=(client,))
        messageListnening.start()

if __name__ == "__main__":
    start_server()