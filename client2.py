import socket
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#This code will be the clientMain code (meaning the code that will be front facing).
#Messages will be sent from the cleint code to a listening server.
#listenMessage in server.py will recieve this message and display it. 
#Ref: 
#https://realpython.com/python-sockets/
#chatGPT (debugging)


def generate_shared_key(seed="Rishikk".encode('utf-8'), key_length=16):
    # Generate a random seed if not provided
    if seed is None:
        seed = os.urandom(32)  # 32 bytes for a strong seed 
    # Use SHA-256 hash function to derive a fixed-length key
    hashed_seed = hashlib.sha256(seed).digest()
    # Truncate the hash to the desired key length
    shared_key = hashed_seed[:key_length]
    return shared_key

# Example usage
shared_key = generate_shared_key()

nonce = b'\x00' * 16
associated_data = b'CS645/745 Modern Cryptography: Secure Messaging'

def encrypt_message(message, key, nonce, associated_data):
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), associated_data)
    return ciphertext

def clientMain():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Enter the IP address of the other computer (can find from running IP config and looking at the ipv4 address)
    server_ip = input("Enter the server IP: ")
    #Enter the port the other computer's server.py is listening on.
    server_port = int(input("Enter the server port: "))

    client.connect((server_ip, server_port))

    while True:
        message = input("Type a message to send (press Enter to send): ")
        ciphertext = encrypt_message(message, shared_key, nonce, associated_data)
        if message.lower() == 'exit':
            break
        client.send(ciphertext)
        response = client.recv(1024).decode('utf-8')
        print(f"Server response: {response}")

    client.close()

if __name__ == "__main__":

    clientMain()