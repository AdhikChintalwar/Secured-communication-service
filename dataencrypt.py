from pyascon.ascon import ascon_encrypt, ascon_decrypt
import hashlib
import os

# Function to generate a shared key from a random seed
def generate_shared_key(seed="Manishkk".encode('utf-8'), key_length=16):
    # Generating a random seed if not provided
    if seed is None:
        seed = os.urandom(32)  
    # Use SHA-256 hash function to derive a fixed-length key
    hashed_seed = hashlib.sha256(seed).digest()
    # Truncating the hash to the desired key length
    shared_key = hashed_seed[:key_length]
    return shared_key

shared_key = generate_shared_key()
  

def encrypt_and_save(message, key, nonce, associated_data, variant="Ascon-128", filename="encrypted.txt"):
    ciphertext_and_tag = ascon_encrypt(key, nonce, associated_data, message, variant=variant)
    with open(filename, "wb") as file:
        file.write(ciphertext_and_tag)

# Function to read ciphertext from a text file and decrypt it
def read_and_decrypt(filename, key, nonce, associated_data, variant="Ascon-128"):
    with open(filename, "rb") as file:
        ciphertext_and_tag = file.read()
    plaintext = ascon_decrypt(key, nonce, associated_data, ciphertext_and_tag, variant=variant)
    if plaintext is not None:
        return plaintext.decode()
    else:
        return "Decryption failed or the file has been tampered with."


nonce = b'\x00' * 16
associated_data = b'CS645/745 Modern Cryptography: Secure Messaging'

# Encrypting a text message
message = "Hello, this is CS645 class.".encode('utf-8')
ciphertext_and_tag = encrypt_and_save(message, shared_key, nonce, associated_data)


# # Read the encrypted file, decrypt it, and print the plaintext
decrypted_message = read_and_decrypt("encrypted.txt", shared_key, nonce, associated_data)
print("Decrypted Message:", decrypted_message)