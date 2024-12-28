import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

def generate_key():
    return os.urandom(16)  # 128 bits = 16 bytes

def encrypt(message, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + encrypted).decode('utf-8')  # Return base64 encoded string

def decrypt(encrypted_message, key):
    encrypted_message = b64decode(encrypted_message)
    iv = encrypted_message[:16]  # Extract the IV
    encrypted_data = encrypted_message[16:]  # Extract the encrypted data
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the decrypted message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted.decode('utf-8')

def main():
    message = input("Enter a message to encrypt: ")
    
    # Measure time to generate key
    start_time = time.time()
    key = generate_key()
    key_generation_time = time.time() - start_time
    print(f"Key generation time: {key_generation_time:.50f} seconds")
    
    # Measure time to encrypt
    start_time = time.time()
    encrypted_message = encrypt(message, key)
    encryption_time = time.time() - start_time
    print(f"Encryption time: {encryption_time:.50f} seconds")
    
    print(f"Encrypted message: {encrypted_message}")
    
    # Measure time to decrypt
    start_time = time.time()
    decrypted_message = decrypt(encrypted_message, key)
    decryption_time = time.time() - start_time
    print(f"Decryption time: {decryption_time:.50f} seconds")
    
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()