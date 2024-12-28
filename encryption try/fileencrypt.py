import os
import time
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.primitives import padding # type: ignore
from base64 import b64encode, b64decode

def generate_key():
    return os.urandom(16)  # 128 bits = 16 bytes

def encrypt_file(file_path, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file data
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Pad the file data to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded data
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to a new file
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(iv + encrypted)  # Prepend IV to the encrypted data

    return encrypted_file_path

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()

    iv = encrypted_data[:16]  # Extract the IV
    encrypted_file_data = encrypted_data[16:]  # Extract the encrypted data

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded = decryptor.update(encrypted_file_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Write the decrypted data to a new file
    decrypted_file_path = encrypted_file_path.replace('.enc', '.dec')
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    return decrypted_file_path

def main():
    file_path = input("Enter the path of the file to encrypt (image, video, audio): ")
    # Measure time to generate key
    start_time = time.perf_counter()
    key = generate_key()
    key_generation_time = time.perf_counter() - start_time
    print(f"Key generation time: {key_generation_time:.10f} seconds")

    # Measure time to encrypt
    start_time = time.time()
    encrypted_file_path = encrypt_file(file_path, key)
    encryption_time = time.time() - start_time
    print(f"Encryption time: {encryption_time:.6f} seconds")
    print(f"Encrypted file created: {encrypted_file_path}")

    # Measure time to decrypt
    start_time = time.time()
    decrypted_file_path = decrypt_file(encrypted_file_path, key)
    decryption_time = time.time() - start_time
    print(f"Decryption time: {decryption_time:.6f} seconds")
    print(f"Decrypted file created: {decrypted_file_path}")

if __name__ == "__main__":
    main()