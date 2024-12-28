import os
import time
import platform
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore

# Function to generate a random AES key
def generate_key():
    return os.urandom(16)  # 128-bit key

# Function to encrypt text
def encrypt_text(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return cipher.iv, ct_bytes

# Function to decrypt text
def decrypt_text(iv, encrypted_data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

# Function to encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv, ct_bytes

# Function to decrypt a file
def decrypt_file(iv, encrypted_data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Function to print OS and hardware information
def print_system_info():
    os_info = platform.uname()
    print("\n\nHardware model Information")
    print(f"Processor: {os_info.processor}")
    print(f"Machine Type: {os_info.machine}")
    print(f"Processor Type: {os_info.processor}")
    print("\nOperating System Information")
    print(f"Operating Sytem used: {os_info.system}")
    print(f"Release: {os_info.release}")
    print(f"Version: {os_info.version}")
    print(f"Machine: {os_info.machine}")

# Main function to select data type and encrypt
def main():

    print("\nSelect the type of data to encrypt:")
    print("1. Text")
    print("2. File")
    
    choice = input("Enter your choice (1 or 2): ")

    # Measure time to generate key
    start_time = time.perf_counter()
    key = generate_key()
    key_generation_time = time.perf_counter() - start_time
    print(f"Key generation time: {key_generation_time:.10f} seconds")

    if choice == '1':
        plain_text = input("Enter the text to encrypt: ")

        # Measure time to encrypt
        start_time = time.perf_counter()
        iv, encrypted_data = encrypt_text(plain_text, key)
        encryption_time = time.perf_counter() - start_time
        print(f"Encryption time: {encryption_time:.10f} seconds")

        # Measure time to decrypt
        start_time = time.perf_counter()
        decrypted_text = decrypt_text(iv, encrypted_data, key)
        decryption_time = time.perf_counter() - start_time
        print(f"Decryption time: {decryption_time:.10f} seconds")

        # Display results
        print(f"IV: {iv.hex()}")
        print(f"Encrypted Data: {encrypted_data.hex()}")
        print(f"Decrypted Text: {decrypted_text}")

    elif choice == '2':
        file_path = input("Enter the path of the file to encrypt: ")

        # Measure time to encrypt
        start_time = time.perf_counter()
        iv, encrypted_data = encrypt_file(file_path, key)
        encryption_time = time.perf_counter() - start_time
        print(f"Encryption time: {encryption_time:.10f} seconds")

        # Measure time to decrypt
        start_time = time.perf_counter()
        decrypted_data = decrypt_file(iv, encrypted_data, key)
        decryption_time = time.perf_counter() - start_time
        print(f"Decryption time: {decryption_time:.10f} seconds")

        # Display results
        print(f"IV: {iv.hex()}")
        print(f"Encrypted Data: {encrypted_data.hex()}")
        print(f"Decrypted Data (as bytes): {decrypted_data.hex()}")

    else:
        print("Invalid choice. Please select 1 or 2.")

    # Print system information
    print_system_info()

if __name__ == "__main__":
    main()