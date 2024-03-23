# Import fungsi enkripsi dan dekripsi dari cipher
from backend.cipher import encrypt, decrypt
from backend.utils import *

# Fungsi untuk enkripsi pesan menggunakan mode CFB 8 bit
def cfb_encrypt(plaintext: str, key: str, iv: str) -> bytes:
    """RamadhanCipher cfb-mode encryption function

    plaintext : text to be encrypted
    key       : external key
    iv        : initialization vector
    """
    ciphertext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_ciphertext_block = bytes(iv, 'utf-8')
    # Iterasi melalui setiap byte dalam plaintext
    for byte in plaintext:
        # Enkripsi blok sebelumnya untuk digunakan sebagai IV
        encrypted_iv = encrypt(previous_ciphertext_block, bytes(key, 'utf-8'))
        # XOR byte plaintext dengan byte hasil enkripsi IV untuk mendapatkan byte ciphertext
        ciphertext_byte = bytes([p ^ i for p, i in zip(bytes(byte, 'utf-8'), int.to_bytes(encrypted_iv[0], 1, 'big'))]) 
        # Tambahkan byte ciphertext ke ciphertext
        ciphertext += ciphertext_byte
        # Perbarui blok sebelumnya dengan byte ciphertext yang baru saja dihasilkan
        previous_ciphertext_block = previous_ciphertext_block[1:] + ciphertext_byte
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode CFB 8 bit
def cfb_decrypt(ciphertext: str, key: str, iv: str) -> str:
    """RamadhanCipher cfb-mode decryption function

    ciphertext : text (in hex) to be decrypted
    key        : external key
    iv         : initialization vector
    """
    plaintext = b''
    ciphertext = bytes.fromhex(ciphertext)
    # Menginisialisasi IV untuk blok pertama
    previous_ciphertext_block = bytes(iv, 'utf-8')
    # Iterasi melalui setiap byte dalam ciphertext
    for byte in ciphertext:
        # Enkripsi blok sebelumnya untuk digunakan sebagai IV
        encrypted_iv = encrypt(previous_ciphertext_block, bytes(key, 'utf-8'))
        # XOR byte ciphertext dengan byte hasil enkripsi IV untuk mendapatkan byte plaintext
        plaintext_byte = bytes([p ^ i for p, i in zip(int.to_bytes(byte, 1, 'big'), int.to_bytes(encrypted_iv[0], 1, 'big'))])
        # Tambahkan byte plaintext ke plaintext
        plaintext += plaintext_byte
        # Perbarui blok sebelumnya dengan byte ciphertext yang baru saja dihasilkan
        previous_ciphertext_block = previous_ciphertext_block[1:] + int.to_bytes(byte, 1, 'big')
    return plaintext.decode('utf-8')

# Test
import string
import random
import time

if __name__ == '__main__':
    plain_text = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=32))
    key = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=16))
    iv = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=16))

    print("===== START CFB - RAMADHAN CIPHER TESTING =====")
    print("Plain text:\t", plain_text)
    print("Key:\t\t", key)
    print("IV:\t\t", iv)

    start_time = time.time()
    encrypted_text = cfb_encrypt(plain_text, key, iv)
    end_time = time.time()
    print("\nEncrypting...")
    print("Encrypted hex:\t", bytes.hex(encrypted_text))
    print("Time to encrypt:\t", end_time - start_time)

    start_time = time.time()
    decrypted_text = cfb_decrypt(bytes.hex(encrypted_text), key, iv)
    end_time = time.time()
    print("\nDecrypting...")
    print("Decrypted text:\t", decrypted_text)
    print("Time to decrypt:\t", end_time - start_time)

    print("\nResult:\t", plain_text == decrypted_text)
    print("===============================================")
