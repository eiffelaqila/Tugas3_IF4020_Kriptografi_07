# Import fungsi enkripsi dan dekripsi dari cipher
from backend.cipher import encrypt, decrypt
from backend.utils import *

# Fungsi untuk enkripsi satu blok pesan menggunakan mode CBC
def cbc_encrypt_block(plaintext_block: bytes, key: bytes, iv: bytes):
    # XOR blok pesan dengan IV (Initialization Vector)
    plaintext_block_xor_iv = bytes([p ^ i for p, i in zip(plaintext_block, iv)])
    # Enkripsi hasil XOR dengan kunci
    ciphertext_block = encrypt(plaintext_block_xor_iv, key)
    return ciphertext_block

# Fungsi untuk dekripsi satu blok pesan menggunakan mode CBC
def cbc_decrypt_block(ciphertext_block: bytes, key: bytes, iv: bytes):
    # Dekripsi blok ciphertext menggunakan kunci
    decrypted_block = decrypt(ciphertext_block, key)
    # XOR hasil dekripsi dengan IV (Initialization Vector)
    plaintext_block = bytes([p ^ i for p, i in zip(decrypted_block, iv)])
    return plaintext_block

# Fungsi untuk enkripsi pesan menggunakan mode CBC
def cbc_encrypt(plaintext: bytes, key: str, iv: str) -> bytes:
    """RamadhanCipher cbc-mode encryption function

    plaintext : text to be encrypted
    key       : external key
    iv        : initialization vector
    """
    ciphertext = b''
    if (len(plaintext) % 16 > 0):
        plaintext = plaintext + bytes(16 - len(plaintext) % 16)

    # Menginisialisasi IV untuk blok pertama
    previous_cipher_block = bytes(iv, 'utf-8')
    # Membagi pesan menjadi blok-blok 128 bit
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i+16]
        # Enkripsi setiap blok pesan dan tambahkan ke ciphertext
        ciphertext_block = cbc_encrypt_block(plaintext_block, bytes(key, 'utf-8'), previous_cipher_block)
        ciphertext += ciphertext_block
        # Update IV untuk blok berikutnya
        previous_cipher_block = ciphertext_block
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode CBC
def cbc_decrypt(ciphertext: bytes, key: str, iv: str) -> bytes:
    """RamadhanCipher cbc-mode decryption function

    ciphertext : text (in hex) to be decrypted
    key        : external key
    iv         : initialization vector
    """
    plaintext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_cipher_block = bytes(iv, 'utf-8')
    # Membagi ciphertext menjadi blok-blok 128 bit
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i+16]
        # Dekripsi setiap blok ciphertext dan tambahkan ke plaintext
        plaintext_block = cbc_decrypt_block(ciphertext_block, bytes(key, 'utf-8'), previous_cipher_block)
        plaintext += plaintext_block
        # Update IV untuk blok berikutnya
        previous_cipher_block = ciphertext_block
    plaintext = plaintext.rstrip(b'\x00')
    return plaintext

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

    print("===== START CBC - RAMADHAN CIPHER TESTING =====")
    print("Plain text:\t", plain_text)
    print("Key:\t\t", key)
    print("IV:\t\t", iv)

    start_time = time.time()
    encrypted_text = cbc_encrypt(bytes(plain_text, 'utf-8'), key, iv)
    end_time = time.time()
    print("\nEncrypting...")
    print("Encrypted hex:\t", bytes.hex(encrypted_text))
    print("Time to encrypt:\t", end_time - start_time)

    start_time = time.time()
    decrypted_text = cbc_decrypt(encrypted_text, key, iv)
    end_time = time.time()
    print("\nDecrypting...")
    print("Decrypted text:\t", decrypted_text.decode('utf-8'))
    print("Time to decrypt:\t", end_time - start_time)

    print("\nResult:\t", plain_text == decrypted_text.decode('utf-8'))
    print("===============================================")
