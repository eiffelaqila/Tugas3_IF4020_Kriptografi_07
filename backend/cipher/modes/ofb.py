# Import fungsi enkripsi dan dekripsi dari cipher
from backend.cipher import encrypt, decrypt

# Fungsi untuk enkripsi pesan menggunakan mode OFB 8 bit
def ofb_encrypt(plaintext: bytes, key: str, iv: str) -> bytes:
    """RamadhanCipher ofb-mode encryption function

    plaintext : text to be encrypted
    key       : external key
    iv        : initialization vector
    """
    ciphertext = b''
    if (len(plaintext) % 16 > 0):
        plaintext = plaintext + bytes(16 - len(plaintext) % 16)
    # Menginisialisasi IV untuk blok pertama
    previous_iv = bytes(iv, 'utf-8')
    # Iterasi melalui setiap byte dalam plaintext
    for byte in plaintext:
        # Enkripsi IV untuk digunakan sebagai keystream
        keystream = encrypt(previous_iv, bytes(key, 'utf-8'))
        # XOR byte plaintext dengan byte keystream untuk mendapatkan byte ciphertext
        ciphertext_byte = bytes([p ^ i for p, i in zip(int.to_bytes(byte, 1, 'big'), int.to_bytes(keystream[0], 1, 'big'))])
        # Tambahkan byte ciphertext ke ciphertext
        ciphertext += ciphertext_byte
        # Perbarui IV dengan keystream yang baru saja dihasilkan
        previous_iv = previous_iv[1:] + int.to_bytes(keystream[0], 1, 'big')
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode OFB 8 bit
def ofb_decrypt(ciphertext: bytes, key: str, iv: str) -> bytes:
    """RamadhanCipher ofb-mode decryption function

    ciphertext : text (in hex) to be decrypted
    key        : external key
    iv         : initialization vector
    """
    plaintext = b''
    if type(ciphertext) == str:
      ciphertext = bytes.fromhex(ciphertext)
    # Menginisialisasi IV untuk blok pertama
    previous_iv = bytes(iv, 'utf-8')
    # Iterasi melalui setiap byte dalam plaintext
    for byte in ciphertext:
        # Enkripsi IV untuk digunakan sebagai keystream
        keystream = encrypt(previous_iv, bytes(key, 'utf-8'))
        # XOR byte plaintext dengan byte keystream untuk mendapatkan byte ciphertext
        plaintext_byte = bytes([p ^ i for p, i in zip(int.to_bytes(byte, 1, 'big'), int.to_bytes(keystream[0], 1, 'big'))])
        # Tambahkan byte plaintext ke plaintext
        plaintext += plaintext_byte
        # Perbarui IV dengan keystream yang baru saja dihasilkan
        previous_iv = previous_iv[1:] + int.to_bytes(keystream[0], 1, 'big')
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

    print("===== START OFB - RAMADHAN CIPHER TESTING =====")
    print("Plain text:\t", plain_text)
    print("Key:\t\t", key)
    print("IV:\t\t", iv)

    start_time = time.time()
    encrypted_text = ofb_encrypt(bytes(plain_text, 'utf-8'), key, iv)
    end_time = time.time()
    print("\nEncrypting...")
    print("Encrypted hex:\t", bytes.hex(encrypted_text))
    print("Time to encrypt:\t", end_time - start_time)

    start_time = time.time()
    decrypted_text = ofb_decrypt(encrypted_text, key, iv)
    end_time = time.time()
    print("\nDecrypting...")
    print("Decrypted text:\t", decrypted_text.decode('utf-8'))
    print("Time to decrypt:\t", end_time - start_time)

    print("\nResult:\t", plain_text == decrypted_text.decode('utf-8'))
    print("===============================================")
