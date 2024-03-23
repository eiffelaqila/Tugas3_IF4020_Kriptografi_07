# Import fungsi enkripsi dari cipher
from backend.cipher import encrypt, decrypt

# Fungsi untuk menghasilkan nilai counter berikutnya
def generate_next_counter(counter: int) -> tuple[int, bytes]:
    # Konversi nilai counter menjadi bytes
    counter_bytes = counter.to_bytes(16, byteorder='big')
    # Tambahkan 1 ke nilai counter
    next_counter = counter + 1
    return next_counter, counter_bytes

# Fungsi untuk enkripsi satu blok pesan menggunakan mode Counter
def counter_encrypt_block(plaintext_block: bytes, key: bytes, counter: int):
    # Dapatkan nilai counter berikutnya dan konversi ke bytes
    counter, counter_bytes = generate_next_counter(counter)
    # Enkripsi nilai counter menggunakan kunci
    encrypted_counter = encrypt(counter_bytes, key)
    # XOR hasil enkripsi counter dengan plaintext blok untuk mendapatkan ciphertext blok
    ciphertext_block = bytes([p ^ e for p, e in zip(plaintext_block, encrypted_counter)])
    return ciphertext_block, counter

# Fungsi untuk enkripsi pesan menggunakan mode Counter
def counter_encrypt(plaintext: str, key: str, counter: str):
    ciphertext = b''
    counter = int.from_bytes(bytes(counter, 'utf-8'), 'big')
    # Iterasi melalui setiap blok dalam plaintext
    for i in range(0, len(plaintext), 16):
        plaintext_block = bytes(plaintext[i:i+16], 'utf-8')
        # Enkripsi blok pesan menggunakan mode Counter
        ciphertext_block, counter = counter_encrypt_block(plaintext_block, bytes(key, 'utf-8'), counter)
        # Tambahkan blok ciphertext ke ciphertext
        ciphertext += ciphertext_block
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode Counter (sama dengan enkripsi dalam Counter)
def counter_decrypt(ciphertext, key, counter):
    plaintext = b''
    ciphertext = bytes.fromhex(ciphertext)
    counter = int.from_bytes(bytes(counter, 'utf-8'), 'big')
    # Iterasi melalui setiap blok dalam plaintext
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i+16]
        # Enkripsi blok pesan menggunakan mode Counter
        plaintext_block, counter = counter_encrypt_block(ciphertext_block, bytes(key, 'utf-8'), counter)
        # Tambahkan blok ciphertext ke plaintext
        plaintext += plaintext_block
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
    counter = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=16))

    print("===== START COUNTER - RAMADHAN CIPHER TESTING =====")
    print("Plain text:\t", plain_text)
    print("Key:\t\t", key)
    print("Counter:\t\t", counter)

    start_time = time.time()
    encrypted_text = counter_encrypt(plain_text, key, counter)
    end_time = time.time()
    print("\nEncrypting...")
    print("Encrypted hex:\t", bytes.hex(encrypted_text))
    print("Time to encrypt:\t", end_time - start_time)

    start_time = time.time()
    decrypted_text = counter_decrypt(bytes.hex(encrypted_text), key, counter)
    end_time = time.time()
    print("\nDecrypting...")
    print("Decrypted text:\t", decrypted_text)
    print("Time to decrypt:\t", end_time - start_time)

    print("\nResult:\t", plain_text == decrypted_text)
    print("===================================================")
