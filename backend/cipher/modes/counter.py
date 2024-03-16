# Import fungsi enkripsi dari cipher
from backend.cipher import encrypt, decrypt

# Fungsi untuk menghasilkan nilai counter berikutnya
def generate_next_counter(counter):
    # Konversi nilai counter menjadi bytes
    counter_bytes = counter.to_bytes(16, byteorder='big')
    # Tambahkan 1 ke nilai counter
    next_counter = counter + 1
    return next_counter, counter_bytes

# Fungsi untuk enkripsi satu blok pesan menggunakan mode Counter
def counter_encrypt_block(plaintext_block, key, counter):
    # Dapatkan nilai counter berikutnya dan konversi ke bytes
    counter, counter_bytes = generate_next_counter(counter)
    # Enkripsi nilai counter menggunakan kunci
    encrypted_counter = encrypt(counter_bytes, key)
    # XOR hasil enkripsi counter dengan plaintext blok untuk mendapatkan ciphertext blok
    ciphertext_block = bytes([p ^ e for p, e in zip(plaintext_block, encrypted_counter)])
    return ciphertext_block, counter

# Fungsi untuk enkripsi pesan menggunakan mode Counter
def counter_encrypt(plaintext, key, counter):
    ciphertext = b''
    # Iterasi melalui setiap blok dalam plaintext
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i+16]
        # Enkripsi blok pesan menggunakan mode Counter
        ciphertext_block, counter = counter_encrypt_block(plaintext_block, key, counter)
        # Tambahkan blok ciphertext ke ciphertext
        ciphertext += ciphertext_block
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode Counter (sama dengan enkripsi dalam Counter)
def counter_decrypt(ciphertext, key, counter):
    return counter_encrypt_message(ciphertext, key, counter)
