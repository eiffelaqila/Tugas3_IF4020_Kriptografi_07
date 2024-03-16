# Import fungsi enkripsi dan dekripsi dari cipher
from backend.cipher import encrypt, decrypt

# Fungsi untuk enkripsi satu blok pesan menggunakan mode CBC
def cbc_encrypt_block(plaintext_block, key, iv):
    # XOR blok pesan dengan IV (Initialization Vector)
    plaintext_block_xor_iv = bytes([p ^ i for p, i in zip(plaintext_block, iv)])
    # Enkripsi hasil XOR dengan kunci
    ciphertext_block = encrypt(plaintext_block_xor_iv, key)
    return ciphertext_block

# Fungsi untuk dekripsi satu blok pesan menggunakan mode CBC
def cbc_decrypt_block(ciphertext_block, key, iv):
    # Dekripsi blok ciphertext menggunakan kunci
    decrypted_block = decrypt(ciphertext_block, key)
    # XOR hasil dekripsi dengan IV (Initialization Vector)
    plaintext_block = bytes([d ^ i for d, i in zip(decrypted_block, iv)])
    return plaintext_block

# Fungsi untuk enkripsi pesan menggunakan mode CBC
def cbc_encrypt(plaintext, key, iv):
    ciphertext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_cipher_block = iv
    # Membagi pesan menjadi blok-blok 128 bit
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i+16]
        # Enkripsi setiap blok pesan dan tambahkan ke ciphertext
        ciphertext_block = cbc_encrypt_block(plaintext_block, key, previous_cipher_block)
        ciphertext += ciphertext_block
        # Update IV untuk blok berikutnya
        previous_cipher_block = ciphertext_block
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode CBC
def cbc_decrypt(ciphertext, key, iv):
    plaintext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_cipher_block = iv
    # Membagi ciphertext menjadi blok-blok 128 bit
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i+16]
        # Dekripsi setiap blok ciphertext dan tambahkan ke plaintext
        plaintext_block = cbc_decrypt_block(ciphertext_block, key, previous_cipher_block)
        plaintext += plaintext_block
        # Update IV untuk blok berikutnya
        previous_cipher_block = ciphertext_block
    return plaintext
