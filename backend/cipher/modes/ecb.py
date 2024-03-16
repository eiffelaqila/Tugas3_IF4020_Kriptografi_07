# Import fungsi enkripsi dan dekripsi dari cipher
from cipher import encrypt, decrypt

# Fungsi untuk enkripsi menggunakan mode ECB
def ecb_encrypt_block(plaintext_block, key):
    # Enkripsi blok pesan menggunakan kunci
    ciphertext_block = encrypt(plaintext_block, key)
    return ciphertext_block

# Fungsi untuk dekripsi menggunakan mode ECB
def ecb_decrypt_block(ciphertext_block, key):
    # Dekripsi blok pesan menggunakan kunci
    plaintext_block = decrypt(ciphertext_block, key)
    return plaintext_block

# Fungsi untuk enkripsi pesan menggunakan mode ECB
def ecb_encrypt(plaintext, key):
    ciphertext = b''
    # Membagi pesan menjadi blok-blok 128 bit
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i+16]
        # Enkripsi setiap blok pesan dan tambahkan ke ciphertext
        ciphertext_block = ecb_encrypt_block(plaintext_block, key)
        ciphertext += ciphertext_block
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode ECB
def ecb_decrypt(ciphertext, key):
    plaintext = b''
    # Membagi ciphertext menjadi blok-blok 128 bit
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i+16]
        # Dekripsi setiap blok ciphertext dan tambahkan ke plaintext
        plaintext_block = ecb_decrypt_block(ciphertext_block, key)
        plaintext += plaintext_block
    return plaintext
