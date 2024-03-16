# Import fungsi enkripsi dan dekripsi dari cipher
from cipher import encrypt, decrypt

# Fungsi untuk enkripsi pesan menggunakan mode CFB 8 bit
def cfb_encrypt(plaintext, key, iv):
    ciphertext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_ciphertext_block = iv
    # Iterasi melalui setiap byte dalam plaintext
    for byte in plaintext:
        # Enkripsi blok sebelumnya untuk digunakan sebagai IV
        encrypted_iv = encrypt(previous_ciphertext_block, key)
        # XOR byte plaintext dengan byte hasil enkripsi IV untuk mendapatkan byte ciphertext
        ciphertext_byte = byte ^ encrypted_iv[0]
        # Tambahkan byte ciphertext ke ciphertext
        ciphertext += bytes([ciphertext_byte])
        # Perbarui blok sebelumnya dengan byte ciphertext yang baru saja dihasilkan
        previous_ciphertext_block = previous_ciphertext_block[1:] + bytes([ciphertext_byte])
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode CFB 8 bit
def cfb_decrypt(ciphertext, key, iv):
    plaintext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_ciphertext_block = iv
    # Iterasi melalui setiap byte dalam ciphertext
    for byte in ciphertext:
        # Enkripsi blok sebelumnya untuk digunakan sebagai IV
        encrypted_iv = encrypt(previous_ciphertext_block, key)
        # XOR byte ciphertext dengan byte hasil enkripsi IV untuk mendapatkan byte plaintext
        plaintext_byte = byte ^ encrypted_iv[0]
        # Tambahkan byte plaintext ke plaintext
        plaintext += bytes([plaintext_byte])
        # Perbarui blok sebelumnya dengan byte ciphertext yang baru saja dihasilkan
        previous_ciphertext_block = previous_ciphertext_block[1:] + bytes([byte])
    return plaintext
