# Import fungsi enkripsi dan dekripsi dari cipher
from backend.cipher import encrypt, decrypt

# Fungsi untuk enkripsi pesan menggunakan mode OFB 8 bit
def ofb_encrypt(plaintext, key, iv):
    ciphertext = b''
    # Menginisialisasi IV untuk blok pertama
    previous_iv = iv
    # Iterasi melalui setiap byte dalam plaintext
    for byte in plaintext:
        # Enkripsi IV untuk digunakan sebagai keystream
        keystream = encrypt(previous_iv, key)
        # XOR byte plaintext dengan byte keystream untuk mendapatkan byte ciphertext
        ciphertext_byte = byte ^ keystream[0]
        # Tambahkan byte ciphertext ke ciphertext
        ciphertext += bytes([ciphertext_byte])
        # Perbarui IV dengan keystream yang baru saja dihasilkan
        previous_iv = previous_iv[1:] + bytes([keystream[0]])
    return ciphertext

# Fungsi untuk dekripsi pesan menggunakan mode OFB 8 bit
def ofb_decrypt(ciphertext, key, iv):
    return ofb_encrypt(ciphertext, key, iv)
