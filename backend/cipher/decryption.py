# Fungsi sederhana untuk dekripsi (sama dengan enkripsi karena ini contoh sederhana)
def decrypt(ciphertext, key):
    plaintext = bytes([b ^ key for b in ciphertext])
    return plaintext