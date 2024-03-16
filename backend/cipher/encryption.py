# Fungsi sederhana untuk enkripsi (misalnya, XOR dengan kunci)
def encrypt(plaintext, key):
    ciphertext = bytes([b ^ key for b in plaintext])
    return ciphertext
