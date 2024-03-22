# CONSTANTS
IP = [
    57,  49,  41,  33,  25, 17, 9,  1,  59,  51,  43,  35,  27, 19, 11, 3,
    61,  53,  45,  37,  29, 21, 13, 5,  63,  55,  47,  39,  31, 23, 15, 7,
    56,  48,  40,  32,  24, 16, 8,  0,  58,  50,  42,  34,  26, 18, 10, 2,
    60,  52,  44,  36,  28, 20, 12, 4,  62,  54,  46,  38,  30, 22, 14, 6,
    121, 113, 105, 97,  89, 81, 73, 65, 123, 115, 107, 99,  91, 83, 75, 67,
    125, 117, 109, 101, 93, 85, 77, 69, 127, 119, 111, 103, 95, 87, 79, 71,
    120, 112, 104, 96,  88, 80, 72, 64, 122, 114, 106, 98,  90, 82, 74, 66,
    124, 116, 108, 100, 92, 84, 76, 68, 126, 118, 110, 102, 94, 86, 78, 70,
]

INVERSE_IP = [
    39,  7,  47,  15, 55,  23, 63,  31, 38,  6,  46,  14, 54,  22, 62,  30,
    37,  5,  45,  13, 53,  21, 61,  29, 36,  4,  44,  12, 52,  20, 60,  28,
    35,  3,  43,  11, 51,  19, 59,  27, 34,  2,  42,  10, 50,  18, 58,  26,
    33,  1,  41,  9,  49,  17, 57,  25, 32,  0,  40,  8,  48,  16, 56,  24,
    103, 71, 111, 79, 119, 87, 127, 95, 102, 70, 110, 78, 118, 86, 126, 94,
    101, 69, 109, 77, 117, 85, 125, 93, 100, 68, 108, 76, 116, 84, 124, 92,
    99,  67, 107, 75, 115, 83, 123, 91, 98,  66, 106, 74, 114, 82, 122, 90,
    97,  65, 105, 73, 113, 81, 121, 89, 96,  64, 104, 72, 112, 80, 120, 88
]

S_BOXES = [
    [6,  11, 10, 15, 9,  0,  13, 12, 4,  5,  7,  2,  1,  3,  8,  14],
    [10, 12, 2,  5,  15, 13, 3,  7,  9,  11, 0,  6,  4,  8,  1,  14],
    [14, 4,  0,  13, 5,  2,  8,  6,  15, 9,  7,  1,  10, 12, 3,  11],
    [14, 6,  8,  0,  15, 11, 5,  3,  1,  10, 7,  12, 4,  2,  13,  9],
    [8,  14, 10, 5,  13, 9,  0,  3,  15, 1,  6,  12, 2,  7,  4,  11],
    [13, 11, 0,  6,  14, 2,  3,  8,  12, 5,  15, 10, 4,  1,  9,   7],
    [3,  8,  10, 12, 0,  1,  13, 7,  4,  6,  2,  14, 11, 15, 5,   9],
    [0,  13, 4,  8,  3,  7,  6,  14, 11, 2,  10, 5,  9,  1,  12, 15],
    [6,  0,  5,  3,  2,  15, 14, 4,  11, 8,  13, 7,  9,  1,  10, 12],
    [4,  13, 12, 10, 5,  1,  3,  9,  15, 14, 8,  6,  0,  7,  2,  11],
    [1,  12, 8,  2,  6,  7,  14, 10, 5,  4,  9,  0,  13, 15, 11,  3],
    [6,  11, 13, 15, 2,  5,  12, 3,  7,  14, 10, 9,  0,  4,  8,   1],
    [0,  4,  2,  12, 6,  1,  14, 7,  13, 3,  5,  11, 10, 9,  15,  8],
    [8,  15, 11, 7,  14, 10, 0,  1,  3,  13, 12, 6,  9,  2,  4,   5],
    [5,  7,  14, 1,  13, 0,  3,  2,  9,  10, 6,  11, 15, 12, 8,   4],
    [13, 2,  0,  5,  3,  12, 1,  4,  11, 15, 14, 7,  6,  9,  10,  8],
]

def bytes_to_bitarray(bytes):
    bitarray = []
    for byte in bytes:
        bitarray += [int(i,2) for i in bin(byte).replace('0b', '').rjust(8, '0')]
    
    return bitarray

def bitarray_to_bytes(bitarray):
    res = []
    for i in range(len(bitarray)//8):
        res.append(int(''.join(map(str, bitarray[i*8:(i+1)*8])), 2))
    return bytes(res)

# TODO: Dummy key generator
def key_generator(key):
    key_bits = bytes_to_bitarray(key)
    
    key1 = key_bits[:64]
    key2 = key_bits[64:128]
    
    return [key1, key2, key1, key2, key1, key2, key1, key2, key1, key2, key1, key2, key1, key2, key1, key2]

def encrypt(plain_bytes: bytes, key: any) -> bytes:
    # Konversi plain_bytes (16 bytes) menjadi array of bit (128 bit)
    plain_bits = bytes_to_bitarray(plain_bytes)
    
    internal_keys = key_generator(key)
    
    initial_permutation = [plain_bits[IP[i]] for i in range(128)]
    iteration_result = iteration_encrypt(initial_permutation, internal_keys)
    inverse_permutation = [iteration_result[INVERSE_IP[i]] for i in range(128)]

    return bitarray_to_bytes(inverse_permutation)

def decrypt(cipher_bytes: bytes, key) -> bytes:
    # Konversi cipher_bytes (16 bytes) menjadi array of bit (128 bit)
    cipher_bits = bytes_to_bitarray(cipher_bytes)
    
    internal_keys = key_generator(key)
    
    initial_permutation = [cipher_bits[IP[i]] for i in range(128)]
    iteration_result = iteration_decrypt(initial_permutation, internal_keys)
    inverse_permutation = [iteration_result[INVERSE_IP[i]] for i in range(128)]

    return bitarray_to_bytes(inverse_permutation)

def iteration_encrypt(plain_bitarray: list[int], internal_keys: list[list[int]]) -> bytes:
    L = plain_bitarray[:64]
    R = plain_bitarray[64:128]

    for i in range(16):
        f_result = f(L, internal_keys[i])
        temp = L[:]
        L = [R[j] ^ f_result[j] for j in range(64)]
        R = temp[:]

    return R + L

def iteration_decrypt(cipher_bitarray: list[int], internal_keys: list[list[int]]) -> bytes:
    L = cipher_bitarray[:64]
    R = cipher_bitarray[64:128]

    for i in range(15, -1, -1):
        f_result = f(L, internal_keys[i])
        temp = L[:]
        L = [R[j] ^ f_result[j] for j in range(64)]
        R = temp[:]
    
    return R + L

def f(subbitarray: list[int], internal_key: list[int]) -> list[int]:
    # subbitarray 64-bit
    # internal_key 64-bit
    r_ramadhan = [subbitarray[i] ^ bytes_to_bitarray(b'RAMADHAN')[i] ^ internal_key[i] for i in range(64)] 
    s_boxes = []

    # divide into 16 boxes (4-bit per box) for substitution
    for i in range(16):
        four_bits = r_ramadhan[i*4 : (i+1)*4]
        # substitute the four_bits with element in S_BOXES
        elem_on_sbox = S_BOXES[i][int(''.join(map(str, four_bits)), 2)]
        s_boxes.append([int(i,2) for i in bin(elem_on_sbox).replace('0b', '').rjust(4, '0')])

    # join into s_boxes into 4 elements (16-bit)
    # [s_boxes[0],s_boxes[4],s_boxes[8],s_boxes[12]], ...
    four_by_four_matrices = [[], [], [], []]
    for i in range(16):
        four_by_four_matrices[i % 4].append(s_boxes[i])

    # AES shift rows for every four_by_four_matrices
    # for each matrices of 16-bit (4x4)
    shifted_matrices = []
    for i in range(4):
        matrix = [four_by_four_matrices[j:j+4] for j in range(0, 16, 4)]
        # move element to last column by 1
        matrix[1] = matrix[1][1:] + matrix[1][:1]
        # move element to last column by 2
        matrix[2] = matrix[2][2:] + matrix[2][:2]
        
        matrix[3] = matrix[3][3:] + matrix[3][:3]
        # flatten matrix, put into shifted_matrices
        shifted_matrices.append([elmt for row in matrix for elmt in row])

    # return flatten shifted_matrices
    return [elem for sublist in shifted_matrices for subsublist in sublist for subsubsublist in subsublist for elem in subsubsublist]


# Test
import os
import time

if __name__ == '__main__':
    plain_text = os.urandom(16)
    plain_bytes = bytes(plain_text)
    
    keys = os.urandom(16)
    keys_bytes = bytes(keys)

    start_time = time.time()
    print("PLAIN BYTES:", plain_bytes)
    encrypted_bytes = encrypt(plain_bytes, keys_bytes)
    print("ENCRYPTED BYTES:", encrypted_bytes)
    decrypted_bytes = decrypt(encrypted_bytes, keys_bytes)
    print("DECRYPTED BYTES:", decrypted_bytes)

    end_time = time.time()
    print("VALID:", plain_bytes == decrypted_bytes)
    print("TIME TAKEN:", end_time - start_time)