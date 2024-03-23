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
