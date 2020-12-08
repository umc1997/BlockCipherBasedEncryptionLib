from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import binascii

block_size = 16

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encryptBlock(cipher, key, block):
    if cipher == "AES":
        encryptor = AES.new(key, AES.MODE_ECB)
    elif cipher == "DES3":
        encryptor = DES3.new(key, DES3.MODE_ECB)
    return encryptor.encrypt(block)

def decryptBlock(cipher, key, block):
    if cipher == "AES":
        decryptor = AES.new(key, AES.MODE_ECB)
    elif cipher == "DES3":
        decryptor = DES3.new(key, DES3.MODE_ECB)
    return decryptor.decrypt(block)

def encryptBytes(cipher, mode, key, iv, bytes):
    # encoding (One-Zero padding)
    padLen = (block_size - len(bytes) % block_size)
    pad = bytes.fromhex("10")
    pad += (bytes.fromhex("00") * (padLen - 1))
    bytes += pad

    # encipher
    encryptedBytes = bytearray(b'')
    block_num = len(bytes) // block_size

    for i in range(0, block_num):
        currentBlock = bytes[i * block_size: (i + 1) * block_size]
        if mode == "ECB":
            encryptedBytes += encryptBlock(cipher, key, currentBlock)
        elif mode == "CBC":
            nextiv = encryptBlock(cipher, key, xor(currentBlock,iv))
            encryptedBytes += nextiv
            iv = nextiv
        elif mode == "OFB":
            nextiv = encryptBlock(cipher, key, iv)
            encryptedBytes += xor(currentBlock, nextiv)
            iv = nextiv
        elif mode == "CFB":
            nextiv = xor(encryptBlock(cipher, key, iv), currentBlock)
            encryptedBytes += nextiv
            iv = nextiv
        elif mode == "CTR":
            encryptedBytes += xor(encryptBlock(cipher, key, iv), currentBlock)
            iv = xor(iv, (1).to_bytes(block_size, byteorder="big", signed=True))

    return encryptedBytes

def decryptBytes(cipher, mode, key, iv, bytes):
    # decipher
    decryptedBytes = bytearray(b'')
    block_num = len(bytes) // block_size

    for i in range(0, block_num):
        currentBlock = bytes[i * block_size : (i + 1) * block_size]
        if mode == "ECB":
            decryptedBytes += decryptBlock(cipher, key, currentBlock)
        elif mode == "CBC":
            decryptedBytes += xor(decryptBlock(cipher, key, currentBlock), iv)
            iv = currentBlock
        elif mode == "OFB":
            nextiv = encryptBlock(cipher, key, iv)
            decryptedBytes += xor(currentBlock, nextiv)
            iv = nextiv
        elif mode == "CFB":
            nextiv = xor(encryptBlock(cipher, key, iv), currentBlock)
            decryptedBytes += nextiv
            iv = currentBlock
        elif mode == "CTR":
            decryptedBytes += xor(encryptBlock(cipher, key, iv), currentBlock)
            iv = xor(iv, (1).to_bytes(block_size, byteorder="big", signed=True))
    # decoding
    lastBlock = decryptedBytes[(block_num - 1) * block_size:]
    lastBlockReverse = lastBlock[::-1]
    for i in lastBlockReverse:
        if i != 0:
            decryptedBytes = decryptedBytes[:(block_num - 1) * block_size + block_size - i]
            break

    return decryptedBytes

msg = bytes.fromhex(" 6bc1bee22e409f96e93d7e117393172a  \
                     ae2d8a571e03ac9c9eb76fac45af8e51   \
                     30c81c46a35ce411e5fbc1191a0a52ef   \
                     f69f2445df4f9b17ad2b417be66c3710")


cipher = "AES"
#cipher = "DES3"

mode1 = "ECB"
mode2 = "CBC"
mode3 = "OFB"
mode4 = "CFB"
mode5 = "CTR"
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
en1 = encryptBytes(cipher, mode1, key, IV, msg)
de1 = decryptBytes(cipher, mode1, key, IV, en1)
en2 = encryptBytes(cipher, mode2, key, IV, msg)
de2 = decryptBytes(cipher, mode2, key, IV, en2)
en3 = encryptBytes(cipher, mode3, key, IV, msg)
de3 = decryptBytes(cipher, mode3, key, IV, en3)
en4 = encryptBytes(cipher, mode4, key, IV, msg)
de4 = decryptBytes(cipher, mode4, key, IV, en4)
en5 = encryptBytes(cipher, mode5, key, IV, msg)
de5 = decryptBytes(cipher, mode5, key, IV, en5)
print(binascii.hexlify(msg))
print(binascii.hexlify(en1))
print(binascii.hexlify(de1))
print(binascii.hexlify(en2))
print(binascii.hexlify(de2))
print(binascii.hexlify(en3))
print(binascii.hexlify(de3))
print(binascii.hexlify(en4))
print(binascii.hexlify(de4))
print(binascii.hexlify(en5))
print(binascii.hexlify(de5))