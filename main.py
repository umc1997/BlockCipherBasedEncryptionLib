from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import binascii, os, tkinter
from tkinter import filedialog

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
    for i in range(len(lastBlockReverse)):
        if lastBlockReverse[i] != 0:
            decryptedBytes = decryptedBytes[:(block_num - 1) * block_size + block_size - i - 1]
            break

    return decryptedBytes

def encryptFile(cipher, mode, key, iv, inputFileName, outputFileName, buffer_size = 64 * 1024):
    with open(inputFileName, 'rb') as infile:
        with open(outputFileName, 'wb') as outfile:

            while True:
                buffer = infile.read(buffer_size)
                if len(buffer) == 0:
                    break
                outfile.write(encryptBytes(cipher, mode, key, iv, buffer))
    print ("{} is encrypted.".format(inputFileName))

def decryptFile(cipher, mode, key, iv, inputFileName, outputFileName, buffer_size = 64 * 1024):
    with open(inputFileName, 'rb') as infile:
        fileSize = os.path.getsize(inputFileName)
        with open(outputFileName, 'wb') as outfile:
            while True:
                buffer = infile.read(buffer_size)
                if len(buffer) == 0:
                    break
                outfile.write(decryptBytes(cipher, mode, key, iv, buffer))
    print ("{} is decrypted.".format(inputFileName))

#Sample code: HexString Encryption
msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a \
                     ae2d8a571e03ac9c9eb76fac45af8e51 \
                     30c81c46a35ce411e5fbc1191a0a52ef \
                     f69f2445df4f9b17ad2b417be66c3710 \
                      ff")

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

cipher = "AES" # "DES3"

en1 = encryptBytes(cipher, "ECB", key, IV, msg)
de1 = decryptBytes(cipher, "ECB", key, IV, en1)
en2 = encryptBytes(cipher, "CBC", key, IV, msg)
de2 = decryptBytes(cipher, "CBC", key, IV, en2)
en3 = encryptBytes(cipher, "OFB", key, IV, msg)
de3 = decryptBytes(cipher, "OFB", key, IV, en3)
en4 = encryptBytes(cipher, "CFB", key, IV, msg)
de4 = decryptBytes(cipher, "CFB", key, IV, en4)
en5 = encryptBytes(cipher, "CTR", key, IV, msg)
de5 = decryptBytes(cipher, "CTR", key, IV, en5)

print("Message: ", binascii.hexlify(msg))
print("Encryption by AES.ECB mode : ", binascii.hexlify(en1))
if msg == de1:
    print("Encryption Success")
print("Encryption by AES.CBC mode : ", binascii.hexlify(en2))
if msg == de2:
    print("Encryption Success")
print("Encryption by AES.OFB mode : ", binascii.hexlify(en3))
if msg == de3:
    print("Encryption Success")
print("Encryption by AES.CFB mode : ", binascii.hexlify(en4))
if msg == de4:
    print("Encryption Success")
print("Encryption by AES.CTR mode : ", binascii.hexlify(en5))
if msg == de5:
    print("Encryption Success")

#Sample code: File Encryption
root = tkinter.Tk()
root.withdraw()

inputFileName = filedialog.askopenfilename()
encryptedFileName = inputFileName + ".enc"
decryptedFileName = encryptedFileName + ".dec"

encryptFile("AES", "CBC", key, IV, inputFileName, encryptedFileName)
decryptFile("AES", "CBC", key, IV, encryptedFileName, decryptedFileName)
