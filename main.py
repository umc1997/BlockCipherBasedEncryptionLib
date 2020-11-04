from Crypto.Cipher import AES
from PIL import Image
import binascii, os, random, struct
    
def convert2RGB(data):
    r,g,b = tuple(map(lambda d: [data[i] for i in range(0,len(data)) \
                                 if i % 3 == d], [0, 1, 2]))
    pixels = tuple(zip(r,g,b))
    return pixels

def encrypt_bmp_file(key, mode, in_filename, out_filename = None):

    im = Image.open(in_filename)
    data = im.convert("RGB").tobytes()
    original = len(data)

    pad_len = 16 - len(data) % 16
    pad = pad_len.to_bytes(1, byteorder='big', signed=False) * pad_len
    data += pad

    encryptor = AES.new(key, mode)
    encrypted = convert2RGB((encryptor.encrypt(data)[: original]))

    im2 = Image.new(im.mode, im.size)
    im2.putdata(encrypted)

    im2.save(out_filename)
    print("{} is encrypted".format(in_filename))


key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

mode = AES.MODE_ECB
str1 = "sample_07.bmp"
str2 = str1 + ".ecb.bmp"
str3 = str2 + ".bmp"
encrypt_bmp_file(key, mode, str1, str2)