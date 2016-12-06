import urllib
import sys
import os
import struct
from Crypto.Cipher import AES
import hashlib

def be32(s):
    return struct.unpack('>I', s)[0]
def be16(s):
    return struct.unpack('>H', s)[0]

def get_key(name):
    try:
        return open(os.environ['WIIU']+'/keys/'+name,'rb').read()
    except:
        print 'Key \'%s\' not found..' % name
        print 'You need to set WIIU environment variable.'
        sys.exit(1)

def aes_cbc_dec_file(inf, outf, key, iv, offset=0):
    in_file = open(inf, 'rb')
    out_file = open(outf, 'wb')

    in_file.seek(offset)

    while True:
        cipher = AES.new(key, AES.MODE_CBC, iv)

        enc = in_file.read(16)
        if len(enc) == 0:
            break
        if len(enc) < 16:
            break

        dec = cipher.decrypt(enc)
        out_file.write(dec)

        iv = enc

    in_file.close()
    out_file.close()

def aes_cbc_dec(inb, key, iv='\x00'*16):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(inb)

def aes_cbc_enc(inb, key, iv='\x00'*16):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(inb)

def sha1(buf):
    m = hashlib.sha1()
    m.update(buf)
    return m.digest()
