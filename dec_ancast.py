#!/usr/bin/python2
# dec_ancast.py -- Decrypt Wii U ancast images
# plutoo, nwert

import sys
import struct
from common import *
import hashlib

def rsa_verify(sig, hdr, N):
    e = 0x10001
    sig = int(sig.encode("hex"), 16)
    p = "{0:X}".format(pow(sig, rsa_e, N))
    p = ("0" if len(p)%2 else "") + p
    p = p.decode("hex")
    return p[0xEB:] == hashlib.sha1(hdr).digest()

if len(sys.argv) != 2:
    print '%s file.img' % sys.argv[0]
    sys.exit(1)

in_file  = sys.argv[1]
out_file = in_file + '.bin'

header = open(in_file, 'rb').read(0x200)

magic = be32(header[0:4])
if magic != 0xEFA282D9:
    print 'Bad magic!'
    sys.exit(1)

sig_type = be32(header[0x20:0x24])

if sig_type == 1:
    offset = 0x100
elif sig_type == 2:
    offset = 0x200
else:
    print 'Unknown signature type %x..' % sig_type
    sys.exit(1)

types = {0x11: 'ppc_wiiu', 0x13: 'ppc_vwii', 0x21: 'arm'}
type_raw = be32(header[offset-0x5C:offset-0x58])

if type_raw not in types:
    print 'Unknown type %x..' % type
    sys.exit(1)

type = types[type_raw]
if type == 'arm':
    if be32(header[offset-0x54:offset-0x50]) in [0xE000, 0xC000]:
        type += '_boot1'
    else:
        type += '_iosu'

btypes = {1: 'debug', 2: 'retail'}
btype_raw = be32(header[offset-0x58:offset-0x54])
type += '_'+btypes[btype_raw]

print 'Type:', type

#print "Signature verified:", rsa_verify(header[0x24:0x124], header[0x1A0:0x200], Ns[btype])

key  = get_key('ancast_%s_key' % type)
iv   = get_key('ancast_%s_iv'  % type)

aes_cbc_dec_file(in_file, out_file, key, iv, offset)

out      = open(out_file, 'rb').read()
elf_pos  = out.find('\x7FELF')

if elf_pos != -1:
    elf_file = in_file + '.elf'
    elf      = open(elf_file, 'wb')
    elf.write(out[elf_pos:])
