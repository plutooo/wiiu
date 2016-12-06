#!/usr/bin/python2
# dld.py -- Download Wii U firmware from update servers.
# plutoo

import urllib
import urllib2
import sys
import os
import struct
import argparse
from Crypto.Cipher import AES

from common import *

NUS_SERVER='http://nus.cdn.c.shop.nintendowifi.net/ccs/download/%s/%s'
key = ''


def get_file(tid, remote, local):
    retries = 0
    wget = urllib.URLopener()

    while True:
        try:
            wget.retrieve(NUS_SERVER % (tid, remote), local)
            print '[!] Download done.'
            return

        except IOError, e:
            if e[0] == 'http error' and e[1] in [404, 401]:
                print '[!] Download failed..'
                raise Exception('Download failed.')

            print 'Got error: %s, retrying..' % repr(e)

def remove_sig(buf):
    sig_type = be32(buf[0:4])
    buf_off = 0
    
    if sig_type == 0x10000 or sig_type == 0x10003:
        buf_off = 0x240
    elif sig_type == 0x10001 or sig_type == 0x10004:
        buf_off = 0x140
    elif sig_type == 0x10002 or sig_type == 0x10005:
        buf_off = 0x80
    else:
        raise Exception('Unknown signature size.')

    return buf[buf_off:]

def decrypt_title_key(tik):
    key = tik[0x7f:0x8f]
    iv = tik[0x9c:0xa4] + ('\x00'*8)
    return aes_cbc_dec(key, get_key('common_key'), iv)

def mkdir(d):
    try:
        os.makedirs(d)
    except Exception, e:
        if '[Errno 17]' not in str(e):
            raise

def parse_fst_entry(buf):
    return {'type': buf[0],
        'str_off': be32(buf[0:4]) & 0xffffff,
        'prev_dir': be32(buf[4:8]),   # for dir only
        'next_dir': be32(buf[8:0xc]), # for dir only
        'offset': be32(buf[4:8]), # for files only
        'size': be32(buf[8:0xc]), # for files only
        'flags': be16(buf[0xc:0xe]),
        'index': be16(buf[0xe:0x10])}

def walk_fst_tree(dstdir, nodes, pos, path):
    node = nodes[pos]

    if node['type'] == '\x01': # dir
        if path == '':
            node['path'] = '.'
        else:
            node['path'] = path+'/'+node['name']
            mkdir('%s/%s' % (dstdir, node['path']))
        
        new_pos = pos + 1
        while new_pos < node['next_dir']:
            new_pos = walk_fst_tree(dstdir, nodes, new_pos, node['path'])

        return node['next_dir']

    else: # file
        node['path'] = path+'/'+node['name']
        return pos + 1

def parse_fst(dstdir, fst):
    print '[!] Parsing FST file..'
    fst = open(fst, 'rb').read()
    magic, offset_align, num_contents = struct.unpack('>LLL', fst[0:0xc])

    if magic != 0x46535400:
        print '[!] Wrong magic FST.. skipping.'
        return

    entries_off = 0x20 + 0x20 * num_contents

    root = parse_fst_entry(fst[entries_off:entries_off+0x10])
    root['name'] = '.'

    entries_off += 0x10
    strtbl_off = 0x20 + 0x20 * num_contents + 0x10 * root['size']

    nodes = []
    nodes.append(root)

    for i in range(0, root['size']-1):
        node = parse_fst_entry(fst[entries_off:entries_off+0x10])

        name = fst[strtbl_off + node['str_off']:]
        name = name[:name.find('\x00')]

        node['name'] = name

        nodes.append(node)
        entries_off += 0x10

    walk_fst_tree(dstdir, nodes, 0, '')

    for node in nodes:
        if node['type'] == '\x00': # files
            print '[!] File %s.' % node['path']

            off = node['offset'] * offset_align
            sz  = node['size']

            #print '  off:', off, 'sz:', sz, 'id:', node['index'], 'flags', hex(node['flags'])

            f   = open('%s/%08x' % (dstdir, node['index']), 'rb')
            out = open('%s/%s'   % (dstdir, node['path']), 'wb')

            if node['flags'] & 0x440:
                f.seek((off/0xFC00) * 0x10000)
                chunk_off = off - ((off / 0xFC00) * 0xFC00)

                block = (off / 0xFC00) % 16
                left = sz

                def sxor(s1,s2):
                    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

                while left > 0:
                    buf = f.read(0x10000)

                    iv = ('%04x' % node['index']).decode('hex') + ('\x00'*14)
                    hashes = aes_cbc_dec(buf[:0x400], key, iv)

                    iv = hashes[20*block : 20*block+16]
                    if block == 0:
                        content_id = ('%04x' % node['index']).decode('hex') + ('\x00'*14)
                        iv = sxor(iv, content_id)

                    dec = aes_cbc_dec(buf[0x400:], key, iv)

                    h = sha1(dec)
                    if block == 0:
                        content_id = ('%04x' % node['index']).decode('hex') + ('\x00'*18)
                        h = sxor(h, content_id)

                    if h != hashes[block*20 : block*20+20]:
                        print '[!] Hash mismatch detected!'
                    
                    rd = 0xFC00 - chunk_off
                    wr = left if left < rd else rd
                    out.write(dec[chunk_off : chunk_off+wr])

                    chunk_off = 0
                    block = (block + 1) % 16
                    left -= wr
            else:
                iv = ('%04x' % node['index']).decode('hex') + ('\x00'*14)

                left = sz
                while left > 0:
                    rd = left if left < 0x8000 else 0x8000
                    rd_aligned = ((rd + 15)/16 * 16)
                    b = f.read(rd_aligned)
                    dec = aes_cbc_dec(b, key, iv)

                    out.write(dec[:rd])
                    iv = b[-0x10:]
                    left -= rd

def parse_tmd(tid, dstdir):
    print '[!] Parsing tmd and tik..'

    tmd = remove_sig(open('%s/tmd' % dstdir, 'rb').read())
    num_contents = be16(tmd[0x9e:0xa0])
    off = 0x9c4

    tik = remove_sig(open('%s/cetk' % dstdir, 'rb').read())
    global key
    key = decrypt_title_key(tik)

    print '[!] Decrypted title key: ' + key.encode('hex')

    for i in range(0, num_contents):
        print '[!] Downloading content %08x..' % i
        info = tmd[off:off+0x30]
        sha1 = info[0x10:0x24]
        cid  = be32(info[0:4])
        idx  = be16(info[4:6])

        dst_file = '%s/%08x' % (dstdir, i)
        get_file(tid, '%08x' % cid, dst_file)

        iv = info[4:6] + ('\x00'*14)

        if i == 0:
            print '[!] Found FST-file, decrypting directly..'
            aes_cbc_dec_file(dst_file, '%s/fst.bin' % dstdir, key, iv)

        off += 0x30

    parse_fst(dstdir, '%s/fst.bin' % dstdir)

def get_title(tidver, dstdir=None):
    if dstdir == None:
        dstdir = tidver

    tidver = tidver.split('.')
    tid = tidver[0]
    ver = tidver[1] if len(tidver)==2 else None

    print '[!] Getting title %s, version: %s.' % (tid, ver if ver else 'latest')

    mkdir(dstdir)

    try:
        print '[!] Downloading tmd and tik..'

        if ver:
            get_file(tid, 'tmd.%s' % ver, '%s/tmd' % dstdir)
        else:
            get_file(tid, 'tmd', '%s/tmd' % dstdir)

        get_file(tid, 'cetk', '%s/cetk' % dstdir)
        parse_tmd(tid, dstdir)

    except Exception, e:
        #os.rmdir(dstdir) # XXX: ?
        raise

def get_csv(url, dstdir, y8, onlylatest):
    csv = urllib2.urlopen(url).read()
    csv = csv.splitlines()[1:]

    titles = {}

    def add_to_dl_queue(tid, ver, region):
        tv = (tid, ver)

        if tv not in titles:
            titles[tv] = [region]
        else:
            titles[tv].append(region)

    for line in csv:
        if line.strip() == '':
            continue

        line = line.split(',')
        tid    = line[0]
        region = line[1]
        vers   = line[2].split(' ')

        # Only download last version.
        if onlylatest:
            add_to_dl_queue(tid, vers[-1], region)
        else:
            # Download all versions.
            for ver in vers:
                add_to_dl_queue(tid, ver, region)

    for tv in titles:
        tid = tv[0]
        ver = tv[1]

        tidver = '%s.%s' % (tid, ver[1:])

        # If multiple regions has this title+version, only download it once.
        if len(titles[tv]) > 1:
            tdir = '%s/%s/%s' % (dstdir, tid, ver)
            get_title(tidver, tdir)
        else:
            region = titles[tv][0]
            if y8:
                tdir = '%s/%s/%s/%s' % (dstdir, tid, region, ver)
            else:
                tdir = '%s/%s/%s/%s' % (dstdir, region, tid, ver)

            get_title(tidver, tdir)

def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--dl', help='Download title, format: title_id[.version].')
    parser.add_argument('--dlcsv', help='Download titles based on csv-file from url.')
    parser.add_argument('--dir', help='Output directory.')
    parser.add_argument('--y8', action='store_true', help='Compatibility with ctr-titletool.')
    parser.add_argument('--onlylatest', action='store_true', help='If many versions, pick last one.')

    args = parser.parse_args()

    if args.dl and args.dlcsv:
        print 'You can either download a title id or an csv. Not both!'
        return 1

    elif args.dl:
        if args.dir:
            get_title(args.dl, args.dir)
        else:
            get_title(args.dl)

    elif args.dlcsv:
        if not args.dir:
            print 'You must supply --dir for --dlcsv!'
            return 1

        get_csv(args.dlcsv, args.dir, args.y8, args.onlylatest)

    else:
        parser.print_help()

    return 0

sys.exit(main(sys.argv))
