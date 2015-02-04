#!/usr/bin/python3
import os
import sys
import argparse
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

# File header
# MAGIC (str, 9 bytes)
# Key size (char, 1 byte)

IV_SIZE = 12
KEY_SIZE = 16
TAG_SIZE = 16
CHUNK_SIZE = 1024
MAGIC = 'bogocrypt'


def get_maxint(byte_size):
    if byte_size <= 0:
        return 0
    val = 0xff
    for i in range(1, byte_size):
        val = (val << 8) + 0xff
    return val


def get_keysize():
    while True:
        try:
            keysize = int(input("Keysize (bytes): "))
        except:
            pass
        else:
            if 0 < keysize <= 256:
                return keysize


def round_16(num):
    return ((num // 16) + 1) * 16


def encrypt(fn):
    keysize = get_keysize()
    rounded = round_16(keysize)
    key = (b'\x00' * (rounded - keysize)) + os.urandom(keysize)
    iv = int.from_bytes(os.urandom(IV_SIZE), 'little')
    max_iv = get_maxint(IV_SIZE)
    b = bytearray(bytes(MAGIC, 'utf-8') + (keysize - 1).to_bytes(1, 'little'))
    rsize = CHUNK_SIZE
    with open(fn, 'rb') as f:
        d = f.read(rsize)
        while len(d) != 0:
            tiv = iv.to_bytes(IV_SIZE, 'little')
            encryptor = Cipher(algorithms.AES(key),
                               modes.GCM(tiv),
                               backend=default_backend()
                               ).encryptor()
            encryptor.authenticate_additional_data(tiv)
            ciphertext = encryptor.update(d) + encryptor.finalize()

            b += bytearray(tiv)
            b += bytearray(ciphertext)
            b += bytearray(encryptor.tag)

            iv += 1
            if iv > max_iv:
                iv -= max_iv
            d = f.read(rsize)
    with open(fn, 'wb') as f:
        f.write(b)

def decrypt(fn):
    keysize = int.from_bytes(open(fn, 'rb').read(len(MAGIC) + 1)[-1:], 'little') + 1
    print("KEYSIZE: %s" % keysize)
    rounded = round_16(keysize)
    maxint = get_maxint(keysize)
    keyseed = int.from_bytes(os.urandom(keysize), 'little')
    i = 1
    t = datetime.now()
    while True:
        key = (b'\x00' * (rounded - keysize)) +
               keyseed.to_bytes(keysize, 'little')
        b = bytearray()
        rsize = IV_SIZE + TAG_SIZE + CHUNK_SIZE
        with open(fn, 'rb') as f:
            # Throw away non-relevant data
            f.read(len(MAGIC) + 1)
            d = f.read(rsize)
            try:
                while len(d) != 0:
                    iv = d[:IV_SIZE]
                    tag = d[-TAG_SIZE:]
                    d = d[IV_SIZE:-TAG_SIZE]
                    decryptor = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv, tag),
                        backend=default_backend()
                    ).decryptor()
                    decryptor.authenticate_additional_data(iv)
                    b += bytearray(decryptor.update(d) +
                                   decryptor.finalize())
                    d = f.read(rsize)

            except InvalidTag:
                i += 1
                keyseed += 1
                if keyseed > maxint:
                    keyseed = 0
                if i % 1000 == 0:
                    sys.stdout.write('.')
                    sys.stdout.flush()
                if i % 50000 == 0:
                    t2 = datetime.now()
                    rate = 50000 / (t2 - t).total_seconds()
                    remaining = seconds=(maxint - i) / rate
                    rhour = remaining / 3600.0
                    print(' - {0:0.2f}/s, {1:0.2f} hours'.format(rate, rhour))
                    t = t2
            else:
                print("Decrypted after %s tries" % i)
                break
    with open(fn, 'wb') as f:
        f.write(b)
        

def main():
    p = argparse.ArgumentParser(
        description='Encrypt or decrypt a file')
    p.add_argument('filename', metavar='filename')
    args = p.parse_args()
    fn = args.filename
    if not (os.path.exists(fn) and os.path.isfile(fn)):
        print("File does not exist or is non-encryptable")
        exit(1)
    try:
        f = open(fn, 'ab')
    except PermissionError:
        print("Can not write to chosen file - check permissions")
        exit(1)

    try:
        if str(open(fn, 'rb').read(len(MAGIC)), 'utf-8') != MAGIC:
            print("Magic string not found in file - encrypting")
            encrypt(fn)
        else:
            print("Magic string found - decrypting")
            decrypt(fn)
    # If the bytes are arbitrary and can not be decoded to the MAGIC
    except UnicodeDecodeError:
        print("Magic string not found in file - encrypting")
        encrypt(fn)


if __name__ == '__main__':
    main()
