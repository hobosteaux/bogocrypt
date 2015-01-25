#!/usr/bin/python3
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

IV_SIZE = 12
KEY_SIZE = 16
TAG_SIZE = 16
CHUNK_SIZE = 1024
MAGIC = 'bogocrypt'


def get_maxint(byte_size):
    if byte_size <= 0:
        return 0
    val = 0xf
    for i in range(1, byte_size):
        val = (val << 8) + 0xff
    return val


def encrypt(fn):
    key = os.urandom(KEY_SIZE)
    iv = int.from_bytes(os.urandom(IV_SIZE), 'little')
    max_iv = get_maxint(IV_SIZE)
    b = bytearray(bytes(MAGIC, 'utf-8'))
    rsize = CHUNK_SIZE
    with open(fn, 'rb') as f:
        d = f.read(rsize)
        while len(d) != 0:
            print(d, len(d))
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
    i = 1
    while True:
        key = os.urandom(KEY_SIZE)
        b = bytearray()
        rsize = IV_SIZE + TAG_SIZE + CHUNK_SIZE
        with open(fn, 'rb') as f:
            d = f.read(rsize)
            try:
                while len(d) != 0:
                    iv = d[:IV_SIZE]
                    tag = d[-TAG_SIZE:]
                    d = d[IV_SIZE:TAG_SIZE]
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
                if i % 1000 == 0:
                    sys.stdout.write('.')
                    sys.stdout.flush()
                if i % 50000 == 0:
                    print('')
            else:
                print("Decrypted after %s tries" % i)
                break
    with open(fn, 'wb') as f:
        f.write(b)
        

def main():
    # TODO: args / argparse
    fn = 'test'

    try:
        if str(open(fn, 'rb').read(len(MAGIC)), 'utf-8') != MAGIC:
            print("Magic string not found in file - encrypting")
            encrypt(fn)
        else:
            print("Magic string found - decrypting")
            decrypt(fn)
    except UnicodeDecodeError:
        print("Magic string not found in file - encrypting")
        encrypt(fn)


if __name__ == '__main__':
    main()
