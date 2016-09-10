#!/usr/bin/python3

#TODO: trademark research

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Hash import SHA256

passphrase = "mykey"

def crypt(plaintext, key):
    plaintext = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    print(ciphertext)
    print(tag)
    return ciphertext, nonce, tag

def decrypt(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data)


def genkey(passphrase):
    passphrase=passphrase.encode('utf-8')
    key = get_random_bytes(32) #TODO: store
    salt = get_random_bytes(32) #TODO: store
    salted_pass = passphrase + salt
   
    h = SHA256.new()
    h.update(salted_pass)
    intermed_key = h.digest()

    cipher = AES.new(key, AES.MODE_CBC)
    for i in range(1, 100000): #TODO: store?(authenticated?)
        intermed_key = cipher.encrypt(intermed_key)
    print(intermed_key)
    h.update(intermed_key)
    final_key = h.digest()
    print(final_key)


#crypt('asdf', key)
genkey(passphrase)
