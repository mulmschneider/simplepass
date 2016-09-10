#!/usr/bin/python3

#from Crypto.Hash import SHA256
#from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

key = get_random_bytes(16)
data = "This is a test".encode('utf-8')
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce
print(ciphertext)
print(tag)

cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)

#file_out = open("encrypted.bin", "wb")
#[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]


#hash = SHA256.new()
#hash.update('message'.encode())
#digest = hash.digest()
#print(digest)
#
#
## https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes might be simpler
#obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#message = "The answer is no"
#ciphertext = obj.encrypt(message)
#obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#plaintext = obj2.decrypt(ciphertext)
#print(ciphertext)
#print(plaintext)
#print(message)
