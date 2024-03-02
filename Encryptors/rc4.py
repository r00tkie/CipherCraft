import sys
sys.path.append('..')
from Encoder.LoaderStrings import rc4_deobfuscation_code
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def RC4encrypt(plaintext, key):
    rc4 = ARC4.new(key)
    ciphertext = rc4.encrypt(pad(plaintext, ARC4.block_size))
    return ciphertext, key

def generate_rc4_output(key, ciphertext, L):
    global rc4_deobfuscation_code

    RC4key = 'unsigned char Rc4Key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in key) + ' };'
    RC4shellcode = 'unsigned char Rc4CipherText[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'

    rc4_deobfuscation_code = rc4_deobfuscation_code.replace("unsigned char Rc4Key[] =", RC4key)
    rc4_deobfuscation_code = rc4_deobfuscation_code.replace("unsigned char Rc4CipherText[] =", RC4shellcode)

   

    if L==1:
            print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
            print(rc4_deobfuscation_code)
    else:
            print(RC4key)
            print(RC4shellcode)