# xor.py
import sys
sys.path.append('..')
from Encoder.LoaderStrings import xor_deobfuscation_code

def xor(plaintext, key):
    key_bytes = key if isinstance(key, bytes) else key.encode('utf-8')
    key_len = len(key_bytes)
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        current_byte = plaintext[i] if isinstance(plaintext[i], int) else ord(plaintext[i])
        current_key = key_bytes[i % key_len]
        ciphertext.append(current_byte ^ current_key)

    return bytes(ciphertext)

def generate_xor_output(key, ciphertext, L):
    global xor_deobfuscation_code
    xorKey = 'char XORkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in key) + ' };'
    xorShellcode = 'unsigned char XORshellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'
    
    xor_deobfuscation_code = xor_deobfuscation_code.replace("char XORkey[] =", xorKey)
    xor_deobfuscation_code = xor_deobfuscation_code.replace("unsigned char XORshellcode[] =", xorShellcode)

    if L == 1:
        print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
        print(xor_deobfuscation_code)
    else:
        print(xorKey)
        print(xorShellcode)
