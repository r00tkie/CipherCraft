import argparse
from Encryptors.mac import *
from Encryptors.aes import *
from Encryptors.uuid import *
from Encryptors.xor import *
from Encryptors.rc4 import *
from Encryptors.ipv6 import *
from Encryptors.ipv4 import * 
import sys

def main():
    parser = argparse.ArgumentParser(description="Encrypt and generate loader for various encryption types.")
    parser.add_argument("file_path", help="Path to the input payload file")
    parser.add_argument("encryption_type", choices=["mac", "aes", "uuid", "xor", "rc4", "ipv6", "ipv4"], help="Type of encryption")
    parser.add_argument("-L", "--loader", action="store_true", help="Generate loader code")

    args = parser.parse_args()

    try:
        with open(args.file_path, "rb") as file:
            content = file.read()
    except FileNotFoundError:
        print("Error: Input Payload File '{}' not found.".format(args.file_path))
        sys.exit(-1)

    if args.encryption_type == "mac":
        if args.loader:
            L = 1
            generate_mac_output(args.file_path, L)

        else:
            L = 0
            mac_list = generate_mac_output(args.file_path, L)

            if mac_list:
                print("\n\n###### GENERATED MAC LIST ######\n\n")

                for mac in mac_list:
                    print(f'        "{mac}",')
            else:
                print("Error: MAC addresses not generated.")

    elif args.encryption_type == "aes":
        KEY = urandom(16)
        ciphertext, key = AESencrypt(content, KEY)
        if args.loader:
            L = 1
            generate_aes_output(key, ciphertext, L)
        else:
            L = 0
            generate_aes_output(key, ciphertext, L)
 
    elif args.encryption_type == "rc4":
        KEY = hashlib.sha256(urandom(32)).digest()
        ciphertext, key = RC4encrypt(content, KEY)
        if args.loader:
            L = 1
            generate_rc4_output(key, ciphertext, L)
        else:
            L = 0
            generate_rc4_output(key, ciphertext, L)
    elif args.encryption_type == "uuid":
        if args.loader:
            L = 1
            generate_uuid_output(args.file_path, L)
        else:
            L = 0
            generate_uuid_output(args.file_path, L)

    elif args.encryption_type == "xor":
        KEY = urandom(16)
        ciphertext = xor(content, KEY)
        if args.loader:
            L = 1
            generate_xor_output(ciphertext, KEY, L)
        else:
            L = 0
            generate_xor_output(ciphertext, KEY, L)
    # elif args.encryption_type == "ipv6":
    #     if args.loader:
    #         L = 1
    #         generate_ipv6_output(args.file_path , L)
    #     else:
    #         L = 0
    #         generate_ipv6_output(args.file_path, L)
    elif args.encryption_type == "ipv4":
            if args.loader:
                L = 1
                generate_ipv4_output(args.file_path , L)
            else:
                L = 0
                generate_ipv4_output(args.file_path, L)

if __name__ == "__main__":
    main()
