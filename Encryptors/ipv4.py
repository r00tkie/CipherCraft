import sys
import argparse
sys.path.append('..')
from Encoder.LoaderStrings import ipv4_deobfuscation_code

def generate_ipv4(filtered_bytes):
    filtered_bytes += [0] * (4 - len(filtered_bytes))
    result = "{}.{}.{}.{}".format(*filtered_bytes)
    return result

def generate_ipv4_output(file_path, L):
    global ipv4_deobfuscation_code
    ipv4_list = []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4)
            if not chunk:
                break
            filtered_bytes = [b if b != 0 else 0 for b in chunk]  # Replace 0 with 0 in filtered_bytes
            ipv4_list.append(generate_ipv4(filtered_bytes))
    ipv4_code = ", ".join([f'"{ipv4}"' for ipv4 in ipv4_list])
    ipv4_deobfuscation_code = ipv4_deobfuscation_code.replace("// Replace this with the output of generate_ipv4_output function", ipv4_code)
    ipv4_deobfuscation_code = ipv4_deobfuscation_code.replace("#define NumberOfElements 115", f"#define NumberOfElements {len(ipv4_list)}")

    if L == 1:
        print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
        print(ipv4_deobfuscation_code)
    else:
        print(', '.join([f'"{ipv4}"' for ipv4 in ipv4_list]))
        print("NumberOfElements:", len(ipv4_list))

