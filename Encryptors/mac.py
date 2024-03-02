from macaddress import MAC
import sys
sys.path.append('..')
from Encoder.LoaderStrings import mac_deobfuscation_code



def generate_mac(a, b, c, d, e, f):
    return "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}".format(a, b, c, d, e, f)

def generate_mac_output(file_path,L):
    global mac_deobfuscation_code
    mac_list = []
    with open(file_path, "rb") as f:
        chunk = f.read(6)
        while chunk:
            if len(chunk) < 6:
                padding = 6 - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                mac_list.append(generate_mac(*chunk))
                break
            mac_list.append(generate_mac(*chunk))
            chunk = f.read(6)

    # Update mac_deobfuscation_code with the generated MAC addresse

    mac_array_str = ',\n'.join([f'"{mac}"' for mac in mac_list])
    mac_deobfuscation_code = mac_deobfuscation_code.replace('const char* MAC[] ={ };', f'const char* MAC[] ={{\n {mac_array_str}\n}};')

    if L==1:
       print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
       print(mac_deobfuscation_code)
    else:
       return mac_list




