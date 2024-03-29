###

[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/r00tkie?style=social)](https://twitter.com/r00tkie)

# Encoder

## Overview

This tool lets you obfuscate your payload and generate a loader for multiple encryption types. 
It can process raw shellcode as input and provides a range of encoding/encryption options, including IPv4 and IPv6 addresses, XOR, AES, RC4, MAC addresses, and UUID addresses.

## Features

Algorithm Choices: Choose from various encoding algorithms to customize the obfuscation process.
Cipher Generation: Obtain the encoded shellcode as a cipher for further use or analysis.
Loader Code Generation: Utilize the `-L` option to generate a ready-to-compile loader.

### Usage
```bash
 python3 Encrypt.py [shellcode] [algorithm]  [options]
 ```

### Example
```bash
 python3 Encrypt.py shell.bin ipv4 -L
```

## Supported Algorithms

- **Encoding Algorithms:**
  - IPv4 Addresses
  - IPv6 Addresses
  - XOR
  - AES
  - RC4
  - MAC Addresses
  - UUID Addresses


## To-Do
- Fix IPV6 to work with all shellcodes


## Disclaimer

This tool is intended for educational and ethical use only. Do not use it for any malicious activities. The authors are not responsible for any misuse of this tool.

## Credits
https://github.com/NUL0x4C/HellShell

https://maldevacademy.com/

