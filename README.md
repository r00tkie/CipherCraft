# Encoder

## Overview

This Python script is a versatile tool designed to encode shellcode using various algorithms, providing an extra layer of obfuscation. It takes raw shellcode as input and allows you to encode it using different methods, such as IPv4 addresses, IPv6 addresses, XOR, AES, RC4, MAC addresses, and UUID addresses.

## Features

Algorithm Choices: Choose from a variety of encoding algorithms to customize the obfuscation process.
Cipher Generation: Obtain the encoded shellcode as a cipher for further use or analysis.
Loader Code Generation: Utilize the `-L` option to generate ready-to-compile loader.

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
