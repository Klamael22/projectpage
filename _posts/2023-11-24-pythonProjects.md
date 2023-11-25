---
title: "Python Scripting Projects"
categories:
  - Blog
tags:
  - Python
  - Scripting
---

As part of my own personal development I have been learning Python.
This post will link to Python scripts I have created. These scripts will mostly be proof of concept projects, as I learn the language.

[createFiles.py](https://github.com/Klamael22/pythonProjects/tree/e4cb8135a0c6b0827ca0cf0ef110e75b01cd2819/createFiles)
- This is just a simple script to learn a little automation.
- When this script runs it creates 10 text files in the current working directory, named text_file(0-9).txt. If these files already exist, it will create an additional 10 files titled text_file(10-19).txt, and so on.

[encryptDecrypt.py](https://github.com/Klamael22/pythonProjects/tree/e4cb8135a0c6b0827ca0cf0ef110e75b01cd2819/encryption)
- Just a simple script to explore Crypto.Cipher method. Allows user to encrypt or decrypt a string using ECB mode of AES.

[passGen.py](https://github.com/Klamael22/pythonProjects/tree/e4cb8135a0c6b0827ca0cf0ef110e75b01cd2819/password%20generator)
- Simple scrypt to create random passwords. Prompts user for desired length, and any special characters that must be excluded, and returns the randomly generated password.