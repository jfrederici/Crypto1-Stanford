'''
****************************************************************************************************************************************************************
    File name: encrypt_AES.py
    Author: Joshua Frederici
    Date created: 2022/1/1
    Python Version: 3.10
    
    Requires pycryptodome.  See https://www.pycryptodome.org/en/latest/ for documentation.

****************************************************************************************************************************************************************
    Cryptography 1
    Stanford Online via Coursera - https://www.coursera.org/learn/crypto/
    Professor Dan Boneh

    Week 2 - Programming Assignment
    AES Decryption using CBC and CTR Modes

    In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR).  In both cases
    the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

    For CBC encryption we use the PKCS5 padding scheme discussed  in the lecture (14:04). While we ask that you implement both encryption and decryption, we
    will only test the decryption function.   In the following questions you are given an AES key and a ciphertext (both are  hex encoded ) and your goal is
    to recover the plaintext and enter it in the input boxes provided below.

    For an implementation of AES you may use an existing crypto library such as PyCrypto  (Python), Crypto++  (C++), or any other. While it is fine to use the
    built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself.`

****************************************************************************************************************************************************************
    Goal: Implement encryption and encrypt recovered plaintext from given ciphertext using the same key as used during decryption.

    Note that while we are using the same key as initial decryption, the cipher is generating new IV's/nonces leading to completely different ciphertext.
****************************************************************************************************************************************************************
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util import Counter
from Crypto import Random

cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
plaintext_cbc = ["Basic CBC mode encryption needs padding.", "Our implementation uses rand. IV"]

ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
plaintext_ctr = ["CTR mode lets you build a stream cipher from a block cipher.", "Always avoid the two time pad!"]

# Perform encryption on  plaintext using CBC mode
# for each plaintext_cbc...
for i in range(len(plaintext_cbc)):
    # ... convert to bytes... 
    plaintext_bytes = bytes(plaintext_cbc[i], "utf-8")
    
    # set up cipher and encrypt.
    # remember we need to pad the input to a multiple of the blocksize.
    cipher = AES.new(cbc_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    # save the IV used by the cipher.  This will be different each run.
    InitVector = cipher.iv
    print("CBC InitVector " + str(i+1) + " : " + InitVector.hex())
    print("CBC Ciphertext " + str(i+1) + " : " + ciphertext.hex())
    print()

# Perform encryption on plaintext using CTR mode with initial counter value starting as 0
# for each plaintext_ctr...
for i in range(len(plaintext_ctr)):
    # ... convert to bytes... 
    plaintext_bytes = bytes(plaintext_ctr[i], "utf-8")
    
    # set up cipher and encrypt.
    cipher = AES.new(ctr_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext_bytes)
    # save the IV used by the cipher.  This will be different each run.
    nonce_value = cipher.nonce
    print("CTR nonce_value " + str(i+1) + ": " + nonce_value.hex())
    print("CTR Ciphertext  " + str(i+1) + ": " + ciphertext.hex())
    print()