'''
****************************************************************************************************************************************************************
    File name: encrypt_AES.py
    Author: Joshua Frederici
    Date created: 2022/1/2
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
    Goal: Decrypt given ciphertext to recover the plaintext messages using the key provided.

****************************************************************************************************************************************************************
'''

from Crypto.Cipher import AES

# function to XOR two byte arrays and return output bytes, output length will match the length of the shorter of the input byte arrays
# https://nitratine.net/blog/post/xor-python-byte-strings/
def xor_bytes(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
cbc_iv = ("4ca00ff4c898d61e1edbf1800618fb28", "5b68629feb8606f9a6667670b75b38a5")
plaintext_cbc = ["We're all at the same skill level, Jerry.", "No soup for you! Next!"]

ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
ctr_iv = ("69dda8455c7dd4254bf353b773304eec", "770b80259ec33beb2561358a9f2dc617")
plaintext_ctr = ["Look, I work for the phone company. I've had a lot of experience with semantics, so don't try to lure me into some maze of circular logic.", "It's a Festivus miracle!"]

# Perform encryption on CBC plaintext
# for each plaintext_cbc...
for i in range(len(plaintext_cbc)):
    plaintext_bytes = bytearray(plaintext_cbc[i], "utf-8")
    iv = bytes.fromhex(cbc_iv[i])
    # the iv will lead ht encrypted message in the ciphertext
    ciphertext_bytes = bytearray(iv)

    # calculate the number of whole blocks
    # we will always need one more block.  Either we will be rounding up to account for a partial block that we'll pad, or
    # if the message is even divisible by the block size then we will need to create a full block of padding.
    num_blocks = int(len(plaintext_bytes) / AES.block_size) + 1
    # calculate proper PKCS5 padding and add
    padding_length = AES.block_size - (len(plaintext_bytes) % AES.block_size)
    if padding_length == 0:
        # if the message was evenly divisible by the block size, we'll need to create a full block of padding.
        padding_length = AES.block_size
    plaintext_bytes.extend([padding_length] * padding_length)

    # XOR the block with the IV
    # Encrypt the block with the key
    # Set the IV for the next block to the ciphertext block
    # Add the ciphertext block to the ciphertext
    for j in range(int(num_blocks)):
        ptBlock = bytes(plaintext_bytes[j * AES.block_size : (j + 1) * AES.block_size])
        block = bytearray(xor_bytes(ptBlock, bytes(iv)))
        cipher = AES.new(cbc_key, AES.MODE_ECB)
        block = cipher.encrypt(block)
        iv = bytearray(block)
        ciphertext_bytes.extend(block)
    print("CBC Encrypted " + str(i) + ": " + bytearray.hex(ciphertext_bytes))

# Perform encryption on CTR plaintext
# for each plaintext_ctr...
for i in range(len(plaintext_ctr)):
    plaintext_bytes = bytearray(plaintext_ctr[i], "utf-8")
    iv = bytes.fromhex(ctr_iv[i])
    # the iv will lead the encrypted message in the ciphertext
    ciphertext_bytes = bytearray(iv)
    # convert the iv to an int so we can easily increment it for each block
    iv = int.from_bytes(iv, 'big')

    # calculate the number of whole blocks
    num_blocks = int(len(plaintext_bytes) / AES.block_size)
    # check if there's a partial block, and if so add it to the number of blocks we'll process.
    if (len(plaintext_bytes) % AES.block_size) != 0:
        num_blocks += 1

    # Encrypt the IV with the key
    # XOR the block with the plaintext to get the ciphertext
    # Add the ciphertext block to the ciphertext
    # Increment the IV for the next block
    for j in range(int(num_blocks)):
        ptBlock = bytes(plaintext_bytes[j * AES.block_size : (j + 1) * AES.block_size])
        cipher = AES.new(ctr_key, AES.MODE_ECB)
        block = cipher.encrypt(iv.to_bytes(AES.block_size, 'big'))
        block = xor_bytes(block, ptBlock)
        iv += 1
        ciphertext_bytes.extend(block)
    print("CTR Encrypted " + str(i) + ": " + bytearray.hex(ciphertext_bytes))