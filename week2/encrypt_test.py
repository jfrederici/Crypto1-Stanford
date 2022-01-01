'''
****************************************************************************************************************************************************************
    File name: encrypt_test.py
    Author: Joshua Frederici
    Date created: 2022/1/1
    Python Version: 3.10
    
    Requires pycryptodome.  See https://www.pycryptodome.org/en/latest/ for documentation.

    A quick little script to verify proper encryption of messages encrypted uing encrypt_AES.py by trying to decrypt them again.
****************************************************************************************************************************************************************
    Test values:

    CBC Key          : 140b41b22a29beb4061bda66b6747e14
    CBC InitVector 1 : adaf00082d82837d3e1459d4ca949bd6
    CBC Ciphertext 1 : 3d7290238c29d7ef909145333023dcaf4717ca288797497ac60e4cb8e26598d05f9fb506e00785fa246eef2e75e5fc1e

    CBC Key          : 140b41b22a29beb4061bda66b6747e14
    CBC InitVector 2 : c7b7d86bcb31846afb4b02dc6a9bcf9d
    CBC Ciphertext 2 : 1d0c116c01d98ea6e7c85269059b0ec776d3310f728f8b111a78ab58a32952258044b4911b22c05078a13f3dc44ed9a0

    CTR Key          : 36f18357be4dbd77f050515c73fcf9f2
    CTR nonce_value 1: 0b5219ac730aad9c
    CTR Ciphertext  1: c9f00f8926637a1547b38df6b78343afc6dc1019ad25187b880c402dc87a162f3094400e48ee34cf4215c9ff65e26d5eea09514a014abd4b099c534f

    CTR Key          : 36f18357be4dbd77f050515c73fcf9f2
    CTR nonce_value 2: fb73fcf54aacf42a
    CTR Ciphertext  2: 80023b4137f310e7f3934b1c909024fd375891b0d4e005dc7f8e3de97523
****************************************************************************************************************************************************************
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
ciphertext_cbc = ["adaf00082d82837d3e1459d4ca949bd63d7290238c29d7ef909145333023dcaf4717ca288797497ac60e4cb8e26598d05f9fb506e00785fa246eef2e75e5fc1e", 
    "c7b7d86bcb31846afb4b02dc6a9bcf9d1d0c116c01d98ea6e7c85269059b0ec776d3310f728f8b111a78ab58a32952258044b4911b22c05078a13f3dc44ed9a0"]

ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
ciphertext_ctr = ["0b5219ac730aad9c0000000000000000c9f00f8926637a1547b38df6b78343afc6dc1019ad25187b880c402dc87a162f3094400e48ee34cf4215c9ff65e26d5eea09514a014abd4b099c534f",
    "fb73fcf54aacf42a000000000000000080023b4137f310e7f3934b1c909024fd375891b0d4e005dc7f8e3de97523"]


# Perform decryption on CBC ciphertext
# for each ciphertext_cbc...
for i in range(len(ciphertext_cbc)):
    # ... convert to bytes... 
    ciphertext_cbc[i] = bytes.fromhex(ciphertext_cbc[i])
    
    # ... get the first 16 bytes as the initialization vector and the rest as the ciphertext
    InitVector = ciphertext_cbc[i][0:16]
    ciphertext = ciphertext_cbc[i][16:]
    
    cipher = AES.new(cbc_key, AES.MODE_CBC, InitVector)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print("CBC Plaintext " + str(i+1) + ": " + bytes.decode(plaintext))

# Perform decryption on CTR ciphertext
# for each ciphertext_cbc...
for i in range(len(ciphertext_ctr)):
    # ... convert to bytes... 
    ciphertext_ctr[i] = bytes.fromhex(ciphertext_ctr[i])
    
    # ... get the first 16 bytes as the initialization vector and the rest as the ciphertext
    # Remember that in CTR mode, the first 1/2 of the IV is the nonce and the second 1/2 is the initial counter value.
    InitVector = ciphertext_ctr[i][0:16]
    nonce_value = InitVector[0:8]
    counter_value = InitVector[8:]
    ciphertext = ciphertext_ctr[i][16:]
    
    cipher = AES.new(ctr_key, AES.MODE_CTR, nonce = nonce_value, initial_value = counter_value)
    plaintext = cipher.decrypt(ciphertext)
    print("CTR Plaintext " + str(i+1) + ": " + bytes.decode(plaintext))