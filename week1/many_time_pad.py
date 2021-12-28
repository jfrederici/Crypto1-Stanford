'''
****************************************************************************************************************************************************************
    File name: many_time_pad.py
    Author: Joshua Frederici
    Date created: 2021/12/27
    Python Version: 3.10
    
****************************************************************************************************************************************************************
    Cryptography 1
    Stanford Online via Coursera - https://www.coursera.org/learn/crypto/
    Professor Dan Boneh

    Week 1 - Programming Assignment
    "Many Time Pad"

    Let us see what goes wrong when a stream cipher key is used more than once.  Below are eleven hex-encoded ciphertexts that are the result of encrypting 
    eleven plaintexts with a stream cipher, all with the same stream cipher key.  Your goal is to decrypt the last ciphertext, and submit the secret message
    within it as solution. 
    
    Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].
****************************************************************************************************************************************************************
    My notes:
    
    Regarding the hint given, note the following: 
        - XORing a character and a space shifts the case in the output byte (so a -> A, and A -> a).
        - XORing a character against its opposite case version results in a space in the output byte (A ^ a = <space>).
****************************************************************************************************************************************************************
'''

# function to XOR two byte arrays and return output bytes, output length will match the length of the shorter of the input byte arrays
# https://nitratine.net/blog/post/xor-python-byte-strings/
def xor_bytes(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


# raw hex string messages provided by assignment
# all encrypted using the same stream cipher and key
raw_messages = ["32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"]

# raw hex string of target message to decrypt
# target messsage is encrypted using the same stream cipher and key as messages in raw_messages[]
raw_target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"

# convert messages and target message to bytes and store for use
messages = []
target_msg = ""

for i in range(len(raw_messages)):
    messages.append (bytes.fromhex(raw_messages[i]))
    # DEBUG: print("message " + str(i) + " = " + messages[i].hex(" "))

target_msg = bytes.fromhex(raw_target)

# initialize a list to hold the key -- we only really need to decrypt the key until it matches the length of the target message, though
# we could go further to enable decrypting longer messages intercepted in the future and encrypted using the same key.
keylength = len(target_msg)
key = bytearray([0x00] * keylength)

# XOR every message against every other message looking for likely spaces
for i in range(len(messages)):
    spaces = [0]*keylength
    for j in range(len(messages)):
        if messages[i] != messages[j]:
            xoroutput = xor_bytes(messages[i], messages[j])
            #print("xoroutput(" + str(i) + ", " + str(j) + "): " + xoroutput.hex(","))
            
            # loop through the XOR output... 
            # ... if resulting bytes are between 0x40 and 0x7e then we may have a space.
            # ... if XOR output is 0x00 then we've XORed two identical values and it may have been a space.
            for k in range(keylength):
                if ((xoroutput[k] >= 0x40 and xoroutput[k] <= 0x7e) or (xoroutput[k] == 0)):
                    # note the position of the potential spaces and keep a count of how many hits we get.
                    spaces[k] += 1

    # loop through array to see which character positions had possible spaces (incremented above each time we suspected a space)
    # if hit count exceeds threshold, XOR the original message (i) byte position (m) with a space (0x20) to get the suspected resulting key byte.
    for m in range(len(spaces)):
        if key[m] == 0x00:
            if spaces[m] > 7:
                key[m] = messages[i][m] ^ 0x20

# now we've looped through the XOR of all messages XORed against all other messages, looked for suspected spaces, and 
# calculated and saved the key byte for those positions.  Now use this key against all messages and see how well we did!
# set up a list to hold count of potential errors as we loop through messages.
errors = [0] * keylength
for n in range(len(messages)):
    decrypted_text = xor_bytes(messages[n],key)
    # print(decrypted_text)

    # The message is coming through, but there are a few recurring errors.
    # Output at this point is as follows:
    '''
    'There aue two type\xbd of cyatography\t bne that allow} the \x9fovernment to use brute for'
    'We can aactor the \xa0umber  5 with qFactum computers  We c\xb9n also factor the number 1'
    'Euler whuld probab\xa2y enjoh that noD eis theorem bemomes \xb9 corner stone of crypto - '
    'The nicb thing abo\xbbt Keey}oq is noD ze cryptographkrs ca\xb6 drive a lot of fancy cars'
    'The cipoertext pro\xaauced bh a weak Vnnryption algorgthm l\xb7oks as good as ciphertext '
    'You don t want to \xacuy a stt of car\x13khys from a guy.who s\xa8ecializes in stealing cars'
    'There aue two type\xbd of crhptographJ   that which wgll ke\xbdp secrets safe from your l'
    'We can tee the poi\xa0t whert the chiC ds unhappy if o wron\xbf bit is sent and consumes '
    'A (privfte-key)  e\xa0crypti~n scheme\x13syates 3 algorizhms, \xb6amely a procedure for gene'
    ' The Coicise Oxfor\xaaDictio\x7fary (200\x05)-de\xef\xac\x81nes crypzo as \xache art of  writing o r sol'
    '''

    # loop through decrypted text looking for non-printable characters.
    for o in range(len(decrypted_text)):
        if (decrypted_text[o] < 0x20 or decrypted_text[o] > 0x7f):
            errors[o] += 1
            #print("n: " + str(n) + " o: " + str(o))

for p in range(len(errors)):
    if errors[p] > 0:
        #print("Warning: " + str(errors[p]) + " non-printable characters at position: " + str(p))

        '''
        Warning: 10 non-printable characters at position: 18
        Warning: 4 non-printable characters at position: 34
        Warning: 1 non-printable characters at position: 39
        Warning: 1 non-printable characters at position: 40
        Warning: 1 non-printable characters at position: 41
        Warning: 10 non-printable characters at position: 56
        
        '''
        # Note: the last message in messages[] appears to have non-printable characters (39-41) despite all other messages decrypting successfully.  Ignoring
        # those errors assuming some sort of malformed input message or alternate encoding.


# Our intitial pass through the messages got us most of the way there, but there are few errors to address:
#   - non-printable characters
#   - incorrect printable characters
#
# The human brain can easily determine what the characters SHOULD be in many of the cases.  Will determine the correct
# value for a given position and fix the key here.
key[7] = 0xcc
key[18] = 0xce
key[25] = 0x7f
key[34] = 0x33
key[36] = 0x19
key[50] = 0xfe
key[56] = 0xd8

# Decrypt and print all messages with the fixed key
for q in range(len(messages)):
    print(str(xor_bytes(messages[q],key)))

# Decrypt and print final answer
print()
print("Decrypted target message:")
print(str(xor_bytes(target_msg,key)))