from helper import compression_oracle, padding_oracle
import string

################################################################################################################################
#Task 1

def guessCharacter(prefix):
    characters = list(string.ascii_uppercase + string.ascii_lowercase + string.digits)
    for char in characters: #for each valid character, observe encryption length after appending it. The value that keeps the length at 112 bytes is part of the secret
            text = prefix + char
            x = len(compression_oracle(text.encode()))
            if x < 128:
                return char

def guessSecret(text):
    secret = ""
    while(char := guessCharacter(text + secret)) is not None: #keep guessing the secret's next character until done
        print(text + secret)
        secret += char
    print(text + secret)
    return secret


secret = guessSecret("token=") #"Ue9iIUdaPdDhRsrlGHBUxTwOLjcNOa9r"
print(secret.hex())



###############################################################################################################################
#Task 2

def decrypt_withpadoracle(block):
    assert len(block) == 16
    hits = 0 
    validDelta = 0
    prefix = bytearray(b'\x00'*16) #take two zero bytes as prior block
    for delta in range(256): #xor all values 0-255 into the last byte
        prefix[-1] ^= delta
        x = padding_oracle(bytes(prefix) + block)
        if x != -1: #if padding was valid
            if hits > 0: #if two distinct deltas yield valid paddings, we are unable to tell which delta turns the last byte in the block decrypted text into 0x01. However, that means the second to last Byte must be \xcc
                hits += 1
                break
            hits += 1
            validDelta = delta
        prefix[-1] ^= delta
    
    if hits > 1: #if we could not tell which delta turns the last byte in the decryption to 0x01
        prefix = bytearray(b'\x00'*14 + b'\xcc' + b'\x00') #use prior decryption block that turns the second to last byte to \x00. Now only one delta will yield a valid padding
        for delta in range(256):
            prefix[-1] ^= delta
            x = padding_oracle(bytes(prefix) + block)
            if x != -1:
                validDelta = delta 
                break 
            prefix[-1] ^= delta
    
    lastbyte = 0x01 ^ validDelta #last byte of raw block decryption
    decrypted = lastbyte.to_bytes(1, 'big')

    j = 2
    prefix = bytearray(b'\x00'*16)
    for byte in range(14, -1, -1): #iteratively set the last byte in the block decryption to 0x02, 0x03, ... 
        pDelta = lastbyte ^ j
        prefix[-1] ^= pDelta 
        for delta in range(255): #find the unique delta that extends the \xcc chain to the current length
            prefix[byte] ^= delta 
            x = padding_oracle(bytes(prefix) + block)
            if x != -1:
                char = b'\xcc'[0] ^ delta #calculate block decrypted byte value
                break
            prefix[byte] ^= delta
        decrypted = char.to_bytes(1, 'big') + decrypted 
        prefix[-1] ^= pDelta
        j += 1 
    
    return decrypted


thirdBlock = bytes.fromhex('4142434445464748494a4b4c4d4e4f50') #some 16 byte sequence
decryptedThirdBlock = decrypt_withpadoracle(thirdBlock) #raw AES decryption of thirdblock
target = b'solved it!' + b'\xcc'*5 + b'\x06' #target decryption value for the last block
secondBlock = bytes(a ^ b for a, b in zip(decryptedThirdBlock, target)) #calculate secondBlock such that decrypting will return target value for last block
decryptedSecondBlock = decrypt_withpadoracle(secondBlock)
target = b'Hello, world! I '
iv = bytes(a ^ b for a, b in zip(decryptedSecondBlock, target))
encrypted = iv + secondBlock + thirdBlock #1c1406bba6044293d357d8b30211feb86eb8ba54ffa5968f97bd361b6fd64ae84142434445464748494a4b4c4d4e4f50
print(encrypted.hex())