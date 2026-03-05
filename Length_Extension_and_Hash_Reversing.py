from wonky_has import wonky_compress, wonky_hash, rotate

def calculatePadding(message): # returns the padding for message
    bitlen = len(message) * 8
    padding = b'\x80'
    padding += b'\0' * ((23 - len(message)) % 32)
    padding += bitlen.to_bytes(8, 'big')
    assert len(message+padding) % 32 == 0
    return padding

def attackWithKeyLength(n):
    keyReplacement = b'\x00'*n
    padding1 = calculatePadding(keyReplacement + b'Hello, world!') # calcualting the padding that was used for the message of which we know the hash value
    suffix = b'I solved it!'
    padding2 = calculatePadding(keyReplacement + b'Hello, world!' + padding1 + suffix) # calculating the padding for the newly created message
    suffixAndPadding = suffix + padding2
    blocks = [suffixAndPadding[i:i+32] for i in range(0, len(suffixAndPadding), 32)]
    state = bytes.fromhex(b'6b1ee67fa43baa0cdab734decbfef83a'.decode('ascii')) # setting state to the known hash value
    for block in blocks: #length-extension attack
        state = wonky_compress(state, block)
    return b'Hello, world!' + padding1 + suffix + state 

def stateToZero(state): # Given the state of wonky_compress, returns 16 bytes such that after consumption, wonky_compress will be in state b'00'*32
    A,B,C,D = [int.from_bytes(state[i:i+4],'big') for i in range(0,16,4)]

    first = 0xffffffff ^ 0xeeeeeeee ^ 0xdeadbeef ^ 0x0c0ffee0 ^ rotate(D,7) ^ rotate(C, 5) ^ rotate(B, 3) ^ rotate(A, 1)
    A = 0xffffffff - B
    B = 0xeeeeeeee ^ C
    C = 0xdeadbeef ^ D
    D = 0xffffffff ^ 0xeeeeeeee ^ 0xdeadbeef

    second = 0xeeeeeeee ^ 0xdeadbeef ^ 0x0c0ffee0 ^ rotate(D, 7) ^ rotate(C,5) ^ rotate(B, 3) ^ rotate(A, 1)
    A = 0xffffffff - B
    B = 0xeeeeeeee ^ C
    C = 0xdeadbeef ^ D
    D = 0xeeeeeeee ^ 0xdeadbeef
    
    third = 0xdeadbeef ^ 0x0c0ffee0 ^ rotate(D, 7) ^ rotate(C,5) ^ rotate(B, 3) ^ rotate(A, 1)
    A = 0xffffffff - B
    B = 0xeeeeeeee ^ C
    C = 0xdeadbeef ^ D
    D = 0xdeadbeef

    fourth = 0x0c0ffee0 ^ rotate(D, 7) ^ rotate(C,5) ^ rotate(B, 3) ^ rotate(A, 1)
    
    return b''.join(v.to_bytes(4,'big') for v in (first, second, third, fourth))


def findCompressionCollision(prefix1, prefix2): #takes two 4 byte prefixes and finds a suffix that leads to a collision
        state = b'cc'*16
        A,B,C,D = [int.from_bytes(state[i:i+4],'big') for i in range(0,16,4)]

        #calculating wonky_compress' state after consuming prefix1
        F = prefix1
        F ^= rotate(A, 1)
        F ^= rotate(B, 3)
        F ^= rotate(C, 5)
        F ^= rotate(D, 7)
        A = 0xffffffff - B
        B = 0xeeeeeeee ^ C
        C = 0xdeadbeef ^ D
        D = 0x0c0ffee0 ^ F

        suffix1 = stateToZero(b''.join(v.to_bytes(4,'big') for v in (A, B, C, D))) #find 16 byte suffix that returns wonky_compress' state to 0
        value1 = prefix1.to_bytes(4, 'big') + suffix1

        #calculating wonky_compress' state after consuming prefix2
        state = b'cc'*16
        A,B,C,D = [int.from_bytes(state[i:i+4],'big') for i in range(0,16,4)]
        F = prefix2
        F ^= rotate(A, 1)
        F ^= rotate(B, 3)
        F ^= rotate(C, 5)
        F ^= rotate(D, 7)
        A = 0xffffffff - B
        B = 0xeeeeeeee ^ C
        C = 0xdeadbeef ^ D
        D = 0x0c0ffee0 ^ F

        suffix2 = stateToZero(b''.join(v.to_bytes(4,'big') for v in (A, B, C, D))) #find 16 byte suffix that returns wonky_compress' state to 0
        value2 = prefix2.to_bytes(4, 'big') + suffix2

        return value1, value2

#Length-extension attack
forged = attackWithKeyLength(42) #Length-extension attack with key length assumed to be 42
print("Forged Message: " + forged.hex())

#hash collision
x,y = findCompressionCollision(int.from_bytes(b'\x12\xe8\x96\x99', 'big'), int.from_bytes(b'\x2e\x04\xfd\x43', 'big'))
print("First element for collision: " + x.hex())
print("Second element for collision: " + y.hex())
print("Collision: " + str(wonky_hash(x) == wonky_hash(y)))

print(wonky_hash(bytes.fromhex("12e896995c89895396a4fca8fdb6384fda452422")) == wonky_hash(bytes.fromhex("2e04fd432abc644d0b2987ef1ad5669ea39df396")))

