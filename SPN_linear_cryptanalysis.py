#encryption is a file containing the cipher source code as provided to us
from encryption import BLOCKSIZE, SBITS, SBOX, KEYLENGTH, ROUNDS


# approximations as given to us
eqns = [
    (0.378, 0x0000eb0000000000, 0x20000000080000a0),
    (0.378, 0x0000040000000000, 0x0018080000200000),
    (0.372, 0x0087000000000000, 0x0000200008000888),
    (0.365, 0xf700000000000000, 0x0040000000128400),
    (0.359, 0x0700000000000000, 0x0000040000000020),
    (0.353, 0x0000f20000000000, 0xc000000000000000),
    (0.353, 0x0000000000008700, 0x0000001000000000),
    (0.348, 0x00000000000e0000, 0x8048880000108010),
    (0.342, 0x00000000000000f0, 0x0898180000205000),
    (0.341, 0x00000000eb000000, 0x2000000008000828),
    (0.337, 0x0000000000070000, 0x8000801000220400),
    (0.335, 0x0400000000000000, 0x0002000080010000),
    (0.331, 0x0000000004000000, 0x1000010630000000),
    (0.326, 0x0000000007000000, 0x000000204000a000),
    (0.326, 0x000000000e000000, 0x0200408408000908),
    (0.326, 0x000000000000000a, 0x0004000002482800),
    (0.320, 0x000000000000000e, 0x0080140000000021),
    (0.319, 0x0000000000090000, 0x0048081000328410),
    (0.315, 0x0000000000000087, 0x0400400a10000040),
    (0.314, 0x4d00000000000000, 0x088020000800188b),
    (0.309, 0x00ca000000000000, 0x0081100004000001),
    (0.305, 0x0000190000000000, 0xe0000000080000a0),
    (0.304, 0x0000ef0000000000, 0x20180800082000a0),
    (0.304, 0x000000000000eb00, 0x00080a1000200012),
    (0.304, 0x00000e0000000000, 0x0400408408000068),
    (0.303, 0x000000000000f700, 0x8040801000220000),
    (0.298, 0x0000008700000000, 0x9000810801128000),
    (0.298, 0x0000000000f70000, 0x0880000000003003),
    (0.294, 0xf300000000000000, 0x0042000080138400),
    (0.290, 0xf000000000000000, 0x0040040000128420),
    (0.284, 0x0000f60000000000, 0xc018080000200000),
    (0.282, 0x0300000000000000, 0x0002040080010020),
    (0.280, 0x0000000000007000, 0x8040800000220000),
    (0.275, 0x00000000e5000000, 0x2200408400000120),
    (0.266, 0x0000e50000000000, 0x24004084000000c8),
    (0.266, 0x4a00000000000000, 0x08802400080018ab),
    (0.242, 0x0000000000006c00, 0x00080a0000200012),
]

# reverses substitution
def inverse_substitute(ys, sbox):
    xs = 0
    for i in range(BLOCKSIZE):
        y = (ys >> SBITS*i) % 2**SBITS
        x = sbox.index(y)
        xs |= x << SBITS*i
    return xs

# takes a path to a file containing plaintext - ciphertext pairs as the ones provided. Returns two lists where the i-th entry is the i-th plaintext (ciphertext) as integer
def read_file(path):
    plaintexts = []
    ciphertexts = []
    with open(path, "r") as file:
        for line in file:
            parts = line.split()
            plain = int(parts[0], 16)
            cipher = int(parts[1], 16)
            plaintexts.append(plain)
            ciphertexts.append(cipher)
    return plaintexts, ciphertexts

# takes a linear approximation, a list of plaintexts, a list of their corresponding ciphertexts, a bytenumber describing which byte (0-7, little endian) should be recovered, and a current key estimate. Returns the byte value and associated bias
def guess_byte(approx, plain, cipher, bytenumber, key):
    #mask to reset key after each iteration
    hex_ff_string = 'ff'
    hex_00_string = '00'
    mask = hex_ff_string * (KEYLENGTH-bytenumber) + hex_00_string + hex_ff_string * bytenumber
    mask = int(mask, 16) 

    imask = approx[1]
    omask = approx[2]
    max_bias = -1
    max_val = -1
    
    for i in range(256):
        key |= i << (bytenumber * 8)
        
        count = 0

        # calculating bias
        for index, ciphertext in enumerate(cipher):
                # inverting the last round
                last_round_ciphertext = inverse_substitute(ciphertext ^ key, SBOX)
                # calculating the dot product
                x = (imask & plain[index]).bit_count() % 2
                y = (omask & last_round_ciphertext).bit_count() % 2
                z = x ^ y
                if z == 0:
                    count += 1
        
        bias = abs(count - 500)
        if bias > max_bias:
            max_bias = bias 
            max_val = i
        
        key &= mask
        
    return max_val, max_bias

# almost the same as guess_byte, but recovers two bytes: at position bytenumber1, and bytenumber2
def guess_two_bytes(approx, plain, cipher, bytenumber1, bytenumber2, key):
    hex_ff_string = 'ff'
    hex_00_string = '00'
    mask = hex_ff_string * (KEYLENGTH-bytenumber1) + hex_00_string + hex_ff_string * bytenumber1
    mask = int(mask, 16)

    max_bias = -1
    max_val = (-1, -1)

    for i in range(256):
        key |= i << (bytenumber1 * 8)

        bytevalue, bias = guess_byte(approx, plain, cipher, bytenumber2, key)
        if bias > max_bias:
            max_bias = bias 
            max_val = (i, bytevalue)

        key &= mask
    
    return max_val
        
# given a path to a file of plaintext - ciphertext pairs as in the ones provided, recovers the lastround key
def recover_lastround_key(path):
    plain, cipher = read_file(path)
    key = int('0', 16)

    fourth, _ = guess_byte(eqns[6], plain, cipher, 4, key)
    key |= fourth << 32

    seventh, _ = guess_byte(eqns[5], plain, cipher, 7, key)
    key |= seventh << 56

    zeroth, third = guess_two_bytes(eqns[0], plain, cipher, 0, 3, key)
    key |= third << 24
    key |= zeroth

    first, _ = guess_byte(eqns[13], plain, cipher, 1, key)
    key |= first << 8


    fifth, _ = guess_byte(eqns[2], plain, cipher, 5, key)
    key |= fifth  << 40

    second, _ = guess_byte(eqns[10], plain, cipher, 2, key)
    key |= second << 16

    sixth, _ = guess_byte(eqns[1], plain, cipher, 6, key)
    key |= sixth << 48

    return key

# given a path to a file of plaintext - ciphertext pairs as in the ones provided, recovers the original key. Runs for a few (6-8) Minutes
def recover_key(path):
    key = recover_lastround_key(path)
    modulus = (1 << SBITS)**KEYLENGTH
    inverse = pow(5, -1, modulus)
    for _ in range(ROUNDS):
        key = (key * inverse) % modulus
    return key

secret_key = recover_key('pairs')
print(hex(secret_key))

