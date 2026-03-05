from sage.all import prime_range, randint, crt
# scheme is the source code of encrypt() / decrypt(), helper is the oracle as provided 
from scheme import modulus, generator, order, enclen
from helper import decryption_oracle

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
except ModuleNotFoundError:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256

def find_H(modulus, order):
    n = modulus - 1
    ord_H = 1
    factorization = []

    #In ascending order, take as many prime factors of modulus-1 as needed to have product > order. Returns the product and the factorization
    prime_list = prime_range(10000000)
    for prime in prime_list:
        if n % prime == 0:
            counter = 0
            
            while(n % prime == 0):
                ord_H *= prime 
                n //= prime 
                counter += 1
                if ord_H > order:
                    break
            
            factorization.append((prime, counter))
            if ord_H > order:
                return ord_H, factorization 
    
    raise Exception("could not find group H of smooth size")


def find_generator(ord_H, factorization, modulus):
    #For any nonzero g in F_p: ord(g^x) | ord_H by Little Fermat
    x = (modulus - 1) // ord_H
    while True:
        guess = randint(2, modulus-1)
        guess = pow(guess, x, modulus)
        generator = True
        # Check that ord(guess) does not properly divide ord_H
        for prime, _ in factorization:
            if pow(guess, ord_H // prime, modulus) == 1:
                generator = False
                break
        if generator:
            return guess

def find_a_mod(prime, generator, ord_H, modulus):
    # ord(r) = prime
    r = pow(generator, ord_H // prime, modulus)
    m = b'Hello, world!'

    # Check for which i r^i = shared secret mod prime
    for i in range(prime):
        shared = pow(r, i, modulus)
        shared = shared.to_bytes(enclen)
        shared = SHA256.new(shared).digest()
        gcm = AES.new(shared, mode=AES.MODE_GCM, nonce=b'\0'*16)
        aes_part = gcm.encrypt_and_digest(m)
        ciphertext = r.to_bytes(enclen) + b''.join(aes_part)
        if decryption_oracle(ciphertext) == m:
            return i

def increase_multiplicity(prime, generator, ord_H, modulus, last_multiplicity, x):
    # similar to find_a_mod, but only check x, x + prime^i, x + 2 prime^i, ..., x+ (prime - 1) prime^i
    step = pow(prime, last_multiplicity)
    r = pow(generator, ord_H // (step * prime), modulus)
    m = b'Hello, world!'

    for k in range(prime):
        if k != 0:
            x += step
        shared = pow(r, x, modulus)
        shared = shared.to_bytes(enclen)
        shared = SHA256.new(shared).digest()
        gcm = AES.new(shared, mode=AES.MODE_GCM, nonce=b'\0'*16)
        aes_part = gcm.encrypt_and_digest(m)
        ciphertext = r.to_bytes(enclen) + b''.join(aes_part)
        if decryption_oracle(ciphertext) == m:
            return x


def attack(modulus, order):
    ord_H, factorization = find_H(modulus, order) # Determine smooth |H| and its factorization
    generator_H = find_generator(ord_H, factorization, modulus) # Determine an element of order |H|
    residues = []
    for prime, multiplicity in factorization:
        x = find_a_mod(prime, generator_H, ord_H, modulus) # Determine a mod prime
        for i in range(1, multiplicity): # Determine a mod prime^multiplicity
            x = increase_multiplicity(prime, generator_H, ord_H, modulus, i, x) # Determine a mod prime^{i+1} based on a mod prime^i
        residues.append((pow(prime, multiplicity), x))

    # Use CRT to get the secret key
    secret = residues[0][1]
    z = residues[0][0]
    for factor, residue in residues[1:]:
        secret = crt(secret, residue, z, factor)
        z *= factor
    
    return secret

secret = attack(modulus, order)
print("secret: " + str(secret.hex())) # 0x7c311fff2258c8040ea6d10e3e94703f04a63fcbefa915dd3748e5537b4f3301
public = 0x0072e1347d71f4b27b0665465697b32132d5407a21198ff152496979d2e80db767e930a332a9b18b7844bf750ee96dae91eba679bd3726ed94e2e8e6d6a5ff7f8f78fa36502cfbb55f4c9dd235f2906e9a992a9e0905ddbd1560aad216927135b96d516005a4b4a87b2a22ecb5e7354995ba38f627aacc50210f3a14b5cedfa7
print(pow(generator, secret, modulus) == public) # True