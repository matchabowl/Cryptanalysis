# signing_oracle, signature_scheme as was provided
from signing_oracle import signing_oracle
from signature_scheme import myhash, verify, bits
from sage.all import prime_range, prime_factors, factor, vector, Matrix, matrix, ZZ
import os

#copied from the sage Cheat sheet
def solve_integer_system_faster(mat, vec):
    '''
    Note: This is equivalent to .solve_left(), you may need to transpose the input matrix to emulate .solve_right()
    '''
    basis, transformation = mat.LLL(transformation=True)
    assert transformation * mat == basis
    sol1 = basis.solve_left(vec, extend=False)
    assert sol1 * basis == vec
    sol = sol1 * transformation
    assert sol * mat == vec
    return sol

#returns a list of length len(list_of_primes) where the i-th entry is the i-th prime's multiplicity in factor_with_multiplicity (0 if a prime is not present)
def factors_to_vector(factors_with_multiplicity, factors, list_of_primes):
    target = []
    for i in range(len(list_of_primes)):
        prime = list_of_primes[i]
        if prime in factors:
            target.append(factors_with_multiplicity[factors.index(prime)][1])
        else:
            target.append(0)
    return target  

#returns the signature for message
def attack(message):
    #prime factorization of message's hash
    hash = myhash(message)
    factors_with_multiplicity = list(factor(hash)) 
    factors = [factors_with_multiplicity[i][0] for i in range(len(factors_with_multiplicity))]
    maxprime = max(factors) #largest prime occuring in the factorization

    #constructing the target vector for the linear equation: target[i] is the multiplicity of the i-th prime in message's hash
    primes_up_to = prime_range(maxprime+1)
    target = vector(ZZ, factors_to_vector(factors_with_multiplicity, factors, primes_up_to))

    #initializing variables
    length = len(message)
    solved = False
    A = Matrix(ZZ, 0, len(primes_up_to))
    dependency = []

    while not solved:
        #sample random messages and check if all prime divisors of the hash are <= max_prime
        sample = os.urandom(length)
        hash = myhash(sample)
        factors = prime_factors(hash)
        if max(factors) <= maxprime:
            #add message to the list of linearly dependent messages, and add the row corresponding to its hashes prime factorization to the matrix
            dependency.append((sample, hash))
            factors_with_multiplicity = list(factor(hash))
            newrow = vector(ZZ, factors_to_vector(factors_with_multiplicity, factors, primes_up_to))
            A = A.stack(matrix(newrow))
            #check if a linear dependency was found
            try:
                x = solve_integer_system_faster(A, target)
                solved = True
            except:
                pass
    
    assert A.transpose()*x == target

    #query signatures for all messages in the linear dependency
    signatures = []
    for entry in dependency:
        signatures.append(int.from_bytes(signing_oracle(entry[0]))) 
    
    #calculate target message's signature
    signature = 1
    for i, sgn in enumerate(signatures):
        a = pow(sgn, x[i], n)
        signature = (signature * a) % n

    return signature.to_bytes((bits + 7)//8, 'big')

    
####################################################################################################################################################################################################################################################################################


n = 0xee8fdeb12150be6ad7b937ba42b7c5bfbf2496d419e1b349ae27290e3b3c017c9851fe12ef92e0c29323f9b29098fbda4b566c82d882450d3b5312362f9aa4a0f93b4cf96707716cbbf1681a6a445b7c97c88da9b82652585525ad3fa69aef455a1dab4809d13126a011784443a3ea17247899825192778f52a2d813e90bcaf3
e = 0x10001
pub = (n, e)
target = b'I solved it!!!!!!!!!!!!!!!!!!!!!!!! :^)'

#calculating the signature
signature = attack(target) 
print(signature) #b'O)\xa6T\x84\x00\xb5\xc9.\x0c\x06\xe3\xaf\xad\xcb\xda\xf7\xe5\x10\xc1\xd3\xcdq:x\x84\xf0\x9f\x17/-\x16o\xdfc\x11\xda\xd1\xabR\xd0E\xf5/\x99|\xacBq\x1e\xc4\xd4;\x0e%\xa7W\xddk\xa8\xcb\xa9\\\x00\xa32.&\x01\xa1\xc4\xbd\xad#|\x05\x825q\x9d\xcd\xc9\xb8\x06\x16\x1a\x83lF\xce\x86H\xf6\x17/\x08\xa4#T\x84Y\x1a\x9c\xb9\xe1O\xb4\xa6@p\xd6\xd2m\xfe`\xf2\x13\x82t\x94\xad\x1f\xba\xca#\xba\xd3V'
print(verify(target, signature, pub)) #True