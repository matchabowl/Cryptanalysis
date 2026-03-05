from sage.matrix import *
from sage.all import *
from mceliece import H as H1, n, k, w, pack, unpack
import random

try:
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    from Cryptodome.Hash import SHA256
    from Cryptodome.Cipher import AES

def attack(path):
    #reading and initializing data
    with open(path, 'r') as f:
        encrypted = bytes.fromhex(f.readline())
    l = len(H1) // 8
    s, c = encrypted[:l], encrypted[l:]
    rank = n - k 
    F = GF(2)
    H = Matrix(F, H1)
    s = vector(F,unpack(s))
    
    while True:
        
        #sampling I by checking a random set of n-k columns for linear independence
        independent = False
        while not independent:
            I = random.sample(range(n), rank)
            H_I = H.matrix_from_columns(I)
            if H_I.rank() == rank:
                independent = True 
        
        # Bringing H to systematic form (using a permutation matrix that takes those I columns to columns 1, ..., n-k)
        I_c = sorted(list(set(range(n)) - set(I)))
        permutation = I + I_c
        P = Matrix.identity(F, n).columns()
        P = [P[i] for i in permutation]
        P = Matrix(F, P).transpose()
        
        M = H * P
        H_e = M.echelon_form()
        U = M.solve_left(H_e)
        
        #Splitting up H_e
        JA = list(range(n-k, n-(k // 2)))
        ja = len(JA)
        JB = list(range(n-(k // 2), n))
        jb = len(JB)
        A = H_e[:, JA]
        B = H_e[:, JB]

        #Meet in the middle
        l = 20
        L = random.sample(range(rank), l)

        us = U*s
        for p in range(4, 7):
            pa = p // 2
            pb = p - pa 
            hashmap = dict()
            for ones in Subsets(range(ja), pa):
                a = zero_vector(F, ja)
                for i in ones: 
                    a[i] = 1
                key = vector(F,[(us - A*a)[i] for i in L])
                hashmap[tuple(key)] = a

            for ones in Subsets(range(jb), pb):
                b = zero_vector(F, jb)
                for i in ones: 
                    b[i] = 1
                v = vector(F,[(B*b)[i] for i in L])

                if tuple(v) in hashmap:
                    a = hashmap[tuple(v)]
                    e_I = us - A*a - B*b
                    e_p = vector(F, list(e_I)+list(a)+list(b))
                    if sum(e_p) == w:
                        e = P * e_p
                        h = SHA256.new(pack([int(b) for b in e])).digest()
                        aes = AES.new(h, AES.MODE_GCM, nonce=b'\0')
                        try: 
                            return aes.decrypt(c).decode()
                        except:
                            continue

x = attack("ciphertext.txt")
print(x)