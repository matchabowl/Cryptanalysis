from scheme import order, myhash, generator, modulus
from helper import signing_oracle
from sage.all import ZZ, vector, matrix

public = 0x14ff65d5d5774b2c16d780a7b622173e349a2ad9c37e0e06663cd5981b5a43beee538238a5e34359112a9f3b3140972a261123999766ae6a212be334788b8dbf54de9fd34bcc67cd4bc922ab0374d2b60bce9efb2b78073fdb12a54c28198cabab81905b1cbb63e9e8a3d3753489be9a17d12028d3fccc64ef8de3962512a65

def recover_key(n):
    factor = 2**8

    # collect some valid (R,s) through the oracle
    s = []
    h = []
    for i in range(n):
        m, (R, response) = signing_oracle()
        hash = myhash(R, m)
        s.append(factor * response)
        h.append(factor * hash)

    # construct the lattice matrix
    row_one = vector(ZZ, [order, 0] + s)
    row_two = vector(ZZ, [0, 1] + h)
    A = matrix(ZZ, [row_one,row_two])

    for i in range(n):
        new_row = [0] * (i+2) + [factor * order] + [0] * (n-i-1)
        A = A.stack(matrix([new_row]))

    # LLL reduction, and sorting by norm
    reduced = A.LLL()
    rows_sorted = sorted(reduced.rows(), key=lambda row: row.norm())
    rows = list(filter(lambda x: not x.is_zero(), rows_sorted))
    
    # read private key from short vectors
    for guess in rows: 
        if guess[0] == order: 
            a = -guess[1]
        if guess[0] == -order:
            a = guess[1]
        else:
            continue
        if pow(generator, a, modulus) == public:
                return a 

          
priv = recover_key(100) # -0xed22ff70b455421576c4c113a831e9c1bf10f4ec16d77ec497b42dbb4657500
print(pow(generator, priv, modulus) == public)
print(hex(priv))