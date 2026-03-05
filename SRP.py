#importing the protocol implementation and the helper function
from srp import H, modulus, generator, k, u
from helper import Interactor
import random

seed = b'EIaeqpE2A6vn6vMV'

#the same as an honest client1()
def client1():
    global a 
    a = random.randrange(modulus - 1)
    A = pow(generator, a, modulus)
    return A

def client2 (B):
    # extract the highest 245 bits of Math.floor(B / k) = v + q. We can assume them to be equal to those of v
    shift = 1024 - 245
    v_q = B // k
    v_q = v_q >> shift 

    #use some (huge) wordlist to find a match. I used https://raw.githubusercontent.com/dwyl/english-words/refs/heads/master/words_alpha.txt
    with open("words_alpha.txt", 'r', encoding='utf-8') as f:
        for word in f:
            word = word.strip()
            x = H(seed, word.encode())
            v = pow(generator, x, modulus)
            v = v >> shift
            if v == v_q:
                #In this case 'word' should equal Alice's private password.
                print(f"Password is: {word}")
                c = pow(B - k * pow(generator, x, modulus), a + u*x, modulus)
                chk = H(c, b'This is Alice!')
                return chk 
    raise RuntimeError("Could not find password")
    
interact = Interactor(URL)
res = interact(client1, client2)
print(res)

