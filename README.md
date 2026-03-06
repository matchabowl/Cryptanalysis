# Some CTF solutions

## Context
These files are solutions to CTF-style Cryptography tasks. Note that since these tasks required access to specific files or servers, the code does not run as is. Furthermore, some of these tasks require SageMath, an open Source Computer Algebra system based on Python.

## Challenges
* Given a Viginère encrypted file that is significantly longer than the key, recover the key
* Reversing a custom-defined hash-function and performing a length-extension attack
* Using a padding and compression oracle to decrypt a message
* Using Linear Cryptanalysis to recover the secret key used in a substitution permutation network
* Forging a signature against textbook RSA using its homomorphic property
* Recovering the secret key in a Diffie-Hellman implementation without public-key validation
* Recovering the server's private key against a Schnorr-style signature using biased nonces
* Logging in as another user against a broken SRP implementation
* Extracting the server-side key in a Ring-LWE key exchange using a reaction attack
* Decrypting a McElliece encrypted message using Stern
