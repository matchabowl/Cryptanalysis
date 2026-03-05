# Some CTF solutions

## Context
These files are solutions to CTF-style tasks that were given to us in a class on Cryptanalysis. Note that since these tasks required access to specific files or servers, the code does not run as is. Furthermore, some of these tasks use SageMath, an open Source Computer Algebra system based on Python.

## Challenges
* Given a Viginère encrypted file significantly longer than the key, recover the key
* Reversing a custom-defined hash-function and performing a length-extension attack
* Using a padding and compression oracle to decrypt a message
* Using Linear Cryptanalysis to recover the secret key used in a substitution permutation network
* Forging a signature against textbook RSA using its homomorphic property
* Recovering the secret key in a Diffie-Hellman implementation without public-key validation
* Recovering the server's private key against a Schnorr-style signature using biased nonces
* Log in as a different user against a broken SRP implementation
* Extract the server-side key in a Ring-LWE key exchange using a reaction attack
* Decrypt a McElliece encrypted message using Stern