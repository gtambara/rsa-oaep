from prime import genRandomPrime, isProbablePrime, genRandomCoprime
import math as mth
import random as rnd
import base64 as b64

"""
Least common multiple of 'a' and 'b'
"""
def lcm(a, b):
    return abs(a*b) // mth.gcd(a, b)

"""
Carmichael totient function for defining e (key exponent)
"""
def carmichaelTot(a: int, b: int) -> int:
    return lcm(a, b)

"""
Extended Euclidean Algorithm for 'a' and 'b'
"""
def egcd(a, b):
    if a == 0 :
        return b, 0, 1
             
    gcd, u, v = egcd(b % a, a)

    x = v - (b // a) * u
    y = u

    return gcd, x, y

"""
Inverse Multiplicative Inverse with extended euclidean algorithm implemented, considering 'a' and 'b' coprimes
"""
def modInv(a, b):
    gcd, x, y = egcd(a, b)
    return x % b

"""
RSA Public key generation as per PKCS#1
"""
def GenRSAKey(keysize: int):
    print("GENERATING RSA KEYS...")

    if keysize < 2048:
        keysize = 2048

    primeSize = keysize // 2

    # Making sure the modulus is big enough to criptograph the message
    p = genRandomPrime(primeSize)
    q = genRandomPrime(primeSize)
    n = p * q   # RSA modulus
#    while(n.bit_length() // 8 < keysize):
#        primeSize = primeSize + (primeSize // 2)
#        p = genRandomPrime(primeSize)
#        q = genRandomPrime(primeSize)
#        n = p * q   # RSA modulus

    while True:
        e = rnd.randrange(2 ** (1024 - 1), 2 ** (1024))
        if mth.gcd(e, (p - 1) * (q - 1)) == 1:
            break

    d = modInv(e,  (p - 1) * (q - 1)) # private RSA exponent

    publicKey = [n, e]
    privateKey = [n, e, int(d), p, q]

    return publicKey, privateKey

def store_keys(key, path):
    with open(path, "wb+") as f:
        for i in key:
            out = b64.b64encode(str(i).encode("utf-8"))
            f.write(out)
            f.write(b'\n')
        f.close()

def import_keys(path):
    with open(path, "r") as f:
        key = [line.rstrip() for line in f]
        f.close()

    for i in range(len(key)):
        key[i] = int(b64.b64decode(key[i].encode("utf-8")))
    return key

#chavepub, chavepriv = GenRSAKey()
#store_keys(chavepub, './keys/pub')
#store_keys(chavepriv, './keys/priv')