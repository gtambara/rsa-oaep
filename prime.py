import random as rnd
import math as mth

"""
Factor power of 2 from 'num'-1 and return d and s as num-1 = (2^s)d.
"""
def factorPowerTwo(num: int):
    s = 0
    d = num -1
    while True:
        if(d % 2 == 0): 
            d = d // 2
            s = s + 1
        else:
            break
    # for some reason, python needs these this to be explicitly defined int so the pow function doesnt take absurds amounts of time to run
    return int(d), int(s)

"""
Estimate if input 'num' is a prime number by the Miller Rabin method with 'iterations' proportional to accuracy.
It then verifies if 'num' is divisible by any prime lower than 1000.
"""
def isProbablePrime(num: int, iterations: int) -> bool:

    smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
    251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
    457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
    571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
    673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
    797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
    911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    for k in smallPrimes:
        if(mth.gcd(k, num) != 1):
            return False

    d, s = factorPowerTwo(num)
    y = 0
    for i in range(iterations):
        a = rnd.randint(2, num-2)
        x = pow(a, d, num)

        for j in range(s):
            y = pow(x, 2, num)
            if(y == 1 and x != 1 and x != num -1):
                return False
            x = y
        if(y != 1):
           return False

    return True # probably

"""
Generate a prime number of specific 'size'.
"""
def genRandomPrime(size: int) -> int:
    num = rnd.randrange(2**(size -1), (2**(size)) -1)
    while not(isProbablePrime(num, 50)):
        num = rnd.randrange(2**(size -1), (2**(size)) -1)

    return num

"""
Generate a random integer coprime to 'number' with defined 'size'
"""
def genRandomCoprime(number: int, size: int) -> int:
    coprime = rnd.randrange(2**(size -1), (2**(size)) -1)
    while(mth.gcd(coprime, number) != 1):
        coprime = rnd.randrange(2**(size -1), (2**(size)) -1)

    return coprime

#genRandomPrime(1024)