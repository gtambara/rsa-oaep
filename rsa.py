from oaep import oaepEncode, oaepDecode
from octetCoverting import i2osp, os2ip
from key import GenRSAKey, store_keys, import_keys
import hashlib as hsh

"""
RSA encription of 'message' representative  with 'public key' as per PKCS#1
"""
def rsaEncript(publicKey: list, message: int):
    print("RSA ENCRIPTION STARTING...")
    n = publicKey[0]        # rsa modulus
    e = publicKey[1]        # rsa exponent

    return pow(message, int(e), int(n))

"""
RSA decription of 'message' representative  with 'private key' as per PKCS#1
"""
def rsaDecript(privateKey: list, criptogram):
    print("RSA DECRIPTION STARTING...")
    # RSA private key format based ASN.1 from PKCS#1 v.2.2 RFC8017 simplifiyng dP, dQ and qInv
    n = privateKey[0]       # rsa modulus
    e = privateKey[1]       # public exponent
    d = privateKey[2]       # private exponent
    p = privateKey[3]       # first prime factor
    q = privateKey[4]       # second prime factor

    u = 2                   # base number of rsa modulus prime factors (p, q)

    message = pow(criptogram, d, n)

    # In case there is a future implementation on a different key generating format that uses more than two prime factors (out of the scope of this project)
    if len(privateKey) != 5:
        otherPrimeInfos = privateKey[5] # optional extra parameters for aditional primes

        r_crt = otherPrimeInfos[0]  # prime factors of rsa modulus n
        d_crt = otherPrimeInfos[1]  # CRT additional factors of r (exponents) d[i] = d % (r[i] -1)
        t_crt = otherPrimeInfos[2]  # CRT additional factors of r (coefficients) t[i] = (r[1]*...*r[i-1])^(-1) % r[i]
        u = len(r_crt)              # number of rsa modulus prime factors

        dP = d % (p -1)         # CRT exponent d % (p -1)
        dQ = d % (q -1)         # CRT exponent d % (q -1)
        qInv = pow(q, -1) % p   # CRT coefficient q^(-1) % p

        if(not(0 <= criptogram <= n -1)):
            print("RSA encription failed. Ciphertext representative out of range. Exiting program...")
            exit()

        m = [0] * u
        m[0] = pow(criptogram, dP) % p
        m[1] = pow(criptogram, dQ) % q

        if(u > 2):
            for i in range(3, u):
                m[i-1] = pow(criptogram, d_crt[i-1]) % r_crt[i-1]

        h = (m[0] - m[1]) * qInv % p
        message = m[1] + q * h

        if(u > 2):
            R = r_crt[0]
            for i in range(3, u):
                R = R * r_crt[i-2]
                h = (m[i-1] - message) * t_crt[i-1] % r_crt[i-1]
                message = message + R * h

    return message

"""
RSA with OAEP encription of 'message' with 'publicKey'
"""
def rsaOaepEncript(publicKey, message: str):
    newMessage = oaepEncode(message, "UNBSC", publicKey[0])
    codNewMessage = os2ip(newMessage)
    criptogram = rsaEncript(publicKey, codNewMessage)
    modSize = (publicKey[0].bit_length()) // 8
    C = i2osp(criptogram, modSize +1) # adding 1 to modSize to avoid overflow on i2osp function byte representation
    return C

"""
RSA with OAEP decription of 'criptogram' with 'privateKey'
"""
def rsaOaepDecript(privateKey, criptogram):
    newCriptogram = os2ip(criptogram)
    message = rsaDecript(privateKey, newCriptogram)

    modSize = privateKey[0].bit_length() // 8
    newMessage = i2osp(message, modSize)
    return oaepDecode(newMessage, "UNBSC", privateKey[0])

#pub_key = (29457423241637220980347924559661426600330442718924500128814737384833494021469542192925758951000481180787649525298335261009556667315786472126840755031219737074114263029557179036233671809108562726727176933112533302091351789257873271090422752678095003853305477784703363696626279235375095763849967817501131834314404095905030643145399613593574935031389470728241480427876481972434698702029368489203497093386342630901302892814185946777301353303225959065110028384170683881655654870829746544188895059789439823961369742130356713924750620068023993356622391790854960925212096511149120130429337154855741372583581823073340447740693, 65537)
#prv_key = (29457423241637220980347924559661426600330442718924500128814737384833494021469542192925758951000481180787649525298335261009556667315786472126840755031219737074114263029557179036233671809108562726727176933112533302091351789257873271090422752678095003853305477784703363696626279235375095763849967817501131834314404095905030643145399613593574935031389470728241480427876481972434698702029368489203497093386342630901302892814185946777301353303225959065110028384170683881655654870829746544188895059789439823961369742130356713924750620068023993356622391790854960925212096511149120130429337154855741372583581823073340447740693,0,3888432007315006770236506025079436066946284693553501848030521585000756164910401902909817975877827222713794589977507336969859388268441777474850838026993636349362382920620400015906396307743689460135752439818064995291091815750947734382154313340833420485144966786936673929833741881154614240094390521220109121544332814215634078024064589124035532375779635954234851604015943318593081929425479375937455347421065367508876042792965294015668894889819788790595350850035510445966122766609502815391953725188143870994349063218443228311783390252899542134012359289069656378446632231161378092930285900244240641668791769616706750893253,0,0)

#msg = "borabill" * 10

# for oaep, mLen < modSize - 2*hLen -2
#keysize = len(msg.encode("utf-8")) + 2 + 2 * len(hsh.sha3_256().digest()) +2

#print(len(msg))
#print(keysize)

#pub_key, prv_key = GenRSAKey(keysize)
#store_keys(pub_key, './keys/pub')
#store_keys(prv_key, './keys/priv')
pub_key = import_keys('./keys/pub')
prv_key = import_keys('./keys/priv')

#c = rsaOaepEncript(pub_key, msg)
#print(c)
#m = rsaOaepDecript(prv_key, c)
#print(m)