import string as str
import math as mth
import hashlib as hsh
import random as rnd
from octetCoverting import i2osp

"""
Applies 'mask' into 'data' with bitwise xor operation

def sxor(data: bytes, mask: bytes) -> bytes:
    output = b""
    for data, mask in zip(data, mask):
        output += bytes([data ^ mask])
    return output
"""

def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked

"""
Creates a hash with SHA3_256 algorithm from 'message'
"""
def sha256(message: bytes) -> bytes:
    return hsh.sha3_256(message).digest()

"""
Mask generating function based on PKCS#1 with SHA3_256 as the hash function of size 'length' with 'seed'
"""
def mgf1(seed: bytes, length: int) -> bytes:
    mask = b""
    hLen = hsh.sha3_256().digest_size

    if(length > pow(2, hLen)):
        print("Mask too long for oaep encoding. Exiting program...")
        exit()       

    for counter in range(0, mth.ceil(length / hLen)):
        byteCounter = i2osp(counter, 4)
        mask += hsh.sha3_256(seed + byteCounter).digest()
    return mask[:length]

"""
OAEP padding scheme encode based on RFC 8017 section 7.1.1
"""
def oaepEncode(message, label, modulus: int) -> bytes:
    print("ENCODING MESSAGE WITH OAEP...")
    mLen = len(message.encode("UTF-8"))
    hLabel = sha256(bytes(label, "UTF-8"))
    hLen = len(hLabel)
    modSize = modulus.bit_length() // 8

    if(mLen > modSize - 2*hLen -2):
        print("Message length too big for oaep encoding. Exiting program...")
        exit()

    paddingString = b"\x00" * (modSize - mLen - 2*hLen - 2)
    dataBlock = hLabel + paddingString + b"\x01" + message.encode("UTF-8")
    seed = "".join(rnd.choices(str.ascii_letters, k=hLen)).encode("UTF-8")
    mask = mgf1(seed, modSize -hLen -1)
    maskedDB = xor(dataBlock, mask)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = xor(seed, seedMask)
    encriptedMessage = b"\x00" + maskedSeed + maskedDB

    return encriptedMessage

"""
OAEP padding scheme decode based on RFC 8017 section 7.1.1
Errors in this function are not to give any information to avoid possible sucessful attacks
"""
def oaepDecode(message: bytes, label, modulus: int) -> bytes:
    print("DECODING MESSAGE WITH OAEP...")
    hLabel = sha256(bytes(label, "UTF-8"))
    hLen = len(hLabel)
    modSize = modulus.bit_length() // 8

    if(modSize < 2*hLen + 2):
        print("Decription error. Exiting program...")
        exit()

    if(len(message) != modSize):
        print("Decription error. Exiting program...")
        exit()

    buff = bytearray()
    buff.append(message[0])
    if(buff != b"\x00"):
        print("Decription error. Exiting program...")
        exit()

    maskedSeed = message[1:hLen+1]
    maskedDB = message[hLen+1:]
    seedMask = mgf1(maskedDB, hLen)
    seed = xor(maskedSeed, seedMask)
    mask = mgf1(seed, modSize - hLen -1)
    dataBlock = xor(maskedDB, mask)
    hLabelNew = dataBlock[:hLen]

    if(hLabel != hLabelNew):
        print("Decription error. Exiting program...")
        exit()

    newBlock = dataBlock[hLen:]
    count = 0

    for i in newBlock:
        buff = bytearray()
        buff.append(i)
        if buff == b"\x00":
            count = count + 1
        else:
            if buff == b"\x01":
                break
            else:
                print("Decription error. Exiting program...")
                exit()

    return newBlock[count+1:]

#lol = 72153539777587845103859381066006852762962962387435662821441938884912206671456126962113971261813914781559392025692166551814336386193848850548040130331506731175349656559485194768791649042139948748349801071236130253493643874818035571955711200751926667139833943356777236786788648538319432778611435694099700476006256638661488525619978424189507946593677788546241375514275915035
#result = oaepEncode("heybabe", "label", lol)
#print(result)
#resultoff = oaepDecode(result, "label", lol)
#print(resultoff.decode("UTF-8"))