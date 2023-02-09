from rsa import *
from key import *
from oaep import sha256

def importData(path: str):
    with open(path, "r") as f:
        data = f.read()
        f.close()

    return str(data)

def importSignedData(path):
    with open(path, "r") as f:
        data = [line.rstrip() for line in f]
        f.close()

    signature = data[1].encode("utf-8")
    criptogram = b64.b64decode(data[0].encode("utf-8"))

    return criptogram, signature

def exportSignedData(data: bytes, signature: bytes, path: str):
    with open(path, "wb+") as f:
        out = b64.b64encode(data) # encripted data from 'rsaOaepEncript'
        f.write(out)
        f.write(b'\n')
        f.write(signature)  # signature from 'sign'
        f.close()

def exportData(data: str, path: str):
    with open(path, "w+") as f:
        f.write(data)
        f.close()

def sign(message: str, privateKey):
    bmessage = message.encode("utf-8")
    hash = os2ip(sha256(bmessage))
    signature = pow(hash, privateKey[2], privateKey[0])

    return b64.b64encode(str(signature).encode("utf-8"))

def verify(message, signature, publicKey):
    bmessage = message.decode("UTF-8")
    bsignature = int(b64.b64decode(signature).decode("UTF-8"))
    hash = os2ip(sha256(message))
    receivedHash = pow(bsignature, publicKey[1], publicKey[0])

    if hash == receivedHash:
        return True
    
    return False

#msg = importDataToEncript('./keys/input')
#keysize = 1024
#pub_key = import_keys('./keys/pub')
#prv_key = import_keys('./keys/priv')

#c = rsaOaepEncript(pub_key, msg)
#signature = sign(msg, prv_key)
#exportSignedData(c, signature, './keys/output')

#newC, newSignature = importSignedData('./keys/output')
#newMsg = rsaOaepDecript(prv_key, newC)
#print(newMsg)
#print(verify(newMsg, newSignature, pub_key))
