"""
RSA OAEP encription system for classroom purposes

Author: Gabriel Tambara Rabelo
Matricula: 18/0017021
Curso: Engenharia Mecatrônica
University of Brasília, UnB
Segurança Computacional - 2022/2
"""

from sign import *
import argparse

parser = argparse.ArgumentParser(description='RSA Encription and signing with OAEP as per PKCS#1')

parser.add_argument('--keysize','-key', type=int, default = 2048,
                    help='initial size of rsa modulus n')
parser.add_argument('--prv_key_path', '-prv', metavar='prv_key_path', default = './keys/priv', action='store_const',
                    help='Path for private key to be used')
parser.add_argument('--pub_key_path', '-pub', default = './keys/pub', action='store_const',
                    help='Path for public key to be used')
parser.add_argument('--encript_path','-enc', default = './keys/input', action='store_const',
                    help='Path to message to be encripted')
parser.add_argument('--store_path', '-str',default = './keys/secret', action='store_const',
                    help='Path to signed message to be stored')
parser.add_argument('--decript_path', '-dec',default = './keys/secret', action='store_const',
                    help='Path to message to be decripted')
parser.add_argument('--output_path', '-out',default = './keys/output', action='store_const',
                    help='Path to save the decripted message')
parser.add_argument('--key_setup', '-set',default = '1', action='store_const', help='1 for key generating and 0 for key importing')
parser.add_argument('--operation','-op', choices=['1','2','3','4','5'], help='1 for full test\n2 for encription\n3 for decription\n4 for signing\n5 for verifying signature')

args = parser.parse_args()

if(args.operation == '1'):

    msg = importData(args.encript_path)

    if(args.key_setup == '1'):
        pub_key, prv_key = GenRSAKey(args.keysize)
    else:
        pub_key = import_keys(args.pub_key_path)
        prv_key = import_keys(args.prv_key_path)

    c = rsaOaepEncript(pub_key, msg)
    signature = sign(msg, prv_key)
    exportSignedData(c, signature, args.store_path)

    newC, newSignature = importSignedData(args.decript_path)
    newMsg = rsaOaepDecript(prv_key, newC)
    exportData(newMsg.decode("UTF-8"), args.output_path)
    print("Is the signature valid? : " + str(verify(newMsg, newSignature, pub_key)))
if(args.operation == '2'):
    if(args.key_setup == '1'):
        keysize = args.keysize
        pub_key, prv_key = GenRSAKey(keysize)
    else:
        pub_key = import_keys(args.pub_key_path)
        prv_key = import_keys(args.prv_key_path)
    msg = importData(args.encript_path)
    c = rsaOaepEncript(pub_key, msg)
    exportData(c.decode("UTF-8"), args.store_path) 
if(args.operation == '3'):
    if(args.key_setup == '1'):
        keysize = args.keysize
        pub_key, prv_key = GenRSAKey(keysize)
    else:
        pub_key = import_keys(args.pub_key_path)
        prv_key = import_keys(args.prv_key_path)
    cript = importData(args.decript_path)
    newMsg = rsaOaepDecript(prv_key, cript)
    exportData(newMsg.decode("UTF-8"), args.store_path)
if(args.operation == '4'):
    if(args.key_setup == '1'):
        keysize = args.keysize
        pub_key, prv_key = GenRSAKey(keysize)
    else:
        pub_key = import_keys(args.pub_key_path)
        prv_key = import_keys(args.prv_key_path)
    msg = importData(args.encript_path)
    signature = sign(msg, prv_key)
    c = rsaOaepEncript(pub_key, msg)
    exportSignedData(c, signature, args.store_path)
if(args.operation == '5'):
    if(args.key_setup == '1'):
        keysize = args.keysize
        pub_key, prv_key = GenRSAKey(keysize)
    else:
        pub_key = import_keys(args.pub_key_path)
        prv_key = import_keys(args.prv_key_path)
    newC, newSignature = importSignedData(args.decript_path)
    newMsg = rsaOaepDecript(prv_key, newC)
    exportData(newMsg.decode("UTF-8"), args.output_path)
    print("Is the signature valid? : " + str(verify(newMsg, newSignature, pub_key)))   
