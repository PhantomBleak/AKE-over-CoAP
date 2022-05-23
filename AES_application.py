import base64
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC

def generatorPoint():
    p = ECC.EccPoint(72322606651807384847403831375643175681500117958841208463667062180171793088469,
    8856254923922720309771422189140314456949507932337029017781130762969692952443,
    curve='p256')
    return p

p = ECC.EccPoint(72322606651807384847403831375643175681500117958841208463667062180171793088469,
    8856254923922720309771422189140314456949507932337029017781130762969692952443,
    curve='p256')

def multiplyGeneratorByScalar(s):
    mul = s*p
    return (mul.x, mul.y)

def multiplyPointByScalar(s, x, y):
    point = ECC.EccPoint(int(x),int(y))
    point = int(s)*point
    return (point.x,point.y)

def double(x,y):
    d = 2*ECC.EccPoint(int(x),int(y))
    return (d.x,d.y)

def is_double(x,y, xprime, yprime):
    p1 = ECC.EccPoint(x,y)
    p2 = ECC.EccPoint(int(xprime),int(yprime))
    return 2*p1 == p2

def encryption(data, key):
    #encryption
    header = b""
    cipher = AES.new(key, AES.MODE_CCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag]]
    result = json.dumps(dict(zip(json_k, json_v)))
    return bytes(result, encoding='utf-8')

def encryptionWithID(data, key, ID):
    #encryption
    header = b""
    cipher = AES.new(key, AES.MODE_CCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = ['id', 'nonce', 'header', 'ciphertext', 'tag' ]
    id = bytes(ID, encoding='utf-8')
    json_v = [ b64encode(x).decode('utf-8') for x in [id, cipher.nonce, header, ciphertext, tag]]
    result = json.dumps(dict(zip(json_k, json_v)))
    return bytes(result, encoding='utf-8')

def decryption(result, key):
    #decryption
    try:
        b64 = json.loads(result)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_CCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'],jv['tag'])
        return plaintext

    except(ValueError, KeyError):
        print("Invalid decryption")
generatorPoint()