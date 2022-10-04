import base64
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC

p = ECC.EccPoint(117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495,
    19,
    curve='ed448')

def multiplyGeneratorByScalar(s):
    mul = s*p
    return (mul.x, mul.y)

def multiplyPointByScalar(s, x, y):
    point = ECC.EccPoint(int(x),int(y),curve='ed448')
    point = int(s)*point
    return (point.x,point.y)

def double(x,y):
    d = 2*ECC.EccPoint(int(x),int(y),curve='ed448')
    return (d.x,d.y)

def is_double(x,y, xprime, yprime):
    p1 = ECC.EccPoint(x,y,curve='ed448')
    p2 = ECC.EccPoint(int(xprime),int(yprime),curve='ed448')
    return 2*p1 == p2

def plus_P(x,y):
    r = p + ECC.EccPoint(int(x),int(y),curve='ed448')
    return (r.x, r.y)

def plus_2P(x,y):
    r = p + ECC.EccPoint(int(x),int(y),curve='ed448')
    r = p + r
    return (r.x, r.y)

def verifyChallenge(x,y, xprime, yprime):
    p1 = ECC.EccPoint(x,y,curve='ed448')
    p2 = ECC.EccPoint(int(xprime),int(yprime),curve='ed448')
    if p + p1 == p2:
        return 1
    if p + p + p1 == p2:
        return 2
    return -1

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
