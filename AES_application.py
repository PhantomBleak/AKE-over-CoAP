import base64
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
