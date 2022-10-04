import logging
import asyncio
import random
import hashlib
import sys
import json

from aiocoap import Context, Message, PUT, OptionNumber
from aiocoap.options import Options


from timeDifCalculator import isMessageFresh, getCurrrentTime

from AES_application import encryption, decryption, encryptionWithID, multiplyGeneratorByScalar, double, is_double, multiplyPointByScalar
from AES_application import plus_P, plus_2P, verifyChallenge
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import time

logging.basicConfig(level=logging.INFO)
CLIENT_ID = 10 #28 bytes
PRE_SHARED_KEY = b'vm\xaa\xae\xf5\x0b\xe0V\xfd\xbf\xa4\xc3\xbb\x03\xf7J' #16 bytes
startTime = None
finishTime = None

async def handshake():
    global PRE_SHARED_KEY, startTime, finishTime
    context = await Context.create_client_context()
    curr_time = round(time.time()*1000)
    startTime = curr_time
    client_id = CLIENT_ID
    rc = random.randint(1, 100)
    client_rand = multiplyGeneratorByScalar(rc)
    t1 = getCurrrentTime()
    enc_str = hashlib.sha1(str(client_id).encode()).hexdigest() + str(client_rand[0]) + ' ' + str(client_rand[1]) + ' ' + str(t1)
    enc_bytes = bytes(enc_str, encoding='utf-8')
    payload = encryptionWithID(enc_bytes, PRE_SHARED_KEY, str(client_id))
    print("size of encrypted first message {}".format(sys.getsizeof(payload)))
    request = Message(mtype=0,code=PUT, payload=payload,
                      uri='coap://127.0.0.1/ake')
    try:
        response = await context.request(request).response
        server_response = response.payload.decode('utf-8')
        msg = decryption(server_response,PRE_SHARED_KEY)
        resp_x, resp_y, server_rand_x, server_rand_y, t2 = msg.decode('utf-8').split(' ')
        t3 = getCurrrentTime()
        if isMessageFresh(t2,t3):
            challengeResponse = verifyChallenge(client_rand[0],client_rand[1], resp_x, resp_y)
            if challengeResponse != -1:
                secret = multiplyPointByScalar(rc, server_rand_x, server_rand_y)
                sessionKey = PBKDF2(bytes(str(secret[0]),encoding='utf-8'),'', 16, count=16, hmac_hash_module=SHA512)
                print('built session key {}'.format(sessionKey))
                if challengeResponse == 2:
                    Y =PBKDF2(bytes(str(secret[1]),encoding='utf-8'),'', 16, count=16, hmac_hash_module=SHA512)
                    server_rand_plust = plus_2P(server_rand_x, server_rand_y)
                    print('new long-term key {}'.format(Y))
                else:
                    server_rand_plust = plus_P(server_rand_x, server_rand_y)
                enc_str = str(server_rand_plust[0]) + ' ' + str(server_rand_plust[1]) + ' ' + str(t3)
                enc_bytes = bytes(enc_str, encoding='utf-8')
                payload = encryption(enc_bytes,PRE_SHARED_KEY)
                print("size of encrypted third message {}".format(sys.getsizeof(payload)))
                request = Message(mtype=1,code=PUT, payload=payload,
                                uri='coap://127.0.0.1/ake')
                curr_time = round(time.time()*1000)
                future_response = context.request(request).response
                finishTime = curr_time
                print('elapsed time in mili-seconds: {}'.format(finishTime - startTime))
                try:
                    response = await asyncio.wait_for(future_response, timeout=1) 
                    print('Result: %s\n%r'%(response.code, response.payload))
                except asyncio.TimeoutError:

                    return

    except Exception as e:
        print(e)
    else:
        print('Result: %s\n%r' % (response.code, response.payload))

if __name__ == '__main__':
    asyncio.get_event_loop().\
                    run_until_complete(handshake())
