import logging
import asyncio
import random
import hashlib
import sys
import json

from aiocoap import Context, Message, PUT, OptionNumber
from aiocoap.options import Options

from server import PRIVATE_KEY

from timeDifCalculator import isMessageFresh, getCurrrentTime

from AES_application import encryption, decryption, encryptionWithID, multiplyGeneratorByScalar, double, is_double, multiplyPointByScalar
from AES_application import plus_generator, is_plus_generator
from Crypto.PublicKey import ECC

logging.basicConfig(level=logging.INFO)
CLIENT_ID = 10 #28 bytes
PRIVATE_KEY = 1050
#PRE_SHARED_KEY = get_random_bytes(16)
PRE_SHARED_KEY = b'vm\xaa\xae\xf5\x0b\xe0V\xfd\xbf\xa4\xc3\xbb\x03\xf7J' #16 bytes

## I REACHED THIS CONCLUSION THAT I CANNOT MAKE ANY NEW OPTION MYSELF. I EITHER 
## HAVE TO USE THE EXISTING OPTIONS FOR LESS AUTH AND MAKE_AUTH HEADERS,
## OR FORGET ABOUT THESE FANCY HEADERS
async def handshake():
    context = await Context.create_client_context()
    client_id = CLIENT_ID
    rc = random.randint(1, 100)
    client_rand = multiplyGeneratorByScalar(rc)
    hashed = hashlib.sha1(str(client_id).encode()).hexdigest()
    print("hash value of Ci " + hashed)
    print("hash size in bytes {}".format(sys.getsizeof(hashed)))
    print("client rand x {}".format(client_rand[0]))
    print("client rand x size in bytes {}".format(sys.getsizeof(client_rand[0])))
    print("client rand y {}".format(client_rand[1]))
    print("client rand y size in bytes {}".format(sys.getsizeof(client_rand[1])))
    t1 = getCurrrentTime()
    enc_str = hashlib.sha1(str(client_id).encode()).hexdigest() + str(client_rand[0]) + ' ' + str(client_rand[1]) + ' ' + str(t1)
    print("message to be encrypted " + enc_str)
    enc_bytes = bytes(enc_str, encoding='utf-8')
    payload = encryptionWithID(enc_bytes, PRE_SHARED_KEY, str(client_id))
    print("size of encrypted first message {}".format(sys.getsizeof(payload)))
    request = Message(mtype=0,code=PUT, payload=payload,
                      uri='coap://127.0.0.1/ake')
    # opt = OptionNumber.create_option(OptionNumber.OBJECT_SECURITY, value=b'1')
    # request.opt.add_option(opt)
    # print(request.opt)
    try:
        response = await context.request(request).response
        server_response = response.payload.decode('utf-8')
        msg = decryption(server_response,PRE_SHARED_KEY)
        print(msg)
        resp_x, resp_y, server_rand_x, server_rand_y, t2 = msg.decode('utf-8').split(' ')
        t3 = getCurrrentTime()
        print("T2 " + t2)
        print("T3 " + t3)
        if isMessageFresh(t2,t3):
            print('retrieved client_rand_x ' + resp_x)
            print('retrieved client_rand_y ' + resp_y)
            if(is_plus_generator(client_rand[0], client_rand[1], resp_x, resp_y)):
                server_rand = (server_rand_x, server_rand_y)
                print('retrieved server_rand x ' + server_rand_x)
                print('retrieved server_rand y ' + server_rand_y)
                session_key = multiplyPointByScalar(rc, server_rand_x, server_rand_y)
                print('built session key x {}'.format(session_key[0]))
                print('built session key y {}'.format(session_key[1]))
                server_rand_plust = plus_generator(server_rand_x, server_rand_y)
                enc_str = str(server_rand_plust[0]) + ' ' + str(server_rand_plust[1]) + ' ' + str(t3)
                enc_bytes = bytes(enc_str, encoding='utf-8')
                payload = encryption(enc_bytes,PRE_SHARED_KEY)
                request = Message(mtype=1,code=PUT, payload=payload,
                                uri='coap://127.0.0.1/ake')
                # As you see, I have tried everything to create no-response option in the 
                # request, not in the response.
                # I tried that to keep the client from awaiting the response.
                # I am convinced that I have to set the no_response option in the response
                # The aiocoap code is really unclear and I had to read the code in their
                # repo as the no_response mechanism was added to the library and wasn't implemented
                # from the beginning.
                # option = OptionNumber.create_option(OptionNumber.NO_RESPONSE,value=1)
                # request.opt.add_option(option)
                # print(request.opt.no_response)
                # auth2.opt.add_option(option)
                future_response = context.request(request).response
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
