import logging
import asyncio
import random
import hashlib
import sys
import json

from aiocoap import Context, Message, PUT, OptionNumber
from aiocoap.options import Options
from clientAuthentication import PRE_SHARED_KEY

from server import PRIVATE_KEY

from timeDifCalculator import isMessageFresh, getCurrrentTime

from AES_application import encryption, decryption, encryptionWithID

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
    rc = random.randint(10, 49)
    client_rand = rc * 2
    hashed = hashlib.sha1(str(client_id).encode()).hexdigest()
    print("hash value of Ci " + hashed)
    print("hash size in bytes {}".format(sys.getsizeof(hashed)))
    print("client rand {}".format(client_rand))
    t1 = getCurrrentTime()
    enc_str = hashlib.sha1(str(client_id).encode()).hexdigest() + str(client_rand) + str(t1)
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
        t2 = msg[4:].decode('utf-8')
        t3 = getCurrrentTime()
        print("T2 " + t2)
        print("T3 " + t3)
        if isMessageFresh(t2,t3):
            ret_client_rand = msg[0:2].decode('utf-8')
            print('retrieved client_rand ' + ret_client_rand)
            if(ret_client_rand == str(client_rand)):
                server_rand = msg[2:4].decode('utf-8')
                print('retrieved server_rand ' + server_rand)
                sessionKey = int(server_rand)*rc
                print("built session key {}".format(sessionKey))
                enc_str = server_rand + str(t3)
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
