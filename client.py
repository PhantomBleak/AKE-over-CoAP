import logging
import asyncio
import random

from aiocoap import Context, Message, PUT, OptionNumber
from aiocoap.options import Options

from server import PRIVATE_KEY

logging.basicConfig(level=logging.INFO)
CLIENT_ID = 10
PRIVATE_KEY = 1050
PRE_SHARED_KEY = 7 * CLIENT_ID

## I REACHED THIS CONCLUSION THAT I CANNOT MAKE ANY NEW OPTION MYSELF. I EITHER 
## HAVE TO USE THE EXISTING OPTIONS FOR LESS AUTH AND MAKE_AUTH HEADERS,
## OR FORGET ABOUT THESE FANCY HEADERS
async def handshake():
    context = await Context.create_client_context()
    client_id = CLIENT_ID
    client_rand = random.randint(0, 100)
    payload_str = "HELLO" + " " + str(client_id) + " " + str(client_rand)
    payload = bytes(payload_str, encoding='utf-8')
    request = Message(code=PUT, payload=payload,
                      uri='coap://127.0.0.1/ake')

    # opt = OptionNumber.create_option(OptionNumber.OBJECT_SECURITY, value=b'1')
    # request.opt.add_option(opt)
    # print(request.opt)
    try:
        response = await context.request(request).response
        server_response = response.payload.decode('utf-8').split(' ')
        client_rand_i = server_response[0]
        if(client_rand_i == str(client_rand)):
            server_rand = server_response[1]
            Rs = server_response[2]
            Rc = PRIVATE_KEY * PRE_SHARED_KEY
            sessionKey = PRIVATE_KEY * int(Rs)
            print(sessionKey)
            payload_str = server_rand + ' ' + str(Rc)
            payload = bytes(payload_str, encoding='utf-8')
            auth2 = Message(code=PUT, payload=payload,
                            uri='coap://127.0.0.1/ake')
            option = OptionNumber.create_option(OptionNumber.NO_RESPONSE)
            auth2.opt.add_option(option)
            await context.request(auth2).response
    except Exception as e:
        print(e)
    else:
        print('Result: %s\n%r' % (response.code, response.payload))

if __name__ == '__main__':
    asyncio.get_event_loop().\
                    run_until_complete(handshake())
