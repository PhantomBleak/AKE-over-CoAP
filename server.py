import datetime
import logging

import asyncio
from tabnanny import verbose

import aiocoap.resource as resource
import aiocoap
import random
from aiocoap.options import Options
from aiocoap import OptionNumber
import hashlib, sys

import json
from base64 import b64encode, b64decode

from AES_application import encryption, decryption, multiplyGeneratorByScalar, double, is_double, multiplyPointByScalar
from AES_application import verifyChallenge , plus_P, plus_2P

from timeDifCalculator import isMessageFresh, getCurrrentTime

import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

class Session():
    def __init__(self, clientIp):
        self.serverRandom = ''
        self.serverChallenge = ''
        self.clientChallenge = ''
        self.client_ID = ''
        self.session_key = ''
        self.ip = clientIp
        self.shouldUpdateY = True

class SessionDB():
    def __init__(self):
        self.liveSessions = []

    def add_live_session(self, ip):
        session = Session(ip)
        self.liveSessions.append(session)

    def remove_live_session(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                self.liveSessions.remove(session)

    def is_session_live(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return True
        return False

    def add_server_random(self, ip, rs):
        for session in self.liveSessions:
            if session.ip == ip:
                session.serverRandom = rs

    def add_client_challenge(self, ip, client_rand):
        for session in self.liveSessions:
            if session.ip == ip:
                session.clientChallenge = client_rand

    def add_client_ID(self, ip, client_ID):
        for session in self.liveSessions:
            if session.ip == ip:
                session.client_ID = client_ID 

    def get_client_ID(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.client_ID

    def get_long_key_status(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.shouldUpdateY

    def get_server_random(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.serverRandom

    def get_client_challenge(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.clientChallenge

    def get_session_len(self):
        return len(self.liveSessions)
    
    def add_session_key(self, ip, session_key):
        for session in self.liveSessions:
            if session.ip == ip:
                session.session_key = session_key

    def get_session_key(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.session_key

    def add_server_challenge(self, ip, server_rand):
        for session in self.liveSessions:
            if session.ip == ip:
                session.serverChallenge = server_rand
    
    def get_server_challenge(self, ip):
        for session in self.liveSessions:
            if session.ip == ip:
                return session.serverChallenge

class PresharedDB():
    def __init__(self):
        self.keys = {}

    def get_client_key(self, clientID):
        return b'vm\xaa\xae\xf5\x0b\xe0V\xfd\xbf\xa4\xc3\xbb\x03\xf7J'
    
    def set_client_key(self, clientID, key):
        pass

startTime = None
finishTime = None
class KeyExchangeResourceServerAuth(resource.Resource):

    def __init__(self, sessionDB, preSharedDB):
        super().__init__()
        self.sessionDB = sessionDB
        self.preSharedDB = preSharedDB

    async def render_put(self, request):
        global startTime, finishTime
        clientIp = request.remote.hostinfo.split(':')[0]
        if not self.sessionDB.is_session_live(clientIp):
            curr_time = round(time.time()*1000)
            startTime = curr_time
            self.sessionDB.add_live_session(clientIp)
            messages = request.payload.decode('utf-8')
            message = json.loads(messages)
            client_ID = int(b64decode(message['id']))
            msg = decryption(messages,self.preSharedDB.get_client_key(client_ID))
            hci = msg[0:40].decode('utf-8')
            hashed = hashlib.sha1(str(client_ID).encode()).hexdigest()
            client_rand_x, client_rand_y, t1 = (msg[40:].decode('utf-8')).split(' ')
            client_rand = (client_rand_x, client_rand_y)
            t2 = getCurrrentTime()
            isFresh = isMessageFresh(t1,t2)
            if isFresh and hci == hashed:
                self.sessionDB.add_client_challenge(clientIp, client_rand)
                self.sessionDB.add_client_ID(clientIp, client_ID)
                rs = random.randint(1, 100)
                self.sessionDB.add_server_random(clientIp, str(rs))
                server_rand = multiplyGeneratorByScalar(rs)
                self.sessionDB.add_server_challenge(clientIp, server_rand)
                if self.sessionDB.get_long_key_status(clientIp):
                    client_rand_plus = plus_2P(client_rand[0],client_rand[1])
                else:
                    client_rand_plus = plus_P(client_rand[0],client_rand[1])
                enc_str = str(client_rand_plus[0]) + ' ' + str(client_rand_plus[1]) + ' ' + str(server_rand[0]) + ' ' + str(server_rand[1]) + ' ' + str(t2)
                enc_bytes = bytes(enc_str, encoding='utf-8')
                payload = encryption(enc_bytes, self.preSharedDB.get_client_key(client_ID))
                print("size of encrypted second message {}".format(sys.getsizeof(payload)))
                return aiocoap.Message(payload=payload)
        else:
            req = request.payload.decode('utf-8')
            client_ID = self.sessionDB.get_client_ID(clientIp)
            req = decryption(req,self.preSharedDB.get_client_key(client_ID))
            resp_x, resp_y, t3 = req.decode('utf-8').split(' ')
            t4 = getCurrrentTime()
            if isMessageFresh(t3,t4):
                server_rand = self.sessionDB.get_server_challenge(clientIp)
                challengeResponse = verifyChallenge(server_rand[0],server_rand[1], resp_x, resp_y)
                if challengeResponse != -1:
                    rs = self.sessionDB.get_server_random(clientIp)
                    client_rand = self.sessionDB.get_client_challenge(clientIp)
                    secret = multiplyPointByScalar(rs, client_rand[0], client_rand[1])
                    sessionKey = PBKDF2(bytes(str(secret[0]), encoding='utf-8'),'', 16, count=16, hmac_hash_module=SHA512)
                    print('built session key {}'.format(sessionKey))
                    if challengeResponse == 2:
                        Y = PBKDF2(bytes(str(secret[1]),encoding='utf-8'),'', 16, count=16, hmac_hash_module=SHA512)
                        self.preSharedDB.set_client_key(client_ID, Y)
                        print('new long-term key {}'.format(Y))
                    curr_time = round(time.time()*1000)
                    finishTime = curr_time
                    print('elapsed time in mili-seconds: {}'.format(finishTime - startTime))
                    self.sessionDB.add_session_key(clientIp, sessionKey)
                    self.sessionDB.remove_live_session(clientIp)
                return aiocoap.Message(no_response=26)


class BlockResource(resource.Resource):

    def __init__(self):
        super.__init___()
        self.set_content(b"This is the resrouce's default content."
                         b" It is padded with numbers to form a block.\n")

    def set_content(self, content):
        self.content = content
        while len(self.content) <= 1024:
            self.content = self.content + b"0123456789\n"

    async def render_get(self, request):
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        print('PUT payload: %s' % request.payload)
        self.set_conent(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)


class SeperateLargeResource(resource.Resource):
    def get_link_description(self):
        return dict(**super().get_link_description(),
                    titlte="A large resource")

    async def render_get(self, request):
        await asyncio.sleep(3)

        payload = "Three rings for the elevel kings under the sky,"\
                  " seven rings for dwarven etc etc etc etc.".encode('ascii')
        return aiocoap.Message(payload=payload)


class TimeResource(resource.ObservableResource):

    def __init__(self):
        super().__init__()

        self.handle = None

    def notify(self):
        self.updated_state()
        self.reschedule()

    def reschedule(self):
        self.handle = asyncio.get_event_loop().call_later(5, self.notify)

    def update_observation_count(self, count):
        if count and self.handle is None:
            print("starting the clock")
            self.reschedule()
        if count == 0 and self.handle:
            print("stopping the clcok")
            self.handle.cancel()
            self.handle = None

    async def render_get(self, request):
        payload = datetime.datetime.now().\
                strftime("%Y-%m-%d %H:%M").encode('ascii')
        return aiocoap.Message(payload=payload)


class WhoAmI(resource.Resource):
    async def render_get(self, request):
        text = ["Used protocol: %s." % request.remote.scheme]
        text.append("Request came from %s." % request.remote.hostinfo)
        text.append("The server address used %s." %
                    request.remote.hostinfo_local)

        claims = list(request.remote.authenticated_claims)
        if claims:
            text.append("Authenticated claims of the client: %s." % ", "
                        .join(repr(c) for c in claims))
        else:
            text.append("No claims authenticated.")

        return aiocoap.Message(content_format=0, payload="\n".
                               join(text).encode('utf8'))


logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)


async def main():
    root = resource.Site()
    sessionDB = SessionDB()
    presharedDB = PresharedDB()
    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['time'], TimeResource()),
    root.add_resource(['ake'], KeyExchangeResourceServerAuth(
        sessionDB, presharedDB))

    await aiocoap.Context.create_server_context(
                         bind=('127.0.0.1', 5683), site=root)

    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
