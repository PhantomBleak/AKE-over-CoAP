import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap
import random
from aiocoap.options import Options
from aiocoap import OptionNumber
import hashlib

import json
from base64 import b64encode, b64decode

from AES_application import encryption, decryption, encryptionWithID

from timeDifCalculator import isMessageFresh, getCurrrentTime



class BlockedIPDB():
    pass


class Session():
    def __init__(self, clientIp):
        self.serverRandom = ''
        self.serverChallenge = ''
        self.clientChallenge = ''
        self.client_ID = ''
        self.session_key = ''
        self.ip = clientIp


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
        return b'vm\xaa\xae\xf5\x0b\xe0V\xfd\xbf\xa4\xc3\xbb\x03\xf7J'  # to be replaced by a random key


class KeyExchangeResourceServerAuth(resource.Resource):

    def __init__(self, sessionDB, preSharedDB):
        super().__init__()
        # self.set_up_database_of_client_IDS()
        self.sessionDB = sessionDB
        self.preSharedDB = preSharedDB

    async def render_put(self, request):
        # await updateNumberOfAttempts(request.remote.hostinfo)
        # if isHostBlocked(request.remote.hostinfo):
        # block mechanism: (maybe i need to go to lower layers)
        clientIp = request.remote.hostinfo.split(':')[0]
        if not self.sessionDB.is_session_live(clientIp):
            self.sessionDB.add_live_session(clientIp)
            messages = request.payload.decode('utf-8')
            message = json.loads(messages)
            client_ID = int(b64decode(message['id']))
            msg = decryption(messages,self.preSharedDB.get_client_key(client_ID))
            print("retrieved client ID {}".format(client_ID))
            print("retrieved decrypted message " + str(msg))
            hci = msg[0:40].decode('utf-8')
            hashed = hashlib.sha1(str(client_ID).encode()).hexdigest()
            print("retrieved hash value of client " + hci)
            print("calculated hash value of client " + hashed)
            client_rand = msg[40:42].decode('utf-8')
            print("retrieved client rand " + client_rand)
            t1 = msg[42:].decode('utf-8')
            t2 = getCurrrentTime()
            print("T1 " + t1)
            print("T2 " + t2)
            isFresh = isMessageFresh(t1,t2)
            if isFresh and hci == hashed:
                self.sessionDB.add_client_challenge(clientIp, str(client_rand))
                self.sessionDB.add_client_ID(clientIp, client_ID)
                rs = random.randint(10, 49)
                print("chosen random number {}".format(rs))
                self.sessionDB.add_server_random(clientIp, str(rs))
                server_rand = rs * 2
                self.sessionDB.add_server_challenge(clientIp, str(server_rand))
                print("chosen challenge {}".format(server_rand))
                enc_str = client_rand + str(server_rand) + str(t2)
                print("second message to be encrypted " + enc_str)
                enc_bytes = bytes(enc_str, encoding='utf-8')
                payload = encryption(enc_bytes, self.preSharedDB.get_client_key(client_ID))
                return aiocoap.Message(payload=payload)
        else:
            req = request.payload.decode('utf-8')
            client_ID = self.sessionDB.get_client_ID(clientIp)
            req = decryption(req,self.preSharedDB.get_client_key(client_ID))
            t3 = req[2:].decode('utf-8')
            t4 = getCurrrentTime()
            print("T3 " + t3)
            print("T4 " + t4)
            if isMessageFresh(t3,t4):
                server_rand = self.sessionDB.get_server_challenge(clientIp)
                client_response = req[:2].decode('utf-8')
                if client_response == server_rand:
                    rs = self.sessionDB.get_server_random(clientIp)
                    client_rand = self.sessionDB.get_client_challenge(clientIp)
                    session_key = int(rs) * int(client_rand)
                    print("built session key {}".format(session_key))
                    self.sessionDB.add_session_key(clientIp, session_key)
            # client_response = request.payload.decode('utf-8').split(' ')
            # server_rand_i = client_response[0]
            # # Rc = client_response[1]
            # server_rand = self.sessionDB.get_server_challenge(clientIp)
            # if(server_rand == str(server_rand_i)):
            #     # sessionKey = PRIVATE_KEY * int(Rc)
            #     sessionKey = int(server_rand) * int(self.sessionDB.
            #         get_client_challenge(clientIp))
            #     #print(sessionKey)
            #     self.sessionDB.remove_live_session(clientIp)
            # return aiocoap.Message()
        # #add session to database
        # elif self.step == '2':
        #     print("I'm over here now!")
        #     #if isSessionCreated()
        #     print("I got the third message")
            # I could not add no_respnse option here in a clean way
            # (by adding a No_RESPONSE option)
                resp = aiocoap.Message(no_response=26)
                return resp


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
