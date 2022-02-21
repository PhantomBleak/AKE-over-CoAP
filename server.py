import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap


class SessionDB():
    def __init__(self):
        self.liveSessions = []

    def add_live_session(self, session):
        self.liveSessions.append(session)

    def remove_live_session(self, session):
        self.liveSessions.remove(session)

    def is_session_live(self, session):
        return session in self.liveSessions

    def get_session_len(self):
        return len(self.liveSessions)


class KeyExchangeResourceServerAuth(resource.Resource):

    def __init__(self, sessionDB):
        super().__init__()
        # self.set_up_database_of_client_IDS()
        self.sessionDB = sessionDB

    async def render_put(self, request):
        # await updateNumberOfAttempts(request.remote.hostinfo)
        # if isHostBlocked(request.remote.hostinfo):
        # block mechanism: (maybe i need to go to lower layers)
        if not self.sessionDB.is_session_live(
                request.remote.hostinfo.split(':')):
            self.sessionDB.add_live_session(request.remote.hostinfo.split(':'))
            return aiocoap.Message(payload=b"I got the second message")
        else:
            print("I got the third message")
            return aiocoap.Message()
        # #add session to database
        # elif self.step == '2':
        #     print("I'm over here now!")
        #     #if isSessionCreated()
        #     print("I got the third message")
        #     return aiocoap.Message.NoResponse


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
    root.add_resource(['.well-known', 'core'],
                      resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['time'], TimeResource()),
    root.add_resource(['ake'], KeyExchangeResourceServerAuth(sessionDB))

    await aiocoap.Context.create_server_context(
                         bind=('127.0.0.1', 5683), site=root)

    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
