import Pyro4, os, sys
from importlib import import_module
from django.conf import settings
import django.htoken as htoken

PYRO_NAME = "session"
PYRO_SOCK = "/tmp/sock_hachi_ssn"
PYRO_URI = "PYRO:%s@./u:%s" % (PYRO_NAME, PYRO_SOCK)

class SessionServer(object):
    def __init__(self):
        engine = import_module(settings.SESSION_ENGINE)
        self.manager = engine.SessionManager() 
    def get_session_dict(self, session_key, request_obj):
        if session_key == "None":
            session_key = None
        try:
            return (session_key,) + self.manager.load(session_key, request_obj)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print tb

            token_dict = {}
            token_dict.update([("req_%s" % k, v) for k,v in request_obj.iteritems()])
            session_key = None
            return None, {}, htoken.HachiToken(token_dict)
    def save_session(self, session_key, session_dict, token):
        if session_key == "None":
            session_key = None
        try:
            return self.manager.save(session_key, session_dict, token)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print tb
            return None

def start_session_daemon():
    daemon = False
    try:
        local = SessionServer()
        daemon = Pyro4.Daemon(unixsocket=PYRO_SOCK)
        daemon.register(local, PYRO_NAME)
        daemon.requestLoop()
    finally:
        if daemon:
            daemon.close()

def fork_session_daemon():
    pid = os.fork()
    if pid == 0:
        start_session_daemon()
        sys.exit(0)
    else:
        return pid

