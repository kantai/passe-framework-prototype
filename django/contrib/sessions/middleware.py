import time

from django.conf import settings
from django.utils.cache import patch_vary_headers
from django.utils.http import cookie_date
from django.contrib.sessions import Session
from django.contrib.sessions.server import PYRO_URI, SessionServer
from django.analysis.tracer import is_analysis_running
import django.htoken as htoken

import Pyro4

def SessionMiddleware():
    global instance
    return instance

class InnerSessionMiddleware(object):
    def __init__(self):
#        if is_analysis_running():
        self.proxy_object = SessionServer()
#        else:
#            self.proxy_object = Pyro4.Proxy(PYRO_URI)

    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
        new_key, session_dict, token = self.proxy_object.get_session_dict(session_key, request.REQUEST)
        request.session = Session(new_key, session_dict)
        if new_key != session_key:
            request.session.modified = True
        request.token = token
#        htoken.set_token(token)

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
        except AttributeError:
            pass
        else:
            if accessed:
                patch_vary_headers(response, ('Cookie',))
            if modified or settings.SESSION_SAVE_EVERY_REQUEST:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = cookie_date(expires_time)
                # Save the session data and refresh the client cookie.
                updated_key = self.proxy_object.save_session(request.session.session_key, 
                                                             request.session.get_session(),
                                                             request.token)
                response.set_cookie(settings.SESSION_COOKIE_NAME,
                                    updated_key, max_age=max_age,
                                    expires=expires, domain=settings.SESSION_COOKIE_DOMAIN,
                                    path=settings.SESSION_COOKIE_PATH,
                                    secure=settings.SESSION_COOKIE_SECURE or None,
                                    httponly=settings.SESSION_COOKIE_HTTPONLY or None)
        return response

instance = InnerSessionMiddleware()
