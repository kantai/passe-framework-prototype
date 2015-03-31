import base64
import os
import random
import sys
import time
from datetime import datetime, timedelta
try:
    import cPickle as pickle
except ImportError:
    import pickle

from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.utils.hashcompat import md5_constructor
from django.utils.crypto import constant_time_compare, salted_hmac

# Use the system (hardware-based) random number generator if it exists.
if hasattr(random, 'SystemRandom'):
    randrange = random.SystemRandom().randrange
else:
    randrange = random.randrange
MAX_SESSION_KEY = 18446744073709551616L     # 2 << 63

class CreateError(Exception):
    """
    Used internally as a consistent exception type to catch from save (see the
    docstring for SessionBase.save() for details).
    """
    pass


# Hachi Sessions are simply dictionary type objects?

class SessionManagerBase(object):
    """
    Base class for handling the session management operations
    like saving / restoring.
    """
    def get_new_session_key(self):
        "Returns session key that isn't being used."
        # The random module is seeded when this Apache child is created.
        # Use settings.SECRET_KEY as added salt.
        try:
            pid = os.getpid()
        except AttributeError:
            # No getpid() in Jython, for example
            pid = 1
        while 1:
            session_key = md5_constructor("%s%s%s%s"
                    % (randrange(0, MAX_SESSION_KEY), pid, time.time(),
                       settings.SECRET_KEY)).hexdigest()
            if not self.exists(session_key):
                break
        return session_key

    def _hash(self, value):
        key_salt = "django.contrib.sessions" + self.__class__.__name__
        return salted_hmac(key_salt, value).hexdigest()

    def encode(self, session_dict):
        "Returns the given session dictionary pickled and encoded as a string."
        pickled = pickle.dumps(session_dict, pickle.HIGHEST_PROTOCOL)
        hash = self._hash(pickled)
        return base64.encodestring(hash + ":" + pickled)

    def decode(self, session_data):
        encoded_data = base64.decodestring(session_data)
        try:
            # could produce ValueError if there is no ':'
            hash, pickled = encoded_data.split(':', 1)
            expected_hash = self._hash(pickled)
            if not constant_time_compare(hash, expected_hash):
                raise SuspiciousOperation("Session data corrupted")
            else:
                return pickle.loads(pickled)
        except Exception:
            # ValueError, SuspiciousOperation, unpickling exceptions
            # Fall back to Django 1.2 method
            # PendingDeprecationWarning <- here to remind us to
            # remove this fallback in Django 1.5
            try:
                return self._decode_old(session_data)
            except Exception:
                # Unpickling can cause a variety of exceptions. If something happens,
                # just return an empty dictionary (an empty session).
                return {}

    def _decode_old(self, session_data):
        encoded_data = base64.decodestring(session_data)
        pickled, tamper_check = encoded_data[:-32], encoded_data[-32:]
        if not constant_time_compare(md5_constructor(pickled + settings.SECRET_KEY).hexdigest(),
                                     tamper_check):
            raise SuspiciousOperation("User tampered with session cookie.")
        return pickle.loads(pickled)

    def exists(self, session_key):
        """
        Returns True if the given session_key already exists.
        """
        raise NotImplementedError

    def save(self, session_key, session_dict):
        """
        Saves the session data. 
        save() can update an existing object with the same key.
        """
        raise NotImplementedError

    def delete(self, session_key):
        """
        Deletes the session data under this key.
        """
        raise NotImplementedError

    def load(self, session_key, request):
        """
        Loads the session data and returns a dictionary.
        Request object is required for generating the hachi_auth token.
        """
        raise NotImplementedError

