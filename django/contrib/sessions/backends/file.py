import errno
import os
import tempfile

from django.conf import settings
from django.contrib.sessions.backends.base import SessionManagerBase, CreateError
from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
import django.htoken as htoken
from django.contrib.auth import SESSION_KEY as AUTH_SESSION_KEY

class SessionManager(SessionManagerBase):
    """
    Implements a file based session store.
    """
    def __init__(self):
        self.storage_path = getattr(settings, "SESSION_FILE_PATH", None)
        if not self.storage_path:
            self.storage_path = tempfile.gettempdir()

        # Make sure the storage path is valid.
        if not os.path.isdir(self.storage_path):
            raise ImproperlyConfigured(
                "The session storage path %r doesn't exist. Please set your"
                " SESSION_FILE_PATH setting to an existing directory in which"
                " Django can store session data." % self.storage_path)

        self.file_prefix = settings.SESSION_COOKIE_NAME
        super(SessionManager, self).__init__()

    VALID_KEY_CHARS = set("abcdef0123456789")

    def _key_to_file(self, session_key):
        """
        Get the file associated with this session key.
        """
        if session_key is None:
            return SuspiciousOperation("No Session Key Given")

        # Make sure we're not vulnerable to directory traversal. Session keys
        # should always be md5s, so they should never contain directory
        # components.
        if not set(session_key).issubset(self.VALID_KEY_CHARS):
            raise SuspiciousOperation(
                "Invalid characters in session key %s" % session_key )

        return os.path.join(self.storage_path, self.file_prefix + session_key)

    def load(self, session_key, request):
        """
        What's essential here is that request be a DICTIONARY OF REQUEST VARIABLES
        not the request object.
        """
        token_dict = {}
        token_dict.update([("req_%s" % k, v) for k,v in request.iteritems()])
        try:

            if session_key is None:
                return {}, htoken.HachiToken(token_dict)
            session_data = {}
            session_file = open(self._key_to_file(session_key), "rb")
            try:
                file_data = session_file.read()
                # Don't fail if there is no data in the session file.
                # We may have opened the empty placeholder file.
                if file_data:
                    try:
                        session_data = self.decode(file_data)
                    except (EOFError, SuspiciousOperation):
                        return {}, htoken.HachiToken(token_dict)
            finally:
                session_file.close()
        except Exception as e:
            raise e

        if AUTH_SESSION_KEY in session_data:
            token_dict[htoken.ACTIVE_USER_ID_KEY] = session_data[AUTH_SESSION_KEY]
        token = htoken.HachiToken(token_dict)

        return session_data, token

    def save(self, session_key, session_dict, token = None):
        # Get the session data now, before we start messing
        # with the file it is stored within.
        session_data = session_dict
        
        # TODO here we need to do two things: 
        # (1) check that the auth token matches the session user
        if token == None: 
            print "No token?"
            if AUTH_SESSION_KEY in session_data:
                del session_data[AUTH_SESSION_KEY]
        else:
            if htoken.verify_signature(token):
                if AUTH_SESSION_KEY in session_data:
                    if (htoken.ACTIVE_USER_ID_KEY not in token.dict or 
                        session_data[AUTH_SESSION_KEY] != token.dict[htoken.ACTIVE_USER_ID_KEY]):
                        print "user token mismatch"
                        raise Exception("user token mismatch")
            else:
                print "bad token mismatch"
                raise Exception("bad token passed!")

        if session_key is None:
            session_key = self.get_new_session_key()
        
        session_file_name = self._key_to_file(session_key)

        try:
            # Make sure the file exists.  If it does not already exist, an
            # empty placeholder file is created.
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_BINARY', 0)
            fd = os.open(session_file_name, flags)
            os.close(fd)

        except OSError, e:
            raise

        # Write the session file without interfering with other threads
        # or processes.  By writing to an atomically generated temporary
        # file and then using the atomic os.rename() to make the complete
        # file visible, we avoid having to lock the session file, while
        # still maintaining its integrity.
        #
        # Note: Locking the session file was explored, but rejected in part
        # because in order to be atomic and cross-platform, it required a
        # long-lived lock file for each session, doubling the number of
        # files in the session storage directory at any given time.  This
        # rename solution is cleaner and avoids any additional overhead
        # when reading the session data, which is the more common case
        # unless SESSION_SAVE_EVERY_REQUEST = True.
        #
        # See ticket #8616.
        dir, prefix = os.path.split(session_file_name)

        try:
            output_file_fd, output_file_name = tempfile.mkstemp(dir=dir,
                prefix=prefix + '_out_')
            renamed = False
            try:
                try:
                    os.write(output_file_fd, self.encode(session_data))
                finally:
                    os.close(output_file_fd)
                os.rename(output_file_name, session_file_name)
                renamed = True
            finally:
                if not renamed:
                    os.unlink(output_file_name)

        except (OSError, IOError, EOFError):
            pass
        return session_key

    def exists(self, session_key):
        if os.path.exists(self._key_to_file(session_key)):
            return True
        return False

    def delete(self, session_key):
        try:
            os.unlink(self._key_to_file(session_key))
        except OSError:
            pass
