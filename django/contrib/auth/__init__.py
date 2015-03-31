import Pyro4
from django.core.exceptions import ImproperlyConfigured
from django.analysis.tracer import is_analysis_running, set_user_id
import django.htoken as htoken
from django.contrib.auth.signals import user_logged_in, user_logged_out
from importlib import import_module
from warnings import warn

SESSION_KEY = '_auth_user_id'
BACKEND_SESSION_KEY = '_auth_user_backend'
REDIRECT_FIELD_NAME = 'next'

def load_backend(path):
    i = path.rfind('.')
    module, attr = path[:i], path[i+1:]
    try:
        mod = import_module(module)
    except ImportError, e:
        raise ImproperlyConfigured('Error importing authentication backend %s: "%s"' % (path, e))
    except ValueError, e:
        raise ImproperlyConfigured('Error importing authentication backends. Is AUTHENTICATION_BACKENDS a correctly defined list or tuple?')
    try:
        cls = getattr(mod, attr)
    except AttributeError:
        raise ImproperlyConfigured('Module "%s" does not define a "%s" authentication backend' % (module, attr))
    if not hasattr(cls, "supports_object_permissions"):
        warn("Authentication backends without a `supports_object_permissions` attribute are deprecated. Please define it in %s." % cls,
             DeprecationWarning)
        cls.supports_object_permissions = False
        
    if not hasattr(cls, 'supports_anonymous_user'):
        warn("Authentication backends without a `supports_anonymous_user` attribute are deprecated. Please define it in %s." % cls,
             DeprecationWarning)
        cls.supports_anonymous_user = False
        
    if not hasattr(cls, 'supports_inactive_user'):
        warn("Authentication backends without a `supports_inactive_user` attribute are deprecated. Please define it in %s." % cls,
             PendingDeprecationWarning)
        cls.supports_inactive_user = False
    return cls()

def get_backends():
    from django.conf import settings
    backends = []
    for backend_path in settings.AUTHENTICATION_BACKENDS:
        backends.append(load_backend(backend_path))
    if not backends:
        raise ImproperlyConfigured('No authentication backends have been defined. Does AUTHENTICATION_BACKENDS contain anything?')
    return backends

def authenticate(**credentials):
    """
    Authenticates the user credentials, returns a USER OBJECT
    and a token.
    """
    for backend in get_backends():
        try:
            cur_token = htoken.get_token()
            user = backend.authenticate(cur_token, credentials['username'], credentials['password'])
        except TypeError as e:
            print e
            # This backend doesn't accept these credentials as arguments. Try the next one.
            continue
        if user is None:
            continue
        # Annotate the user object with the path of the backend...
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        return user

def login(request, user):
    """
    Persist the logged in user and token to the session.
    """
    
    if user is None or not hasattr(user, 'token'):
        raise NotImplementedError
    # assert that token matches user
    if not (htoken.ACTIVE_USER_ID_KEY in user.token.dict and 
            user.token.dict[htoken.ACTIVE_USER_ID_KEY] == user.id and
            htoken.verify_signature(user.token)):
        raise Exception("token fails to verify")
    
    # TODO: It would be nice to support different login methods, like signed cookies.
    if SESSION_KEY in request.session:
        if request.session[SESSION_KEY] != user.id:
            # To avoid reusing another user's session, create a new, empty
            # session if the existing session corresponds to a different
            # authenticated user.
            request.session.flush()
    else:
        request.session.cycle_key()
    if is_analysis_running():
        set_user_id(user.id)
    request.session[SESSION_KEY] = user.id
    request.session[BACKEND_SESSION_KEY] = user.backend
    request.session.modified = True
    htoken.set_token(user.token)

    if hasattr(request, 'user'):
        request.user = user
    user_logged_in.send(sender=user.__class__, request=request, user=user)

def logout(request):
    """
    Removes the authenticated user's ID from the request and flushes their
    session data.
    """
    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = getattr(request, 'user', None)
    if hasattr(user, 'is_authenticated') and not user.is_authenticated():
        user = None
    user_logged_out.send(sender=user.__class__, request=request, user=user)
    if is_analysis_running():
        set_user_id(None)

    request.session.flush()
    request.session.modified = True
    if hasattr(request, 'user'):
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()

def get_user(request):
    from django.contrib.auth.models import AnonymousUser
    try:
        user_id = request.session[SESSION_KEY] 
        backend_path = request.session[BACKEND_SESSION_KEY]
        backend = load_backend(backend_path)
        user = backend.get_user(user_id) or AnonymousUser()
        if is_analysis_running() and user:
            set_user_id(user_id)
    except KeyError:
        user = AnonymousUser()
    return user
