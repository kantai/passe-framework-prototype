import datetime
from warnings import warn
from django.core.exceptions import ImproperlyConfigured
from django.utils.importlib import import_module
from django.contrib.auth.signals import user_logged_in, user_logged_out

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
    If the given credentials are valid, return a User object.
    """
    for backend in get_backends():
        try:
            user = backend.authenticate(**credentials)
        except TypeError:
            # This backend doesn't accept these credentials as arguments. Try the next one.
            continue
        if user is None:
            continue
        # Annotate the user object with the path of the backend.
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        token = "foo_bar"
        return user, token

# TODO: use more generic credentials to support other login methods...
