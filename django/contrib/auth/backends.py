from django.db import connection
from django.contrib.auth.models import User, Permission
from django.contrib.auth.server import get_URI
import Pyro4
import django.htoken.serializer
from django.analysis.tracer import is_analysis_running

shared_proxy_object = None

class ModelBackend(object):
    supports_object_permissions = False
    supports_anonymous_user = True
    supports_inactive_user = True

    def __init__(self):
        if is_analysis_running():
            from django.contrib.auth.server import ModelBackendProxy
            self.proxy_object = ModelBackendProxy()
        else:
            global shared_proxy_object
            if not shared_proxy_object:
                shared_proxy_object = Pyro4.Proxy(get_URI())
                shared_proxy_object._pyroSerializer = django.htoken.serializer.Serializer()
            self.proxy_object = shared_proxy_object
    def authenticate(self, token, username=None, password=None):
        return self.proxy_object.authenticate(token, username, password)
    def get_group_permissions(self, user_obj):
        return self.proxy_object.get_group_permissions(user_obj)
    def get_all_permissions(self, user_obj):
        return self.proxy_object.get_all_permissions(user_obj)
    def has_perm(self, user_obj, perm):    
        return self.proxy_object.has_perm(user_obj, perm)
    def has_module_perms(self, user_obj, app_label):
        return self.proxy_object.has_module_perms(user_obj, app_label)
    def get_user(self, user_id):
        return self.proxy_object.get_user(user_id)
        
class RemoteUserBackend(ModelBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of this package, and is used when the server
    is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = True

    def authenticate(self, remote_user):
        """
        The username passed as ``remote_user`` is considered trusted.  This
        method simply returns the ``User`` object with the given username,
        creating a new ``User`` object if ``create_unknown_user`` is ``True``.

        Returns None if ``create_unknown_user`` is ``False`` and a ``User``
        object with the given username is not found in the database.
        """
        if not remote_user:
            return
        user = None
        username = self.clean_username(remote_user)

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = User.objects.get_or_create(username=username)
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return user

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username

    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user
