import os, sys, Pyro4

import django.htoken.serializer
from django.contrib.auth.models import User, Permission
from django.analysis.tracer import pause_sql_analysis, resume_sql_analysis
from django import htoken
from django.conf import settings

PYRO_NAME = "authbackend"

def get_SOCK():
    return "/tmp/auth_%s.sock" % settings.worker_id
def get_URI():
    return "PYRO:%s@./u:%s" % (PYRO_NAME, get_SOCK())

class ModelBackendProxy(object):
    """
    Authenticates against django.contrib.auth.models.User.
    """
    supports_object_permissions = False
    supports_anonymous_user = True
    supports_inactive_user = True

    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    # TODO: should return the fackin' token.
    def authenticate(self, token, username=None, password=None):
        try:
            pause_sql_analysis()
            user = User.objects.get(username=username)
            if user.check_password(password):
                d = {}
                if token:
                    d.update(token.dict)
                d[htoken.ACTIVE_USER_ID_KEY] = user.id
                user.token = htoken.HachiToken(d) 

                return user
        except User.DoesNotExist:
            return None
        except:
            from traceback import format_exc
            print format_exc()
            return None
        finally:
            resume_sql_analysis()


    def get_group_permissions(self, user_obj):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """
        pause_sql_analysis()
        if not hasattr(user_obj, '_group_perm_cache'):
            if user_obj.is_superuser:
                perms = Permission.objects.all()
            else:
                perms = Permission.objects.filter(group__user=user_obj)
            perms = perms.values_list('content_type__app_label', 'codename').order_by()
            user_obj._group_perm_cache = set(["%s.%s" % (ct, name) for ct, name in perms])
        resume_sql_analysis()
        return user_obj._group_perm_cache

    def get_all_permissions(self, user_obj):
        pause_sql_analysis()
        if user_obj.is_anonymous():
            return set()
        if not hasattr(user_obj, '_perm_cache'):
            user_obj._perm_cache = set([u"%s.%s" % (p.content_type.app_label, p.codename) 
                                        for p in user_obj.user_permissions.select_related()])
            user_obj._perm_cache.update(self.get_group_permissions(user_obj))
        resume_sql_analysis()
        return user_obj._perm_cache

    def has_perm(self, user_obj, perm):
        if not user_obj.is_active:
            return False
        return perm in self.get_all_permissions(user_obj)

    def has_module_perms(self, user_obj, app_label):
        """
        Returns True if user_obj has any permissions in the given app_label.
        """
        if not user_obj.is_active:
            return False
        for perm in self.get_all_permissions(user_obj):
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def get_user(self, user_id):
        try:
            pause_sql_analysis()
            r = User.objects.get(pk=user_id)
            r.username #bust up some more laziness
            return r
        except User.DoesNotExist:
            return None
        finally:
            resume_sql_analysis()

def start_auth_daemon():
    daemon = False
    try:
        local = ModelBackendProxy()
        daemon = Pyro4.Daemon(unixsocket=get_SOCK())
        daemon.serializer = django.htoken.serializer.Serializer()
        daemon.register(local, PYRO_NAME)
        daemon.requestLoop()
    finally:
        if daemon:
            daemon.close()

def fork_auth_daemon():
    pid = os.fork()
    if pid == 0:
        start_auth_daemon()
        sys.exit(0)
    else:
        return pid


