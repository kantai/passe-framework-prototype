import Pyro4
Pyro4.config.HMAC_KEY = 'deadbeef'

from django.analysis.persisted import resolver_position_to_id, req_socket
import django.conf
import django.htoken as htoken
import django.htoken.serializer
from django.http import get_changeset

USED_NUMBERS = {}
import random
gen_guess = lambda : random.randint(2**10,2**20)

def pre_save_nolabel(**kwargs):
    sender_class, instance, raw = (kwargs["sender"], kwargs["instance"], kwargs["raw"])
    global USED_NUMBERS, gen_guess
    if raw or instance.id is not None:
        return
    pk = gen_guess()
    if sender_class in USED_NUMBERS:
        while pk in USED_NUMBERS[sender_class]:
            pk = gen_guess()
        USED_NUMBERS[sender_class].add(pk)
    else:
        USED_NUMBERS[sender_class] = set((pk,))
    instance.id = pk

class ViewServer(object):
    def get_response(self, request, token, delta):
        request = self.cereal.deserialize(request)
        self.cereal.apply_req_delta(request, delta)
        request.reset_changeset()
        htoken.set_token(token)
        from django.core import exceptions, urlresolvers
        from django.conf import settings

        from django.db.models.signals import pre_save as pre_save_signaler
        if self.starting:
            self.starting = False
            pre_save_signaler.connect(pre_save_nolabel)
        try:
            urlconf = settings.ROOT_URLCONF
            urlresolvers.set_urlconf(urlconf)
            resolver = urlresolvers.RegexURLResolver(r'^/', urlconf)
            cb, cb_args, cb_kwargs, position, view_name = resolver.resolve(request.path_info)
            assert resolver_position_to_id(position) == django.conf.view_id
            response = cb(request, *cb_args, **cb_kwargs)
            if hasattr(response, "render"):
                response.render()
            return htoken.get_token(), request.get_changeset(), response
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print tb
            return None


def run_view_server(view_id):
    django.conf.view_id = view_id

    req_socket_str = req_socket(view_id)
    vs = ViewServer()
    vs.starting = True

    daemon = False
    try:
        daemon = Pyro4.Daemon(unixsocket=req_socket_str)
        daemon.serializer = django.htoken.serializer.Serializer()
        vs.cereal = daemon.serializer
        daemon.register(vs, 'request')
        daemon.requestLoop()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        print tb
        return None
        
    finally:
        if daemon:
            daemon.close()
