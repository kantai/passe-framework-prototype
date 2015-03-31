import os, Pyro4, new
import django.htoken.serializer
from django.utils.importlib import import_module
from django.analysis.persisted import mw_socket
from django.http import get_changeset

PYRO_NAME = 'middleware'

def pre_req(self, request, delta):
    request = self.cereal.deserialize(request)
    self.cereal.apply_req_delta(request, delta)
    request.reset_changeset()
    return request

def spawn_middleware_server(mw_path):
    pid = os.fork()
    if pid == 0:
        start_daemon(mw_path)
        import sys
        sys.exit(0)
    else:
        return pid

def get_middleware_methods(self):
    names = ('process_request', 'process_view', 'process_template_response', 'process_response',
             'process_exception')
    return [ name for name in names if hasattr(self, name) ]

from traceback import format_exc
def proxied_response(self, request, response, delta):
    try:
        request = pre_req(self, request, delta)
        response = self._process_response(request, response)
        return response, request.get_changeset()
    except:
        print format_exc()

def proxied_template_response(self, request, response, delta):
    try:
        request = pre_req(self, request, delta)
        response = self._process_template_response(request, response)
        return response, request.get_changeset()
    except:
        print format_exc()
        
def proxied_request(self, request, delta):
    try:
        request = pre_req(self, request, delta)
        response = self._process_request(request)
        return response, request.get_changeset()
    except:
        print format_exc()
        
def proxied_view(self, request, callback_dummy, callback_args, callback_kwargs, delta):
    try:
        request = pre_req(self, request, delta)
        response = self._process_view(request, callback_dummy, callback_args, callback_kwargs)
        return response, request.get_changeset()
    except:
        print format_exc()

def proxied_exception(self, request, e, delta):
    try:
        request = pre_req(self, request, delta)
        response = self._process_exception(request, e)
        return response, request.get_changeset()
    except:
        print format_exc()

def start_daemon(middleware_path):
    try:
        mw_module, mw_classname = middleware_path.rsplit('.', 1)
    except ValueError:
        raise exceptions.ImproperlyConfigured('%s isn\'t a middleware module' % middleware_path)
    try:
        mod = import_module(mw_module)
    except ImportError, e:
        raise exceptions.ImproperlyConfigured('Error importing middleware %s: "%s"' % (mw_module, e))

    try:
        mw_class = getattr(mod, mw_classname)
    except AttributeError:
        raise exceptions.ImproperlyConfigured('Middleware module "%s" does not define a "%s" class' 
                                              % (mw_module, mw_classname))
    try:
        mw_instance = mw_class()
    except exceptions.MiddlewareNotUsed:
        return
    
    mw_instance.get_middleware_methods = new.instancemethod(get_middleware_methods,
                                                            mw_instance, mw_instance.__class__) # fuh!
    names = mw_instance.get_middleware_methods()
    if 'process_response' in names:
        mw_instance._process_response = mw_instance.process_response
        mw_instance.process_response = new.instancemethod(proxied_response,
                                                          mw_instance,
                                                          mw_instance.__class__)
    if 'process_exception' in names:
        mw_instance._process_exception = mw_instance.process_exception
        mw_instance.process_exception = new.instancemethod(proxied_exception,
                                                           mw_instance,
                                                           mw_instance.__class__)
    if 'process_template_response' in names:
            mw_instance._process_template_response = mw_instance.process_template_response
            mw_instance.process_template_response = new.instancemethod(proxied_template_response,
                                                                       mw_instance,
                                                                       mw_instance.__class__)
    if 'process_view' in names:
            mw_instance._process_view = mw_instance.process_view
            mw_instance.process_view = new.instancemethod(proxied_view,
                                                              mw_instance,
                                                              mw_instance.__class__)
    if 'process_request' in names:
            mw_instance._process_request = mw_instance.process_request
            mw_instance.process_request = new.instancemethod(proxied_request,
                                                              mw_instance,
                                                              mw_instance.__class__)

    daemon = False
    try:
        local = mw_instance
        daemon = Pyro4.Daemon(unixsocket=mw_socket(middleware_path))
        daemon.serializer = django.htoken.serializer.Serializer()
        local.cereal = daemon.serializer
        daemon.register(local, PYRO_NAME)
        daemon.requestLoop()
    finally:
        if daemon:
            daemon.close()

