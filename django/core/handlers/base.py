import sys,os,threading

from urlparse import urlparse

from django import http
from django.http import HttpRequestDummy, RequestDelta
from django.core import signals
from django.utils.encoding import force_unicode
from django.utils.importlib import import_module
from django.utils.log import getLogger
from django.analysis.persisted import read_hachi_tables, read_hachi_referers, resolver_position_to_id, req_uri, mw_uri
from django.analysis.tracer import is_analysis_running, analysis_view_start, analysis_view_refer, analysis_view_stop, taint, is_tainted
from django.middleware.server import spawn_middleware_server
from django.utils import datastructures
from django.analysis.plogging import plog
from django.core.urlresolvers import Resolver404
import django.htoken as htoken
import django.htoken.serializer as serializer
import time
from copy import copy, deepcopy
import Pyro4
Pyro4.config.HMAC_KEY = 'deadbeef'

building_iframe = False
logger = getLogger('django.request')

CHILD_HEADER = """
<head><base target='_parent' /><script src="%s"></script>
"""

PARENT_HEADER = """
<html><head><script src="%s"></script></head>
"""

VIEW_TOKEN_ID = 0
VIEW_TOKEN_WORKER_ID = -1

def check_referer(view_pos, ref_pos):
    referers = read_hachi_referers()
    view_id = resolver_position_to_id(view_pos)
    ref_id = resolver_position_to_id(ref_pos)
    if not ref_id in referers[view_id]:
        print "JS Error: %s ref'd to %s" % (ref_pos, view_pos)
        
def apply_req_delta(request, request_delta, delta_total):
    for k,v in request_delta.items():
        request.__dict__[k] = (v)
        delta_total[k] = v
        if '_messages' == k:
            request._messages._loaded_messages
            delta_total[k]._loaded_messages

class BaseHandler(object):
    # Changes that are always applied to a response (in this order).
    response_fixes = [
        http.fix_location_header,
        http.conditional_content_removal,
        http.fix_IE_for_attach,
        http.fix_IE_for_vary,
    ]

    view_server_proxies = {
        }
    
    def __init__(self):
        self._request_middleware = self._view_middleware = self._response_middleware = self._exception_middleware = None
        if not is_analysis_running():
            tables = read_hachi_tables()
            self.fancy_serializing = True
            self.req_serializer = serializer.Serializer()
            self.proxy_store = threading.local()
        else:
            self.fancy_serializing = False

    def get_view_server(self, res_position):
        if not hasattr(self.proxy_store, 'views'):
            self.proxy_store.views = {}
        iden = resolver_position_to_id(res_position)
        if iden not in self.proxy_store.views:
            uri = req_uri(iden)
            proxy = Pyro4.Proxy(uri)
            proxy._pyroSerializer = self.req_serializer
            self.proxy_store.views[iden] = proxy
            return proxy
        return self.proxy_store.views[iden]

    def load_middleware(self):
        """
        Populate middleware lists from settings.MIDDLEWARE_CLASSES.

        Must be called after the environment is fixed (see __call__).
        """
        from django.conf import settings

        from django.core import exceptions
        self._view_middleware = []
        self._template_response_middleware = []
        self._response_middleware = []
        self._exception_middleware = []

        request_middleware = []
        for middleware_path in settings.MIDDLEWARE_CLASSES:
            if not is_analysis_running():
                self._load_mw_proxy(middleware_path, request_middleware)
            else:
                try:
                    mw_module, mw_classname = middleware_path.rsplit('.', 1)
                except ValueError:
                    raise exceptions.ImproperlyConfigured('%s isn\'t a middleware module' % middleware_path)
                self._load_mw(mw_module, mw_classname, request_middleware)

        # We only assign to this when initialization is complete as it is used
        # as a flag for initialization being complete.
        self._request_middleware = request_middleware

    def _load_mw(self, mw_module, mw_classname, request_middleware):
        try:
            mod = import_module(mw_module)
        except ImportError, e:
            raise exceptions.ImproperlyConfigured('Error importing middleware %s: "%s"' % (mw_module, e))
        try:
            mw_class = getattr(mod, mw_classname)
        except AttributeError:
            raise exceptions.ImproperlyConfigured('Middleware module "%s" does not define a "%s" class' % (mw_module, mw_classname))
        try:
            mw_instance = mw_class()
        except exceptions.MiddlewareNotUsed:
            return

        if hasattr(mw_instance, 'process_request'):
            request_middleware.append(mw_instance.process_request)
        if hasattr(mw_instance, 'process_view'):
            self._view_middleware.append(mw_instance.process_view)
        if hasattr(mw_instance, 'process_template_response'):
            self._template_response_middleware.insert(0, mw_instance.process_template_response)
        if hasattr(mw_instance, 'process_response'):
            self._response_middleware.insert(0, mw_instance.process_response)
        if hasattr(mw_instance, 'process_exception'):
            self._exception_middleware.insert(0, mw_instance.process_exception)

    def _load_mw_proxy(self, mw_name, request_middleware):
        uri = mw_uri(mw_name)
        mw_instance = Pyro4.Proxy(uri)
        mw_instance._pyroSerializer = self.req_serializer
        try:
            mw_instance._pyroBind()
        except Pyro4.errors.CommunicationError:            
            spawn_middleware_server(mw_name)
            time.sleep(.3) # server startup, I guess. so hacked.
            mw_instance = Pyro4.Proxy(uri)
            mw_instance._pyroSerializer = self.req_serializer

        methods = mw_instance.get_middleware_methods()

        if 'process_request' in methods:
            request_middleware.append(mw_instance.process_request)
        if 'process_view' in methods:
            self._view_middleware.append(mw_instance.process_view)
        if 'process_template_response' in methods:
            self._template_response_middleware.insert(0, mw_instance.process_template_response)
        if 'process_response' in methods:
            self._response_middleware.insert(0, mw_instance.process_response)
        if 'process_exception' in methods:
            self._exception_middleware.insert(0, mw_instance.process_exception)

    def get_response(self, request):
        "Returns an HttpResponse object for the given HttpRequest"
        global VIEW_TOKEN_ID, VIEW_TOKEN_WORKER_ID

        from django.core import exceptions, urlresolvers
        from django.conf import settings
        request.token = None

        referer = request.META.get('HTTP_REFERER', None) or '/'

        htoken.set_token(None)

        if building_iframe:
            from django.contrib.staticfiles.storage import StaticFilesStorage
            sfs = StaticFilesStorage()
            CHILD_JS = sfs.url("shim_extension.js")
            PARENT_JS = sfs.url("master.js")

        if len(settings.HACHI_ANALYZE) > 1:
            plog('req_start', 0)

        if self.fancy_serializing:
            current_delta = dict()
            req_str = self.req_serializer.serialize(request)[0]
        try:
            # Setup default url resolver for this thread, this code is outside
            # the try/except so we don't get a spurious "unbound local
            # variable" exception in the event an exception is raised before
            # resolver is set
            urlconf = settings.ROOT_URLCONF
            urlresolvers.set_urlconf(urlconf)
            resolver = urlresolvers.RegexURLResolver(r'^/', urlconf)
            try:
                response = None
                # POINT OF ENTRY (A) -- REQUEST MIDDLEWARE
                # Apply request middleware
                for middleware_method in self._request_middleware:
                    if self.fancy_serializing:
                        response = middleware_method(req_str, current_delta)
                    else:
                        response = middleware_method(request)
                    if isinstance(response,tuple):
                        response, request_delta = response
                        if isinstance(request_delta, dict):
                            apply_req_delta(request, request_delta, current_delta)
                        else:
                            if self.fancy_serializing:
                                raise Exception("Fancy Serializing is on and got a request object. Cries.")
                            request = request_delta
                    if response:
                        break

                if response is None:
                    if hasattr(request, "urlconf"):
                        # Reset url resolver with a custom urlconf.
                        print "WARNING: Hachi disables request urlconf rewriting!"
                        #urlconf = request.urlconf
                        #urlresolvers.set_urlconf(urlconf)
                        #resolver = urlresolvers.RegexURLResolver(r'^/', urlconf)

                    (callback, callback_args, callback_kwargs, res_position, 
                     view_name) = resolver.resolve(request.path_info)
                    if is_analysis_running():
                        del request.REQUEST
                        request.GET = copy(request.GET)
                        request.POST = copy(request.POST)
                        request.REQUEST = datastructures.MergeDict(request.POST, request.GET)

                        for k,v in request.GET.items():                            
                            request.GET[k] = taint(v) 
                        for k,v in request.POST.items():                            
                            request.POST[k] = taint(v)
                            if not is_tainted(request.POST[k]):
                                import pdb
                                pdb.set_trace()
                                raise Exception()

                    if is_analysis_running():
                        callback_args = [taint(v) for v in callback_args]
                        callback_kwargs = dict( [ (k, taint(v)) for k,v in callback_kwargs.items() ] )
                    
                    view_args_dict = {}
                    
                    token = request.token
                    
                    if token and htoken.ACTIVE_USER_ID_KEY in token.dict:
                        view_args_dict[htoken.ACTIVE_USER_ID_KEY] = token.dict[htoken.ACTIVE_USER_ID_KEY]
                        view_args_dict[htoken.PERMISSION_IDS] = request.user.get_all_permissions()
                        if request.user.is_superuser:
                            view_args_dict[htoken.SUPER_STATUS] = 1
                        else:
                            view_args_dict[htoken.SUPER_STATUS] = 0
                        
                    def atomize(v):
                        if len(v) == 1:
                            return v[0]
                        else:
                            return v
                    view_args_dict.update([("req_%s" % k, atomize(v)) for k,v in request.REQUEST.iterlists()])
#                    if 'req__selected_action' in view_args_dict:
#                        import pdb; pdb.set_trace()
#                        print "DICT: %s" % view_args_dict['req__selected_action']
#                        print "REQ: %s" % request.REQUEST['_selected_action']
#                    if is_analysis_running():
#                        for k,v in view_args_dict.items():
#                            if k.startswith("req"):
#                                if not is_tainted(v):
#                                    print (k,v)

                    for ix, arg in enumerate(callback_args):
                        view_args_dict["view_arg_%s" % ix] = arg
                    for key, value in callback_kwargs.items():
                        view_args_dict["view_arg_%s" % key] = value
                    if VIEW_TOKEN_WORKER_ID == -1:
                        VIEW_TOKEN_WORKER_ID = settings.worker_id

                    # 3-part nonce ...
                    view_args_dict["token_id_0"] = 0 # handler = 0
                    view_args_dict["token_id_1"] = VIEW_TOKEN_WORKER_ID
                    view_args_dict["token_id_2"] = VIEW_TOKEN_ID
                    VIEW_TOKEN_ID += 1

                    request.token = (htoken.HachiToken(view_args_dict))
                    if self.fancy_serializing:
                        current_delta['token'] = request.token
                    htoken.set_token(request.token)

                    # Apply view middleware
                    # POINT OF ENTRY (B) - "view middleware"
                    for middleware_method in self._view_middleware:
                        
                        if self.fancy_serializing:
                            response = middleware_method(req_str, CallbackDummy(callback), callback_args, 
                                                         callback_kwargs, current_delta)
                        else:
                            response = middleware_method(request, CallbackDummy(callback), callback_args, 
                                                         callback_kwargs)

                        if isinstance(response,tuple):
                            response, request_delta = response
                            if isinstance(request_delta, dict):
                                apply_req_delta(request, request_delta, current_delta)
                            else:
                                if self.fancy_serializing:
                                    raise Exception("Fancy Serializing is on and got a request object. Cries.")
                                request = request_delta

                        if response:
                            break

                if response is None:
                    try:
                        # THIS IS THE ACTUAL VIEW
                        if is_analysis_running():
                            analysis_view_start(callback, callback_args, callback_kwargs,
                                                res_position, view_name)
                            try:
                                (cb_ref, cb_refargs, cb_refkwargs, referer_position, 
                                 referer_name) = resolver.resolve(urlparse(referer)[2])
                                
                                if request.is_ajax():
                                    analysis_view_refer(res_position, view_name,
                                                        referer, referer_position, referer_name)
                            except Resolver404:
                                pass

                            response = callback(request, *callback_args,
                                                 **callback_kwargs)

                            if hasattr(response, 'render') and callable(response.render):
#                                for middleware_method in self._template_response_middleware:
#                                    response = middleware_method(request, response)
                                response = response.render()

                            if building_iframe:
                                actual_content = response.content
                                actual_content = actual_content.replace("<head>", CHILD_HEADER % CHILD_JS)
                                actual_content = actual_content.replace("'", "&quot;")
                                actual_content = actual_content.replace('action=""', 'action="' + request.path + '"')
                                actual_content = "<!--startsbox-->" + actual_content + "<!--stopsbox-->"
                                PARENT_START = PARENT_HEADER % PARENT_JS
                                response.content = PARENT_START + "<body><iframe width='100%' height='100%' id='child' name='child' seamless sandbox='allow-forms allow-scripts allow-top-navigation' srcdoc='" + actual_content + "'></iframe></body></html>"

                            request.token = htoken.get_token()

                            analysis_view_stop()
                        else:
                            if building_iframe and is_analysis_running():
                                if request.is_ajax():
                                    (cb_ref, cb_refargs, cb_refkwargs, referer_position, 
                                     referer_name) = resolver.resolve(urlparse(referer)[2])
                                    check_referer(res_position, referer_position)


                            vs = self.get_view_server(res_position)
                            if self.fancy_serializing:
                                full_resp = vs.get_response(req_str, 
                                                            request.token,
                                                            current_delta)
                                if full_resp is not None:
                                    token, request_delta, response = full_resp
                                else:
                                    response = None
                            else:
                                token, request_delta, response = vs.get_response(request, 
                                                                                 request.token)
                            if isinstance(request_delta, dict):
                                apply_req_delta(request, request_delta, current_delta)
                            else:
                                if self.fancy_serializing:
                                    raise Exception("Fancy Serializing is on and got a request object. Cries.")                                
                                request = request_delta
                            
                            if building_iframe:
                                actual_content = response.content
                                actual_content = actual_content.replace("<head>", CHILD_HEADER % CHILD_JS)
                                actual_content = actual_content.replace("'", "&quot;")
                                actual_content = actual_content.replace('action=""', 'action="' + request.path + '"')
                                actual_content = "<!--startsbox-->" + actual_content + "<!--stopsbox-->"
                                PARENT_START = PARENT_HEADER % PARENT_JS
                                response.content = PARENT_START + "<body><iframe width='100%' height='100%' id='child' name='child' seamless sandbox='allow-forms allow-scripts allow-top-navigation' srcdoc='" + actual_content + "'></iframe></body></html>"

                            request.token = token
                            current_delta['token'] = request.token

                            htoken.set_token(token)
                    except Exception, e:
                        import traceback
                        tb = traceback.format_exc()
                        print tb
                        # If the view raised an exception, run it through exception
                        # middleware, and if the exception middleware returns a
                        # response, use that. Otherwise, reraise the exception.
                        for middleware_method in self._exception_middleware:
                            if self.fancy_serializing:
                                response = middleware_method(req_str, e, current_delta)
                            else:
                                response = middleware_method(request, e)                                
                            if isinstance(response,tuple):
                                response,request_delta = response
                                if isinstance(request_delta, dict):
                                    apply_req_delta(request, request_delta, current_delta)
                                else:
                                    if self.fancy_serializing:
                                        raise Exception("Fancy Serializing is on and got a request object. Cries.")
                                    request = request_delta

                            if response:
                                break
                        if response is None:
                            raise


                # Complain if the view returned None (a common error).
                if response is None:
                    import traceback
                    tb = traceback.format_exc()
                    print tb
                    
                    try:
                        view_name = callback.func_name # If it's a function
                    except AttributeError:
                        view_name = callback.__class__.__name__ + '.__call__' # If it's a class
                    raise ValueError("The view %s.%s didn't return an HttpResponse object." % (callback.__module__, view_name))

                # If the response supports deferred rendering, apply template
                # response middleware and the render the response
                # in-fucking-triguing...
                #if hasattr(response, 'render') and callable(response.render):
                #    for middleware_method in self._template_response_middleware:
                #        response = middleware_method(request, response)
                #    response = response.render()

            except http.Http404, e:
                logger.warning('Not Found: %s' % request.path,
                            extra={
                                'status_code': 404,
                                'request': request
                            })
                if settings.DEBUG:
                    from django.views import debug
                    response = debug.technical_404_response(request, e)
                else:
                    try:
                        callback, param_dict = resolver.resolve404()
                        response = callback(request, **param_dict)
                    except:
                        try:
                            response = self.handle_uncaught_exception(request, resolver, sys.exc_info())
                        finally:
                            receivers = signals.got_request_exception.send(sender=self.__class__, request=request)
            except exceptions.PermissionDenied:
                logger.warning('Forbidden (Permission denied): %s' % request.path,
                            extra={
                                'status_code': 403,
                                'request': request
                            })
                response = http.HttpResponseForbidden('<h1>Permission denied</h1>')
            except SystemExit:
                # Allow sys.exit() to actually exit. See tickets #1023 and #4701
                raise
            except: # Handle everything else, including SuspiciousOperation, etc.
                # Get the exception info now, in case another exception is thrown later.
                import traceback
                tb = traceback.format_exc()
                print tb

                receivers = signals.got_request_exception.send(sender=self.__class__, request=request)
                response = self.handle_uncaught_exception(request, resolver, sys.exc_info())
        finally:
            # Reset URLconf for this thread on the way out for complete
            # isolation of request.urlconf
            urlresolvers.set_urlconf(None)

        try:
            # Apply response middleware, regardless of the response
            for middleware_method in self._response_middleware:

                if self.fancy_serializing:
                    response = middleware_method(req_str, response, current_delta)
                else:
                    response = middleware_method(request, response)

                if isinstance(response,tuple):
                    response, request_delta = response
                    if isinstance(request_delta, dict):
                        apply_req_delta(request, request_delta, current_delta)
                    else:
                        request = request_delta

            response = self.apply_response_fixes(request, response)
        except: # Any exception should be gathered and handled
            import traceback
            tb = traceback.format_exc()
            print tb

            receivers = signals.got_request_exception.send(sender=self.__class__, request=request)
            response = self.handle_uncaught_exception(request, resolver, sys.exc_info())

        if len(settings.HACHI_ANALYZE) > 1:
            plog('req_finished', 0)
                
        return response

    def handle_uncaught_exception(self, request, resolver, exc_info):
        """
        Processing for any otherwise uncaught exceptions (those that will
        generate HTTP 500 responses). Can be overridden by subclasses who want
        customised 500 handling.

        Be *very* careful when overriding this because the error could be
        caused by anything, so assuming something like the database is always
        available would be an error.
        """
        from django.conf import settings

        if settings.DEBUG_PROPAGATE_EXCEPTIONS:
            raise

        if settings.DEBUG:
            from django.views import debug
            return debug.technical_500_response(request, *exc_info)

        logger.error('Internal Server Error: %s' % request.path,
            exc_info=exc_info,
            extra={
                'status_code': 500,
                'request':request
            }
        )

        # If Http500 handler is not installed, re-raise last exception
        if resolver.urlconf_module is None:
            raise exc_info[1], None, exc_info[2]
        # Return an HttpResponse that displays a friendly error message.
        callback, param_dict = resolver.resolve500()
        return callback(request, **param_dict)

    def apply_response_fixes(self, request, response):
        """
        Applies each of the functions in self.response_fixes to the request and
        response, modifying the response in the process. Returns the new
        response.
        """
        for func in self.response_fixes:
            response = func(request, response)
        return response

def get_script_name(environ):
    """
    Returns the equivalent of the HTTP request's SCRIPT_NAME environment
    variable. If Apache mod_rewrite has been used, returns what would have been
    the script name prior to any rewriting (so it's the script name as seen
    from the client's perspective), unless DJANGO_USE_POST_REWRITE is set (to
    anything).
    """
    from django.conf import settings
    if settings.FORCE_SCRIPT_NAME is not None:
        return force_unicode(settings.FORCE_SCRIPT_NAME)

    # If Apache's mod_rewrite had a whack at the URL, Apache set either
    # SCRIPT_URL or REDIRECT_URL to the full resource URL before applying any
    # rewrites. Unfortunately not every Web server (lighttpd!) passes this
    # information through all the time, so FORCE_SCRIPT_NAME, above, is still
    # needed.
    script_url = environ.get('SCRIPT_URL', u'')
    if not script_url:
        script_url = environ.get('REDIRECT_URL', u'')
    if script_url:
        return force_unicode(script_url[:-len(environ.get('PATH_INFO', ''))])
    return force_unicode(environ.get('SCRIPT_NAME', u''))


class CallbackDummy:
    def __init__(self, actual_callback):
        if hasattr(actual_callback, 'csrf_exempt'):
            self.csrf_exempt = actual_callback.csrf_exempt

