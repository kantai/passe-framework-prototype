import cStringIO, sys, os
import cPickle
from django.analysis.plogging import plog
timer = None

class SafeUnpickler(object):
    PICKLE_SAFE = {
        'django.contrib.messages.storage.user_messages' : ['LegacyFallbackStorage',
                                                           'UserMessagesStorage'],
        'django.contrib.messages.storage.cookie' : ['CookieStorage'],
        'django.contrib.messages.storage.session' : ['SessionStorage'],
        'django.contrib.messages.storage.base' : ['Message'],
        'socket' : ['_fileobject'],
        '_socket' : ['socket'],
        'django.utils.safestring' : ['SafeUnicode'],
        'django.utils.datastructures' : ['MergeDict', 'ImmutableList', 'MultiValueDict'],
        'django.core.servers.basehttp' : ['FileWrapper'],
        'django.htoken': ['HachiToken'],
        'prof_demo.food.models' : ['UserProfile'],
        'django.contrib.sessions' : ['Session'],
        'django.http' : ['HttpResponse','HttpResponseRedirect', 'HttpResponseServerError', 
                         'HttpResponseForbidden',
                         'RequestDelta', 'HttpResponsePermanentRedirect',
                         'HttpResponseNotFound','SimpleCookie', 'QueryDict'],
        'datetime' : ['datetime'],
        'django.core.files.uploadhandler' : ['MemoryFileUploadHandler', 'TemporaryFileUploadHandler'],
        'django.core.handlers.wsgi' : ['WSGIRequest', 'LimitedStream'],
        'django.core.handlers.base' : ['CallbackDummy'],
        'socialnews.news.rss' : ['LatestEntriesByTopic', 'LatestEntries'],
        'socialnews.news.models' : ['UserProfile', 'Topic'],
        'news.models' : ['UserProfile', 'Topic'],
        'django.template.response' : ['TemplateResponse'],

        'StringIO' : ['StringIO'],
        'exceptions' : ['AssertionError'],
        '__builtin__': ['object', 'list', 'tuple', 'str', 
                        'int', 'float', 'unicode', 'set', 'file'],
        'django.db.models.base' : ['ModelState','simple_class_factory','model_unpickle'],
        'django.contrib.auth.models' : ['User', 'AnonymousUser'],
        'Cookie' : ['Morsel'],
        'decimal' : ['Decimal'],
        'collections' : ['OrderedDict'],
        }
 
    @classmethod
    def find_class(cls, module, name):
        mod_fail = False
        if not module in cls.PICKLE_SAFE:
            mod_fail = True
            print "Unpickler: '%s' : ['%s']," % (module, name)
        __import__(module)
        mod = sys.modules[module]
        if not mod_fail and not name in cls.PICKLE_SAFE[module]:
            print "Unpickler: '%s' : ['%s']," % (module, name)
        klass = getattr(mod, name)
        return klass
 
    @classmethod
    def loads(cls, pickle_string):
        pickle_obj = cPickle.Unpickler(cStringIO.StringIO(pickle_string))
        pickle_obj.find_global = cls.find_class
        return pickle_obj.load()

timing = False
class Serializer(object):
    """
    A (de)serializer that wraps a certain serialization protocol.
    Currently it only supports the standard pickle protocol.
    It can optionally compress the serialized data, and is thread safe.
    """
    def __init__(self):
        import django.conf
        import django.core.handlers.wsgi as wsgi
        self.wsgireqclass = wsgi.WSGIRequest

        if 'serialize' in django.conf.settings.HACHI_ANALYZE:
            import nanotime
            global timer
            timer = nanotime.now
            self.serialize_def = self.serialize
            self.deserialize_def = self.deserialize
            self.serialize = self.timed_serialize
            self.deserialize = self.timed_deserialize
        
        self.last_req_str = None
        
    def timed_serialize(self, data, compress = False):
        global timing
        is_me_timing = False
        if not timing:
            timing = True
            is_me_timing = True
            t_start = timer()

        r = self.serialize_def(data, compress)        
        if is_me_timing:
            t_stop = timer()
            time_ms = (t_stop - t_start).milliseconds()
            plog('serialize', time_ms)
            timing = False

        return r
    def timed_deserialize(self, data, compressed = False):
        global timing
        is_me_timing = False
        if not timing:
            timing = True
            is_me_timing = True
            t_start = timer()
        r = self.deserialize_def(data, compressed)
        if is_me_timing:
            t_stop = timer()
            time_ms = (t_stop - t_start).milliseconds()
            plog('deserialize', time_ms)
            timing = False
        return r
                         
    def serialize(self, data, compress = False):
        """Serialize the given data object, try to compress if told so.
        Returns a tuple of the serialized data and a bool indicating if it is compressed or not."""
        compress = False
        try:
            data=cPickle.dumps(data, cPickle.HIGHEST_PROTOCOL)
        except:
            print data 
            data=cPickle.dumps(data, cPickle.HIGHEST_PROTOCOL)
            

        if not compress or len(data)<200:
            return data, False  # don't waste time compressing small messages
        compressed=zlib.compress(data)
        if len(compressed)<len(data):
            return compressed, True
        return data, False

    def deserialize(self, data, compressed=False):
        compressed = False
        if compressed:
            data=zlib.decompress(data)
        if self.last_req_str and self.last_req_str == data:
            return self.last_req

        r = SafeUnpickler.loads(data)

        if isinstance(r, self.wsgireqclass):
            self.last_req = r
            self.last_req_str = data
        return r

    def apply_req_delta(self, request, request_delta):
        for k,v in request_delta.items():
            request.__dict__[k] = (v)
            if '_messages' == k:
                request._messages._loaded_messages



    def __eq__(self, other):
        """this equality method is only to support the unit tests of this class"""
        return type(other) is Serializer and vars(self)==vars(other)
    def __ne__(self, other):
        return not self.__eq__(other)
    __hash__=object.__hash__

