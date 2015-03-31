from Crypto.Hash import HMAC
from cPickle import dumps, loads
#from django.analysis.taintmode import tainted
from django.analysis.plogging import plog
from collections import OrderedDict
timer = None

ACTIVE_USER_ID_KEY = "hachi_active_user"
PERMISSION_IDS = "perm_ids"
SUPER_STATUS = "hachi_super"
secret = "deadbeef"

class HachiToken(object):
    def __init__(self, dict):
        self.dict = OrderedDict(dict)
        self.sign = sign_dictionary(dict)
    def __repr__(self):
        return "HachiToken(%s)" % self.dict

def sign_dictionary_dispatch(dictionary):
    global sign_dictionary, verify_signature, timer
    import django.conf
    from django.analysis.tracer import ANALYSIS_RUNNING as AR
    if AR:
        return ""
    if 'sign' in django.conf.settings.HACHI_ANALYZE:
        import nanotime
        timer = nanotime.now
        sign_dictionary = sign_dictionary_timed
        verify_signature = verify_signature_timed
    else:
        sign_dictionary = sign_dictionary_def
        verify_signature = verify_signature_def
    return sign_dictionary(dictionary)

def verify_signature_dispatch(token):
    global sign_dictionary, verify_signature
    import django.conf
    from django.analysis.tracer import ANALYSIS_RUNNING as AR
    if AR:
        return True
    if 'sign' in django.conf.settings.HACHI_ANALYZE:
        import nanotime
        timer = nanotime.now
        sign_dictionary = sign_dictionary_timed
        verify_signature = verify_signature_timed
    else:
        sign_dictionary = sign_dictionary_def
        verify_signature = verify_signature_def
    return verify_signature(token)

sign_dictionary = sign_dictionary_dispatch
verify_signature = verify_signature_dispatch

def sign_dictionary_timed(dictionary):
    t_start = timer()
    r = sign_dictionary_def(dictionary)
    t_stop = timer()
    plog('sign', (t_stop - t_start).milliseconds())
    return r

def verify_signature_timed(token):
    t_start = timer()
    r = verify_signature_def(token)
    t_stop = timer()
    plog('sign', (t_stop - t_start).milliseconds())
    return r

def sign_dictionary_def(dictionary):
    message = dumps(dictionary)
    signer = HMAC.new(secret)
    signer.update(message)
    return signer.hexdigest()

def verify_signature_def(token):
    message = dumps(token.dict)
    
    signer = HMAC.new(secret)
    signer.update(message)

    return signer.hexdigest() != token.sign

def extend_token(key, value, token):
    """
    Verifies the token, throwing an exception if it fails,
    then adds a new entry to the token and resigns it.
    """
    if not verify_signature(token):
        raise Exception("passed a bad token!")
    token.dict[key] = value
    token.sign = sign_dictionary(token.dict)

def sql_hash(sql_query):
    return hash(sql_query)

def add_sql_value(sql_query, value, in_token = None, req = None, new_tid = None):
    if in_token == None:
        token = get_token()
    else:
        token = in_token
    dict_out = {}
    dict_out.update(token.dict)

    if new_tid != None:
        # 3-part nonce ...
        dict_out["token_id_0"] = new_tid[0] # handler = 0
        dict_out["token_id_1"] = new_tid[1]
        dict_out["token_id_2"] = new_tid[2]
                    
    q_hash = sql_hash(sql_query)
    for row in value:
        if isinstance(row, tuple): # feh?
            for ix,col in enumerate(row):
                if isinstance(col, bool) or col == None:
                    continue
                tokenix = "sql_%s_%s" % (q_hash, ix)
                if req and tokenix not in req:
                    continue
                storage = dict_out.get(tokenix, None)
                if storage is None:
                    storage = list()
                storage.append(col)

                dict_out[tokenix] = storage
        elif not (isinstance(row, bool) or row == None):
            tokenix = "sql_%s" % (q_hash)
            if req and tokenix not in req:
                continue
            storage = dict_out.get(tokenix, [])
            storage.append(row)
            dict_out[tokenix] = storage
    token_out = HachiToken(dict_out)
    if in_token == None:
        set_token(token_out)
    else:
        return token_out

instance = None

def get_token():
    global instance
    return instance

def check_taintness(token):
    if not token:
        return
    for key,value in token.dict.items():
        if key == ACTIVE_USER_ID_KEY:
            continue
#        if not tainted(value):
#            print "F! (%s, %s)" % (key, value)

def set_token(updated):
    global instance
    instance = updated
