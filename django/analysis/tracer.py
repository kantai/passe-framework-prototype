import sys, os, gc, inspect, dis, opcode
from django.htoken import get_token
from django.analysis import persisted  #, taintmode
import django.analysis.persisted as persisted
from django.analysis.assertion import *

_caller_cache = dict()

NULL_STATE = 1
BEFORE_VIEW_STATE = 2
IN_VIEW_STATE = 3

ANALYSIS_RUNNING = False

analysis = None

# Analysis needs to pick up the following stuff...
# 1. SQL Statements
#	* should be easy enough to grab - watch for my db-proxy hook point
# 2. Current View
#	* watch at the "handler" insertion point
#	* will also need to construct a list of all views
# 3. Inferrable Assertions
#	* use of the current session user - how to get this?
#		+ uses of foreign key constraint?
#		+ uses of session.userid
#
# And output a mapping from view to possible SQL queries
#  with each SQL query having an attached assertion

# Note, this file is a mess of unorganized functions, globals, and strange
# calling structures. This should probably be fixed but, knowing you, it won't be.

def pause_sql_analysis():
    if analysis:
        analysis.sql_paused = True
def resume_sql_analysis():
    if analysis:
        analysis.sql_paused = False
def is_analysis_paused():
    if analysis:
        return analysis.sql_paused

def is_call_SQL(fmf):
    """
    Returns a SQL descriptor if it is a SQL call.
    Otherwise returns False
    """
    if fmf[2] != "mark_sql_call": # TODO: add, ummm, a check for module too? kthnx.
        return False

def make_perm_check(perm):
    if analysis and (not analysis.sql_paused):
        analysis.add_perm(perm)

try:
    from __pypy__ import taint as pypyt
except ImportError:
    class FooMoo:
        def add_taint(self, x, y):
            return None
        def get_taint(self, x):
            return set()
        def get_control_taint(self):
            return set()
    pypyt = FooMoo()

def set_taint(variable, taint):
    if variable is None:
        return # don't taint None!!!
    pypyt.add_taint(variable, taint)
    #assert is_tainted(variable)
    return variable
def is_tainted(variable):
    return len(pypyt.get_taint(variable)) > 0
def get_taint(variable):
    return set(pypyt.get_taint(variable))
def get_cf_taint():
    return set(pypyt.get_control_taint())
def taint(variable):
    if isinstance(variable, tuple):
        return tuple(( taint(v) for v in variable ))
    if analysis:
        analysis.taint_count += 1
        taint_m = analysis.taint_count
        tainted_v = set_taint(variable, taint_m)
#        tainted_v = taintmode.taint(variable, taint_m)
#        if not taintmode.tainted(tainted_v) and \
#                not (isinstance(variable, bool) or variable == None):
#            print "fuh??? %s %s" % (tainted_v, type(tainted_v))
        return tainted_v
    else:
        return variable
    
def is_analysis_running():
    return ANALYSIS_RUNNING
def set_analysis_running(val):
    global ANALYSIS_RUNNING
    ANALYSIS_RUNNING = val
def in_view():
    if analysis:
        return True
    return False

def mark_sql_call(q,a):
    if analysis:
        return analysis.mark_sql_call(q,a)
def set_user_id(v):
    if analysis:
        return analysis.set_user_id(v)
def analysis_view_start(f, a, kw, res_position, alias):
    if analysis:
        return analysis.analysis_view_start(f, a, kw, res_position, alias)
def analysis_view_refer(res_position, view_name,
                        referer, referer_position, referer_name):
    analysis.add_referer(referer_position) 
    print "AJAX-REF %s, %s" % (referer, referer_name)
def analysis_view_stop():
    analysis.analysis_view_stop()

def add_view_magic(magic):
    if analysis and not is_analysis_paused():
        analysis.add_view_magic(magic)

def is_view_start(fmf):
    "Returns whether it is a view start!"
    if fmf[2] != "analysis_view_start":
        return False
    else:
        return True 
    pass

def is_view_done(fmf):
    return fmf[2] == "analysis_view_stop"

def key_search_function_default(value, arg):
    return arg == value
def ksf_cast(value, arg):
    """
    Checks to see if the value is a simple cast of the arg
    and vice-versa
    """
    # untaint will simplify the casting... not in pypyt!
    v = value
    a = arg
    a_type = type(a)
    v_type = type(v)
    if v_type == a_type:
        return v == a
    try:
        casted_v = a_type(v)
        if casted_v == a:
            return True
    except TypeError:
        pass
    except ValueError:
        pass
    try:
        casted_a = v_type(a)
        if casted_a == v:
            return True
    except TypeError:
        pass
    except ValueError:
        pass
    return False
    

def ksf_taints(value, arg):
    """
    value is the token value.
    arg is the actual SQL argument
    """
    if isinstance(value, list):
        rval = any([ksf_taints(potent, arg) for potent in value])
        return rval
    if is_tainted(arg) and is_tainted(value):
        val = (len(set.intersection(get_taint(arg), get_taint(value))) > 0)
        if val and key_search_function_default(value, arg):
            return True
        if val and ksf_cast(value, arg):
            return True
    return False

def ksf_magics(value, arg, query = None, count = None):
    if isinstance(value, list):
        rval = any([ksf_magics(potent, arg, query, count) for potent in value])
        return rval
    if key_search_function_default(value,arg):
        if isinstance(value, int):
            if (value > 10000): # this is my poor man's check for my magic numbers
                print "!magic: %s" % (value)
                return True
    return False

class Analysis:
    def __init__(self):
        self.tracing_state = NULL_STATE
        self.current_user_id = None
        self.sql_paused = False
        self.taint_count = 0
        self.current_view_descriptor = None
        self.all_views = {}
        self.current_view_magic = []

    def add_referer(self, ref_pos):
        if self.current_view_descriptor == None:
            return
        refid = persisted.resolver_position_to_id(ref_pos)
        self.current_view_descriptor.referers[refid] = True

    def collect_control_flow_taint(self, assertion):
        """
        Adds some control-flow inferences to the assertion list "assertion".
        """
        z = [] # z will hold the keys and values which have affected control-flow 
        for taint_value in get_cf_taint():
            token = get_token()
            for token_key, token_value in token.dict.items():
                if isinstance(token_value, list) or isinstance(token_value, tuple):
                    for item in token_value:                     
                        if taint_value in get_taint(item):
                            z.append((token_key, item))
                else:
                    if taint_value in get_taint(token_value):
                        z.append ((token_key, token_value ))
        # Now that we've collected all the (key, values) which have affected c-f,
        # we can check for equality constraints between the values, and otherwise
        # bail out to constants. (same process as in the query args)
        matches = []
        for ix, (token_key, cf_value) in enumerate(z):
            if ix + 1 == len(z):
                continue
            matches.extend([ControlFlowAssert(token_key, a[0]) for a in z[ix+1:] if a[1] == cf_value])
        assertion.extend(matches)
        # TODO: bailing out to constants. differentiation of constants from key asserts in CFAs.

    def mark_sql_call(self, query, args):
        if self.current_view_descriptor == None or self.sql_paused:
            return
        assertion = []
        token = get_token()

        if len(self.current_view_perms) > 0:
            a = PermissionAssert( list(self.current_view_perms),
                                  perm_validity_check(token.dict, self.current_view_perms) )
            assertion.append(a)
        
        self.collect_control_flow_taint(assertion)
        for counter,arg in enumerate(args):
            if arg == self.current_user_id:
                assertion.append(ActiveUserAssert(counter))
            else:                 
                if isinstance(arg, list):
                    token_ix = []
                    for a in arg:
                        token_ix += [key for key,token_value in token.dict.items() if ksf_taints(token_value, a)]
                else:
                    token_ix = [key for key,token_value in token.dict.items() if ksf_taints(token_value, arg)]
                if len(token_ix) < 1:
                    if isinstance(arg, list):
                        token_ix = []
                        for a in arg:
                            token_ix += [key for key,value in token.dict.items() 
                                         if ksf_magics(value, a, query, key)]
                    else:
                        token_ix = [key for key,value in token.dict.items() 
                                    if ksf_magics(value, arg, query, key)]
                if len(token_ix) > 0:
                    res = token_ix[0] # this could result in an over-constraint, but it hasn't so far in testing.
                    if len(token_ix) > 1:
                        # prioritize SQL results...
                        sql_ixs = [key for key in token_ix if key.startswith('sql')]
                        if len(sql_ixs) > 0:
                            res = sql_ixs[0]                    
                    assertion.append(TokenAssert(counter, res))
#                elif arg in self.current_view_magic:
#                    assertion.append(NullAssert(counter))
                else:
#                    if isinstance(arg, int) and arg > 10000:
#                        print "Suspicious magic number : %s " % arg
                    assertion.append(NullAssert(counter))
#                    assertion.append(ConstantAssert(counter, 
#                                                    arg))

        self.current_view_descriptor.add_sql(query, assertion)

    def set_user_id(self, value):
        self.current_user_id = value
    def analysis_view_stop(self):
        self.current_view_magic = set()
        self.current_view_descriptor = None
    def add_view_magic(self, magic):
        self.current_view_magic.add(magic)
    def add_perm(self, perm):
        self.current_view_perms.add(perm)
    def analysis_view_start(self, view_func, args, kwargs, res_position, alias):
        self.current_view_magic = set()
        self.current_view_perms = set()
        if res_position in self.all_views:
            self.current_view_descriptor = self.all_views[res_position]
        else:
            self.current_view_descriptor = ViewDescriptor(res_position)
            self.current_view_descriptor.alias = alias
            self.all_views[res_position] = self.current_view_descriptor


def merge_assertions(assertion_list):
    """ 
    assertion_list is a list containing an entry for every 
    ''use'' of a database query. 
    Each entry is composed of inferred constraints for that particular usage
    of the database query.

    the output is a list of argument labels and other query constraints.
    """
    if len(assertion_list) == 0:
        return assertion_list
    top_list = assertion_list[0]
    out_list = []
    # first we deal with "positional" labels
    for x in top_list:
        if not hasattr(x, "position"):
            continue
        pos = x.position
        possibles = []
        for l in assertion_list:
            y = [z for z in l if hasattr(z, "position") and z.position == pos]
            if len(y) > 0:
                possibles.append(y[0])
        # now that we have the set of possibilities, what do we do? ahhghg.
        is_good = True
        for p in possibles:
            is_good = (p == x)
            if not is_good:
                break
        
        if is_good:
            if isinstance(x, NullAssert):
                continue
            out_list.append(x)
        # now, more specific, check if they are all TokenAsserts...
        elif all([isinstance(p, TokenAssert) for p in possibles]):
            ix_lst = list(set([ p.index for p in possibles]))
            out_list.append(TokenAssert(pos, ix_lst))
        elif any([isinstance(p, TokenAssert) for p in possibles]):
            pass
  #          print  "\n".join(["%s" % j for j in possibles])
    # now we deal with non-positional labels (i.e., Permissions, CF)
    cf_lists = \
        [ [z for z in l if isinstance(z, ControlFlowAssert) or isinstance(z, PermissionAssert)]
          for l in assertion_list ]
    if len(cf_lists) > 0:
        top = cf_lists[0]
        survivors = [ assertion for assertion in top if
                      all([assertion in l for l in cf_lists]) ]
        for assertion in survivors:
            assertion.position = -2 # just to make sorting easier.
            out_list.append(assertion)
    return sorted(out_list, key = lambda x : x.position)

admin_default1 = """SELECT "django_content_type"."id", "django_content_type"."name", "django_content_type"."app_label", "django_content_type"."model" FROM "django_content_type" WHERE "django_content_type"."id" = ?"""
admin_default2 = """SELECT "django_content_type"."id", "django_content_type"."name", "django_content_type"."app_label", "django_content_type"."model" FROM "django_content_type" WHERE ("django_content_type"."app_label" = ?  AND "django_content_type"."model" = ? )"""

capture_contenttype = True

class ViewDescriptor:
    def __init__(self,resolver_position):
        self.resolver_postion = resolver_position
        self.alias = None
        self.sql_possibilities = {} # sql string -> assertion << list(atoms) >>
        self.referers = {}
        
    def add_sql(self,sql, assertion):
        if sql in self.sql_possibilities:
            self.sql_possibilities[sql].append(assertion)
        else:
            self.sql_possibilities[sql] = [ assertion ]
    def get_merged_queries(self):
        rval = {sql : merge_assertions(_assertions) 
                for sql, _assertions in self.sql_possibilities.items()}
        if capture_contenttype:
            if not (admin_default1 in rval):
                rval[admin_default1] = []
            if not (admin_default2 in rval):
                rval[admin_default2] = []
        return rval

    def __str__(self, sql):
        return self.sql_possibilities

    def make_profile(self):
        print "/tmp/hachi_view_%d.sh" % self.id
        print "{"

       # 1 -- requires a connection to the socket for communication with zeh router.
        print "/tmp/sock_handler_%d rw" % self.id
        # 2 -- requires a connection to the db-proxy 
        print "/tmp/sock_db_%d rw" % self.id
        # What else will it need? 
        # Read permissions to the python libraries? read permissions to the application space?

        print "/usr/bin/python rix" # execute python INSIDE of the current APP-ARMOR profile.

        print "}"

        
def modname(path):
    """Return a plausible module name for the patch."""
    for p in sys.path:
        if path.startswith(p):
            base = path[len(p):]
            if base.startswith("/"):
                base = base[1:]
            name, ext = os.path.splitext(base)
            return name.replace("/",".")    
    base = os.path.basename(path)
    filename, ext = os.path.splitext(base)
    return filename

# unapologetically ripped off from cpython tracer.py
def file_module_function_of(code):
    filename = code.co_filename
    if filename:
        modulename = modname(filename)
    else:
        modulename = None
        
    funcname = code.co_name
    clsname = None
    if code in _caller_cache:
        if _caller_cache[code] is not None:
            clsname = _caller_cache[code]
    else:
        _caller_cache[code] = None
            ## use of gc.get_referrers() was suggested by Michael Hudson
            # all functions which refer to this code object
        funcs = [f for f in gc.get_referrers(code)
                 if inspect.isfunction(f)]
            # require len(func) == 1 to avoid ambiguity caused by calls to
            # new.function(): "In the face of ambiguity, refuse the
            # temptation to guess."
        if len(funcs) == 1:
            dicts = [d for d in gc.get_referrers(funcs[0])
                     if isinstance(d, dict)]
            if len(dicts) == 1:
                classes = [c for c in gc.get_referrers(dicts[0])
                           if hasattr(c, "__bases__")]
                if len(classes) == 1:
                    # ditto for new.classobj()
                    clsname = classes[0].__name__
                    # cache the result - assumption is that new.* is
                    # not called later to disturb this relationship
                    # _caller_cache could be flushed if functions in
                    # the new module get called.
                    _caller_cache[code] = clsname
    if clsname is not None:
        funcname = "%s.%s" % (clsname, funcname)

    return filename, modulename, funcname
    
def view_start_tracer(frame, event, arg):
    assert  analysis.tracing_state == BEFORE_VIEW_STATE
    if event == "return":
        analysis.tracing_state = IN_VIEW_STATE

def quar_tracer(frame, event, arg):
    if event == "call":
        call_to = file_module_function_of(frame.f_code)
        call_from = file_module_function_of(frame.f_back.f_code)
        if analysis.tracing_state == NULL_STATE:
            if is_view_start(call_to):
                analysis.tracing_state = BEFORE_VIEW_STATE
                return view_start_tracer
            else:
                return None
        elif analysis.tracing_state == IN_VIEW_STATE:
            if is_view_done(call_to):
                analysis.tracing_state = NULL_STATE
                return None
    return None

def start_tracer(callback, args, kwargs):
    import threading
    global analysis
    analysis = Analysis()
    try:
        sys.settrace(quar_tracer)
        threading.settrace(quar_tracer)
        try:
            return callback(*args, **kwargs)
        finally:
            sys.settrace(None)
            results = persisted.HachiAnalysis()
            view_aliases = {}
            referers = {}
            for view_resolver_position,VD in analysis.all_views.items():
                #view_name_module = file_module_function_of(view_func.func_code)[1:]
                #print view_name_module
                view_id = persisted.resolver_position_to_id(view_resolver_position)
                view_aliases[view_id] = VD.alias
                view_asserts = VD.get_merged_queries()
                results.view_ids.append(view_id)
                results.assertions[view_id] = view_asserts
                referers[view_id] = VD.referers
            persisted.write_hachi_tables(results, view_aliases)
            persisted.write_hachi_referers(referers)
            persisted.write_sys_path()
            persisted.create_spawn_script(results)

    except IOError, err:
        sys.settrace(None)
        threading.settrace(None)
        print ("Cannot run file %r because: %s" % (sys.argv[0], err))
        sys.exit(-1)
    except SystemExit:
        pass
        
