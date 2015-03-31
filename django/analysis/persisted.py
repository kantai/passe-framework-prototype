from django.htoken import sql_hash
import cPickle, sys, yaml, os
from base64 import b16encode as encode, b16decode as decode
from django.analysis.assertion import *
from django.conf import settings

hachi_tables = None
referer_table = None

# ...Garbage below...
#_b32alphabet = '[2-7A-Z]'
#_view_regex = "^[$(?P<view_id>%s+)] \\([A-Za-z\\.]\\)$" % (_b32alphabet, )
#_view_format_str = "[%s] (%s)" # view-id and view-alias
#_sql_format_str = "Q: %s" # just drop the query on this
#_sql_regex = "^Q\\:(?P<query>.+)$"
#_single_assert_regex = "^(.*) is ARG([0-9]+)$"

# The structure of the hachi analysis table is as follows:
# each view id is a key into the asserts dictionary.
# This is a dictionary of sql-> (assertion)
# each assertion is a list of AND'ed assertion_elements

def hachi_analysis_to_dict(analysis, aliases):
    def translate_assert_atom(atom):
        if isinstance(atom, ActiveUserAssert):
            return {"type" : "logged_in_user", "sql_argument" : atom.position}
        elif isinstance(atom, ConstantAssert):
            return {"type" : "constant_value", "sql_argument" : atom.position,
                    "constant_value" : atom.value}
        elif isinstance(atom, TokenAssert):
            return {"type" : "request_parameter", "sql_argument" : atom.position,
                    "parameter_index" : atom.index}
        elif isinstance(atom, PermissionAssert):
            return {"type" : "permission",
                    "perms" : atom.perms, "valid" : atom.valid}
        elif isinstance(atom, ControlFlowAssert):
            return {"type" : "controlflow",
                    "key" : atom.key, "value" : atom.value}
        raise Exception("Foobar'd the analysis bud.")

    d = {}
    for view_id in analysis.view_ids:
        cur_asserts = analysis.assertions[view_id]
        sql_dict = {}
        for sql in cur_asserts:
            sql_dict[sql] = [ {"type" : "decoration" , "sqlhash" : sql_hash(sql)} ] + \
                [ translate_assert_atom(atom) for atom in cur_asserts[sql] ]
        d[view_id] = {'alias' : aliases[view_id],
                      'sql' : sql_dict}
    return d

def dict_to_hachi_analysis(d):
    def translate_assert_atom(atom):
        if atom['type'] == 'logged_in_user':
            return ActiveUserAssert(atom['sql_argument'])
        elif atom['type'] == 'constant_value':
            return ConstantAssert(atom['sql_argument'], atom['constant_value'])
        elif atom['type'] == 'request_parameter':
            return TokenAssert(atom['sql_argument'], atom['parameter_index'])
        elif atom['type'] == 'permission':
            return PermissionAssert(atom['perms'], atom['valid'])
        elif atom['type'] == 'controlflow':
            return ControlFlowAssert(atom['key'], atom['value'])
        raise Exception("Foobar'd the analysis bud.")

    r = HachiAnalysis()
    for view_id in d:
        r.view_ids.append(view_id)
        view_assertions = {}
        for sql_key,assertion in d[view_id]['sql'].items():
            final_key = str(sql_key).strip()
            view_assertions[final_key] = [ translate_assert_atom(atom) for atom in assertion if atom['type'] != 'decoration' ]
        r.assertions[view_id] = view_assertions
    return r

def db_socket(socket_postfix):
    return "/tmp/db_%s_%s.sock" % (socket_postfix, settings.worker_id)
def req_socket(socket_postfix):
    return "/tmp/req_%s_%s.sock" % (socket_postfix, settings.worker_id)
def mw_socket(mw_name):
    return "/tmp/mw_%s_%s.sock" % (mw_name, settings.worker_id)
def delegator_socket():
    return "/tmp/delegator.sock"

def db_uri(socket_postfix):
    return "PYRO:dbproxy@./u:%s" % db_socket(socket_postfix)
def req_uri(socket_postfix):
    return "PYRO:request@./u:%s" % req_socket(socket_postfix)
def mw_uri(mw_name):
    return "PYRO:middleware@./u:%s" % mw_socket(mw_name)
def delegator_uri():
    return "PYRO:delegator@./u:%s" % delegator_socket()

def resolver_position_to_id(position):
    start_str =  "%r" % (position,)
    return encode(start_str)

def id_to_position(viewid):
    tuple_repr = decode(viewid)[1:-1]
    position_tuple = ( int(f) for f in tuple_repr.split(",") )
    return position_tuple

def read_hachi_tables():
    global hachi_tables
    if hachi_tables:
        return hachi_tables

    read_from_file = open(settings.ANALYSIS_LOCATION, 'r')
    hachi_tables = dict_to_hachi_analysis(yaml.load(read_from_file))
    return hachi_tables

def write_hachi_tables(hachi_analysis, aliases):
    try:
        file = open(settings.ANALYSIS_LOCATION, 'w')
        yaml.dump(hachi_analysis_to_dict(hachi_analysis, aliases), file)
    finally:
        file.close()

def write_hachi_referers(referers):
    try:
        file = open('/tmp/hachi_referers', 'w')
        yaml.dump(referers, file)
    finally:
        file.close()

def read_hachi_referers():
    global referer_table
    if referer_table:
        return referer_table

    file = open('/tmp/hachi_referers', 'r')
    referer_table = yaml.load(file)
    return referer_table

def write_sys_path():
    try:
        file = open('/tmp/hachi_sys_path', 'w')
        pickler = cPickle.Pickler(file)
        try:
            settings_module = os.environ['DJANGO_SETTINGS_MODULE']
        except KeyError:
            settings_module = 'settings'
        pickler.dump((sys.path, settings_module))
    finally:
        file.close()

def create_spawn_script(hachi_analysis):
    #spawn_view = "python /disk/local/blanks/hachi-framework/django/hviews/run.py %s"
    spawn_view = "python $HACHIPATH/django/hviews/run.py %s $1"
    spawn_srvr = \
        """python manage.py spawnhelpers &
python manage.py runserver
#gunicorn -b 0.0.0.0:8000 app_foo.wsgi_passe:application
"""
    try:
        file = open('/tmp/hachi_spawn_script.sh', 'w')
        for view in hachi_analysis.view_ids:
            try:
                f_view = open('/tmp/hachi_view_%s' % view,'w')
                f_view.write('#!/bin/sh \n')
                f_view.write(spawn_view % view)
                f_view.write("\n")
                create_apparmor_prof(view)
            finally:
                f_view.close()
            file.write('/tmp/hachi_view_%s &\n' % view)
        file.write(spawn_srvr)
        file.write("\n")
    finally:
        file.close()

def create_apparmor_prof(id):
    z = open('/tmp/hachi_view_%s.a' % id, 'w')
    z.write( "/tmp/hachi_view_%s" % id )
    z.write('\n')
    z.write( "{" )
    z.write('\n')
    z.write( "/tmp/sock_hachi_auth rw," )
    z.write('\n')
    z.write( "%s rw," % db_socket(id) )
    z.write('\n')
    z.write( "%s rw," % req_socket(id) )
    z.write('\n')

    for s in sys.path:
        z.write( "%s r," % s )
        z.write('\n')

    z.write("/etc/ld.so.cache r,")
    z.write('\n')
    z.write("/lib/x86_64-linux-gnu/libc-2.13.so r,")
    z.write('\n')

    z.write( "/usr/bin/python rix," ) # execute python INSIDE of the current APP-ARMOR profile.
    z.write('\n')

    z.write( "}" )
    z.write('\n')


class HachiAnalysis(object):
    def __init__(self):
        self.assertions = {}
        self.view_ids = []
    def __str__(self):
        return "%s\n%s" % (self.assertions, self.view_ids)
