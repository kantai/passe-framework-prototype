"""
PostgreSQL database backend for Django.

Requires psycopg 2: http://initd.org/projects/psycopg2
"""

import sys,os,Pyro4, threading

from django.conf import settings
from django.analysis import persisted
from django.db.utils import DEFAULT_DB_ALIAS

from django.db import utils
from django.db.backends import *
from django.db.backends.signals import connection_created
from django.db.backends.postgresql.operations import DatabaseOperations as PostgresqlDatabaseOperations
from django.db.backends.postgresql.client import DatabaseClient
from django.db.backends.postgresql.creation import DatabaseCreation
from django.db.backends.postgresql.version import get_version
from django.db.backends.postgresql_psycopg2.introspection import DatabaseIntrospection
from django.utils.safestring import SafeUnicode, SafeString
from django.db.backends.sqlite3.utils import parameterize_limit
from django.analysis.assertion import TokenAssert, ControlFlowAssert
from heapq import heappush, heappop

try:
    import psycopg2 as Database
    import psycopg2.extensions
except ImportError, e:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("Error loading psycopg2 module: %s" % e)

DatabaseError = Database.DatabaseError
IntegrityError = Database.IntegrityError

TOKEN_ID = 0
VOCAL_QUERIES = False

psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_adapter(SafeString, psycopg2.extensions.QuotedString)
psycopg2.extensions.register_adapter(SafeUnicode, psycopg2.extensions.QuotedString)

from django.htoken import verify_signature, sign_dictionary, HachiToken,\
    add_sql_value, ACTIVE_USER_ID_KEY, PERMISSION_IDS, SUPER_STATUS

import django.htoken.serializer
DB_SERIALIZER = django.htoken.serializer.Serializer() # I'm great at naming.

# (view-id) --> sql string --> assertion
assertion_table = {}
view_ids = []
settings_dict = settings.DATABASES[DEFAULT_DB_ALIAS]

class ProxyInstance:
    """
    ...This implements the "server" for a particular socket (?) so to speak...
    """
    def _create_conn(self):
        set_tz = settings_dict.get('TIME_ZONE')
        if settings_dict['NAME'] == '':
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("You need to specify NAME in your Django settings file.")
        conn_params = {
            'database': settings_dict['NAME'],
            }
        conn_params.update(settings_dict['OPTIONS'])
        if 'autocommit' in conn_params:
            del conn_params['autocommit']
        if settings_dict['USER']:
            conn_params['user'] = settings_dict['USER']
        if settings_dict['PASSWORD']:
            conn_params['password'] = settings_dict['PASSWORD']
        if settings_dict['HOST']:
            conn_params['host'] = settings_dict['HOST']
        if settings_dict['PORT']:
            conn_params['port'] = settings_dict['PORT']
        dbconn = Database.connect(**conn_params)
        dbconn.set_client_encoding('UTF8')
        return dbconn

    def get_dbconn(self):
        if not hasattr(self.dbstore, 'dbconn'):
            self.dbstore.dbconn = self._create_conn()
        return self.dbstore.dbconn

    def __init__(self, source):
        self.source = source
        self.dbstore = threading.local()
        self.cursor_id = 0
        self.cursors = {}
        if source == None:
            self.asserts = None
            self.required_token_args = None
        else:
            self.asserts = assertion_table[self.source]
            self.required_token_args = set([ACTIVE_USER_ID_KEY, PERMISSION_IDS, SUPER_STATUS])
            for sql, constraints in self.asserts.items():
                for constraint in constraints:
                    if isinstance(constraint, TokenAssert):
                        if isinstance(constraint.index, list):
                            map(self.required_token_args.add, constraint.index)
                        else:
                            self.required_token_args.add(constraint.index)
                    elif isinstance(constraint, ControlFlowAssert):
                        self.required_token_args.add(constraint.key)
                        self.required_token_args.add(constraint.value)
        self.dbconn = {}
#        self._create_conn()

    def create_cursor(self):
        try:
            self.cursors[self.cursor_id] = HachiProxyCursor(self.source, self.get_dbconn())
            self.cursor_id += 1
            return (self.cursor_id - 1)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print tb
    def close(self):
        pass
#        self.get_dbconn().close()
    def rollback(self):
        self.get_dbconn().rollback()
    def commit(self):
        self.get_dbconn().commit()
    def set_isolation_level(self, isolation_level):
        self.get_dbconn().set_isolation_level(isolation_level)

    def destroy_cursor(self, cursor_id):
        del self.cursors[cursor_id]
    def cursor_get_lastrowid(self, cursor_id, token):
        return self.cursors[cursor_id].get_lastrowid(), None
    def cursor_get_description(self, cursor_id, token):
        return self.cursors[cursor_id].get_description(), None
    def cursor_get_rowcount(self, cursor_id, token):
        return self.cursors[cursor_id].get_rowcount(), None
    def cursor_callproc(self, cursor_id, token, procname, parameters = False ):
        return self.cursors[cursor_id].callproc(procname, parameters), None
    def cursor_close(self, cursor_id, token):
        return self.cursors[cursor_id].close(), None
    def cursor_execute(self, cursor_id, token, oper, parameters = False):
        if VOCAL_QUERIES:
            print "Running query."
        try:
            self.cur_query = oper
            if parameters:
                parameters = tuple(parameters)
            if self.asserts == None:
                return self.cursors[cursor_id].execute(oper, parameters), None

            test_oper, test_params = parameterize_limit(oper, parameters)
            test_oper = str(test_oper).strip()
            self.cur_query = test_oper
            if not (test_oper in self.asserts):
                print test_oper
                print "Admissability Error in %s" % self.source
                return self.cursors[cursor_id].execute(oper, parameters), None
            asserts = self.asserts[test_oper]

            check_token(token)

            if not _check_args_assert(asserts, test_params, token):
                print "Error in %s" % self.source
                print "Constraint Error in %s" % self.source
            return self.cursors[cursor_id].execute(oper, parameters), None

        except Exception as e:
            import traceback
            print traceback.format_exc()
            raise e
    def cursor_executemany(self, cursor_id, token, operation, seq_of_parametrs):
        if VOCAL_QUERIES:
            print "Running query."
        self.cur_query = operation
        if self.asserts == None:
            return self.cursors[cursor_id].executemany(operation, seq_of_parameters), token
        for params in seq_of_parameters:
            test_oper, test_params = parameterize_limit(oper, parameters)
            test_oper = str(test_oper).strip()
            self.cur_query = test_oper
            if not (test_oper in self.asserts):
                print test_oper
                print "Admissability Error in %s" % self.source
                return self.cursors[cursor_id].executemany(operation, seq_of_parameters), None
            asserts = self.asserts[test_oper]

            check_token(token)

            if not _check_args_assert(asserts, test_params, token):
                print "Constraint Error in %s" % self.source

        return self.cursors[cursor_id].executemany(operation, seq_of_parameters), None
    def cursor_fetchone(self, cursor_id, token):
        global TOKEN_ID
        val = self.cursors[cursor_id].fetchone()
        if self.asserts == None:
            return val, token
        new_tid = (1, token.dict["token_id_1"], TOKEN_ID)
        TOKEN_ID += 1
        out_token = add_sql_value(self.cur_query, [val], token, req = self.required_token_args, new_tid = new_tid)
        return val, out_token
    def cursor_fetchmany(self, cursor_id, token, size=False):
        global TOKEN_ID
        val = self.cursors[cursor_id].fetchmany(size)
        if self.asserts == None:
            return val, token
        new_tid = (1, token.dict["token_id_1"], TOKEN_ID)
        TOKEN_ID += 1
        out_token = add_sql_value(self.cur_query, val, token, req = self.required_token_args, new_tid = new_tid)
        return val, out_token
    def cursor_fetchall(self, cursor_id, token):
        global TOKEN_ID
        val = self.cursors[cursor_id].fetchall()
        if self.asserts == None:
            return val, token
        new_tid = (1, token.dict["token_id_1"], TOKEN_ID)
        TOKEN_ID += 1
        out_token = add_sql_value(self.cur_query, val, token, req = self.required_token_args, new_tid = new_tid)
        return val, out_token
    def cursor_nextset(self, cursor_id, token):
        return self.cursors[cursor_id].nextset(), None
    def cursor_get_arraysize(self, cursor_id, token):
        return self.cursors[cursor_id].get_arraysize(), None
    def cursor_setinputsizes(self, cursor_id, token, sizes):
        return self.cursors[cursor_id].setinputsizes(sizes), None
    def cursor_setoutputsizes(self, cursor_id, token, sizes):
        return self.cursors[cursor_id].setoutputsizes(sizes), None

class HachiProxyCursor:
    """
    This class simply forwards all requests defined by PEP-0249, the DB-API
    """
    def __init__(self, source, dbconn):
        """ Cursors will be demuxed based on id and source """
        self.source = source
        self.cursor = dbconn.cursor()
        self.cursor.tzinfo_factory = None
    def get_description(self):
        return self.cursor.description
    def get_rowcount(self):
        return self.cursor.rowcount
    def callproc(self, procname, parameters = False ):
        if parameters == False:
            return self.cursor.callproc(procname)
        return self.cursor.callproc(procname, parameters)
    def close(self):
        return self.cursor.close()
    def get_lastrowid(self):
        return self.cursor.lastrowid
    def execute(self, oper, parameters = False):
        if parameters == False:
            self.cursor.execute(oper)
        self.cursor.execute(oper, parameters)
    def executemany(self, operation, seq_of_parametrs):
        self.cursor.executemany(operation, seq_of_parameters)
    def fetchone(self):
        return self.cursor.fetchone()
    def fetchmany(self, size=False):
        if size == False:
            return self.cursor.fetchmany()
        return self.cursor.fetchmany(size)
    def fetchall(self):
        return self.cursor.fetchall()
    def nextset():
        return self.cursor.nextset()
    def get_arraysize():
        return self.cursor.get_arraysize()
    def setinputsizes(sizes):
        return self.cursor.setinputsizes(sizes)
    def setoutputsizes(sizes):
        return self.cursor.setoutputsizes(sizes)


def fork_off_db_proxies():
    # step 1: read in the tables
    global assertion_table, view_ids
    tables = persisted.read_hachi_tables()
    view_ids = tables.view_ids
    assertion_table = tables.assertions
    child_pids = []
    # step 2: fork off proxies
    for view_id in view_ids + [None]:
        pid = os.fork()
        if pid == 0:
            start_proxy_instance(view_id)
        else:
            child_pids.append(pid)
    return child_pids

def start_proxy_instance(source):
    proxy_instance = ProxyInstance(source)
    daemon = False
    try:
        daemon = Pyro4.Daemon(unixsocket=persisted.db_socket(source))
        daemon.serializer = DB_SERIALIZER
        daemon.register(proxy_instance, 'dbproxy')
        daemon.requestLoop()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        print tb
    finally:
        if daemon:
            daemon.close()
        sys.exit(0)

last_tid_hand = -1
last_tid_prox = -1
heap_hand = []
heap_prox = []

def seen_before(tid):
    if tid[0] == 0:
        # handler
        if tid[2] <= last_tid_hand:
            return True
        if tid[2] in heap_hand:
            return True
        cur = tid[2]
        while cur == last_tid_hand + 1:
            last_tid_hand += 1
            if len(heap_hand) != 0:
                cur = heappop(heap_hand)
            else:
                cur = None
        if cur != None:
            heappush(heap_hand, cur)
        return False
    elif tid[0] == 1:
        # proxy
        if tid[2] <= last_tid_prox:
            return True
        if tid[2] in heap_prox:
            return True
        cur = tid[2]
        while cur == last_tid_prox + 1:
            last_tid_prox += 1
            if len(heap_prox) != 0:
                cur = heappop(heap_prox)
            else:
                cur = None
        if cur != None:
            heappush(heap_prox, cur)
        return False

def check_token(token):
    # check tid...
    tid = (token["token_id_0"], token["token_id_1"], token["token_id_2"])
    if not verify_signature(token):
        print "Signature invalid."
        return False
    if seen_before(tid):
        print "Invalid TID!"
        return False

def _check_args_assert(assertion, args, token):
    if not args:
            args = []

    for cur_assertion in assertion:
        if not cur_assertion.check_assert(args, token):
            print "Failed : %s" %  (cur_assertion.printerr(args, token))
            return False
    return True
