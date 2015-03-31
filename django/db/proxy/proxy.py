# what does this need to achieve?
# ugh...
#  ... needs to forward !queries! to an open database
#  ... connection
# .... must manage that connection correctly

import Pyro4, os, sys, sqlite3, thread
import decimal
from heapq import heappush, heappop

from django.conf import settings
from django.analysis import persisted
from django.db.utils import DEFAULT_DB_ALIAS
from django.db.backends import util
from django.db.backends.sqlite3.utils import parameterize_limit

from django.utils.safestring import SafeString, SafeUnicode
from django.htoken import verify_signature, sign_dictionary, HachiToken,\
    add_sql_value, ACTIVE_USER_ID_KEY, PERMISSION_IDS, SUPER_STATUS, sql_hash
from django.analysis.assertion import TokenAssert, ControlFlowAssert

import django.htoken.serializer
DB_SERIALIZER = django.htoken.serializer.Serializer() # I'm great at naming.

# (view-id) --> sql string --> assertion
assertion_table = {}
view_ids = []
settings_dict = settings.DATABASES[DEFAULT_DB_ALIAS]
TOKEN_ID = 0

def register_type_converters(Database):
    Database.register_converter("bool", lambda s: str(s) == '1')
    Database.register_converter("time", util.typecast_time)
    Database.register_converter("date", util.typecast_date)
    Database.register_converter("datetime", util.typecast_timestamp)
    Database.register_converter("timestamp", util.typecast_timestamp)
    Database.register_converter("TIMESTAMP", util.typecast_timestamp)
    Database.register_converter("decimal", util.typecast_decimal)
    Database.register_adapter(decimal.Decimal, util.rev_typecast_decimal)
    if Database.version_info >= (2,4,1):
        # Starting in 2.4.1, the str type is not accepted anymore, therefore,
        # we convert all str objects to Unicode
        # As registering a adapter for a primitive type causes a small
        # slow-down, this adapter is only registered for sqlite3 versions
        # needing it.
        Database.register_adapter(str, lambda s:s.decode('utf-8'))
        Database.register_adapter(SafeString, lambda s:s.decode('utf-8'))

class ProxyInstance:
    """
    ...This implements the "server" for a particular socket (?) so to speak...
    """
    def __init__(self, source):
        reload(sqlite3)
        register_type_converters(sqlite3)

        self.source = source
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
        kwargs = {
            'database': settings_dict['NAME'],
            'detect_types': sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            'check_same_thread' : False
            }
        kwargs.update(settings_dict['OPTIONS'])
        self.dbconn = sqlite3.connect(**kwargs)
        self.dbconn.create_function("django_extract", 2, _sqlite_extract)
        self.dbconn.create_function("django_date_trunc", 2, _sqlite_date_trunc)
        self.dbconn.create_function("regexp", 2, _sqlite_regexp)
        self.dbconn.create_function("django_format_dtdelta", 5, _sqlite_format_dtdelta)

    def create_cursor(self):
        try:
            self.cursors[self.cursor_id] = HachiProxyCursor(self.source, self.dbconn)
            self.cursor_id += 1
            return (self.cursor_id - 1)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            print tb
    def close(self):
        pass
#        self.dbconn.close()
    def rollback(self):
        self.dbconn.rollback()
    def commit(self):
        self.dbconn.commit()

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
#                raise Exception("Operation not contained in the admissable set!")
            check_token(token)
            asserts = self.asserts[test_oper]
            if not _check_args_assert(asserts, test_params, token):
                print "Error in %s" % self.source
                print "Constraint Error in %s" % self.source
                #raise Exception("Arguments failed constraints.")

            return self.cursors[cursor_id].execute(oper, parameters), None

        except Exception as e:
            import traceback
            print traceback.format_exc()
            raise e
    def cursor_executemany(self, cursor_id, token, operation, seq_of_parametrs):
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
#               raise Exception("Operation not contained in the admissable set!")
            asserts = self.asserts[test_oper]
            check_token(token)

            if not _check_args_assert(asserts, test_params, token):
                print "Constraint Error in %s" % self.source
                #raise Exception("Arguments failed constraints.")

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


def _sqlite_extract(lookup_type, dt):
    if dt is None:
        return None
    try:
        dt = util.typecast_timestamp(dt)
    except (ValueError, TypeError):
        return None
    if lookup_type == 'week_day':
        return (dt.isoweekday() % 7) + 1
    else:
        return getattr(dt, lookup_type)

def _sqlite_date_trunc(lookup_type, dt):
    try:
        dt = util.typecast_timestamp(dt)
    except (ValueError, TypeError):
        return None
    if lookup_type == 'year':
        return "%i-01-01 00:00:00" % dt.year
    elif lookup_type == 'month':
        return "%i-%02i-01 00:00:00" % (dt.year, dt.month)
    elif lookup_type == 'day':
        return "%i-%02i-%02i 00:00:00" % (dt.year, dt.month, dt.day)

def _sqlite_format_dtdelta(dt, conn, days, secs, usecs):
    try:
        dt = util.typecast_timestamp(dt)
        delta = datetime.timedelta(int(days), int(secs), int(usecs))
        if conn.strip() == '+':
            dt = dt + delta
        else:
            dt = dt - delta
    except (ValueError, TypeError):
        return None

    if isinstance(dt, datetime.datetime):
        rv = dt.strftime("%Y-%m-%d %H:%M:%S")
        if dt.microsecond:
            rv = "%s.%0.6d" % (rv, dt.microsecond)
    else:
        rv = dt.strftime("%Y-%m-%d")
    return rv

def _sqlite_regexp(re_pattern, re_string):
    import re
    try:
        return bool(re.search(re_pattern, re_string))
    except:
        return False

last_tid_hand = -1
last_tid_prox = -1
heap_hand = []
heap_prox = []

def seen_before(tid):
    global last_tid_hand, last_tid_prox, heap_hand, heap_prox
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
    tid = (token.dict["token_id_0"], token.dict["token_id_1"], token.dict["token_id_2"])
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
