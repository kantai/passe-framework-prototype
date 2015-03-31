"""
SQLite3 backend for django.

Python 2.4 requires pysqlite2 (http://pysqlite.org/).

Python 2.5 and later can use a pysqlite2 module or the sqlite3 module in the
standard library.
"""

import re, sys, datetime, Pyro4
import Pyro4.errors

from django.analysis.tracer import mark_sql_call, is_analysis_running
from django.analysis.persisted import db_uri

import django.conf

from django.db import utils
from django.db.backends import *
from django.db.backends.signals import connection_created
from django.db.backends.sqlite3.client import DatabaseClient
from django.db.backends.sqlite3.creation import DatabaseCreation
from django.db.backends.sqlite3.introspection import DatabaseIntrospection
from django.utils.safestring import SafeString
from django.htoken import set_token, get_token

import django.htoken.serializer
DB_SERIALIZER = django.htoken.serializer.Serializer() # I'm great at naming.

class DatabaseFeatures(BaseDatabaseFeatures):
    # SQLite cannot handle us only partially reading from a cursor's result set
    # and then writing the same rows to the database in another cursor. This
    # setting ensures we always read result sets fully into memory all in one
    # go.
    can_use_chunked_reads = False
    test_db_allows_multiple_connections = False
    supports_unspecified_pk = True
    supports_1000_query_parameters = False
    supports_mixed_date_datetime_comparisons = False

    def _supports_stddev(self):
        """Confirm support for STDDEV and related stats functions

        SQLite supports STDDEV as an extension package; so
        connection.ops.check_aggregate_support() can't unilaterally
        rule out support for STDDEV. We need to manually check
        whether the call works.
        """
        cursor = self.connection.cursor()
        cursor.execute('CREATE TABLE STDDEV_TEST (X INT)')
        try:
            cursor.execute('SELECT STDDEV(*) FROM STDDEV_TEST')
            has_support = True
        except utils.DatabaseError:
            has_support = False
        cursor.execute('DROP TABLE STDDEV_TEST')
        return has_support

class DatabaseOperations(BaseDatabaseOperations):
    def date_extract_sql(self, lookup_type, field_name):
        # sqlite doesn't support extract, so we fake it with the user-defined
        # function django_extract that's registered in connect(). Note that
        # single quotes are used because this is a string (and could otherwise
        # cause a collision with a field name).
        return "django_extract('%s', %s)" % (lookup_type.lower(), field_name)

    def date_interval_sql(self, sql, connector, timedelta):
        # It would be more straightforward if we could use the sqlite strftime
        # function, but it does not allow for keeping six digits of fractional
        # second information, nor does it allow for formatting date and datetime
        # values differently. So instead we register our own function that 
        # formats the datetime combined with the delta in a manner suitable 
        # for comparisons.
        return  u'django_format_dtdelta(%s, "%s", "%d", "%d", "%d")' % (sql, 
            connector, timedelta.days, timedelta.seconds, timedelta.microseconds)

    def date_trunc_sql(self, lookup_type, field_name):
        # sqlite doesn't support DATE_TRUNC, so we fake it with a user-defined
        # function django_date_trunc that's registered in connect(). Note that
        # single quotes are used because this is a string (and could otherwise
        # cause a collision with a field name).
        return "django_date_trunc('%s', %s)" % (lookup_type.lower(), field_name)

    def drop_foreignkey_sql(self):
        return ""

    def pk_default_value(self):
        return 'NULL'

    def quote_name(self, name):
        if name.startswith('"') and name.endswith('"'):
            return name # Quoting once is enough.
        return '"%s"' % name

    def no_limit_value(self):
        return -1

    def sql_flush(self, style, tables, sequences):
        # NB: The generated SQL below is specific to SQLite
        # Note: The DELETE FROM... SQL generated below works for SQLite databases
        # because constraints don't exist
        sql = ['%s %s %s;' % \
                (style.SQL_KEYWORD('DELETE'),
                 style.SQL_KEYWORD('FROM'),
                 style.SQL_FIELD(self.quote_name(table))
                 ) for table in tables]
        # Note: No requirement for reset of auto-incremented indices (cf. other
        # sql_flush() implementations). Just return SQL at this point
        return sql

    def year_lookup_bounds(self, value):
        first = '%s-01-01'
        second = '%s-12-31 23:59:59.999999'
        return [first % value, second % value]

    def convert_values(self, value, field):
        """SQLite returns floats when it should be returning decimals,
        and gets dates and datetimes wrong.
        For consistency with other backends, coerce when required.
        """
        internal_type = field.get_internal_type()
        if internal_type == 'DecimalField':
            return util.typecast_decimal(field.format_number(value))
        elif internal_type and internal_type.endswith('IntegerField') or internal_type == 'AutoField':
            return int(value)
        elif internal_type == 'DateField':            
            return util.typecast_date(value)
        elif internal_type == 'DateTimeField':
            return util.typecast_timestamp(value)
        elif internal_type == 'TimeField':
            return util.typecast_time(value)

        # No field, or the field isn't known to be a decimal or integer
        return value

class DatabaseWrapper(BaseDatabaseWrapper):
    vendor = 'sqlite'
    # SQLite requires LIKE statements to include an ESCAPE clause if the value
    # being escaped has a percent or underscore in it.
    # See http://www.sqlite.org/lang_expr.html for an explanation.
    operators = {
        'exact': '= %s',
        'iexact': "LIKE %s ESCAPE '\\'",
        'contains': "LIKE %s ESCAPE '\\'",
        'icontains': "LIKE %s ESCAPE '\\'",
        'regex': 'REGEXP %s',
        'iregex': "REGEXP '(?i)' || %s",
        'gt': '> %s',
        'gte': '>= %s',
        'lt': '< %s',
        'lte': '<= %s',
        'startswith': "LIKE %s ESCAPE '\\'",
        'endswith': "LIKE %s ESCAPE '\\'",
        'istartswith': "LIKE %s ESCAPE '\\'",
        'iendswith': "LIKE %s ESCAPE '\\'",
    }

    def __init__(self, *args, **kwargs):
        super(DatabaseWrapper, self).__init__(*args, **kwargs)

        self.features = DatabaseFeatures(self)
        self.ops = DatabaseOperations()
        self.client = DatabaseClient(self)
        self.creation = DatabaseCreation(self)
        self.introspection = DatabaseIntrospection(self)
        self.validation = BaseDatabaseValidation(self)

    def _sqlite_create_connection(self):
        self.connection = ConnectionProxy(django.conf.view_id)
        connection_created.send(sender=self.__class__, connection=self)

    def _cursor(self):
        if self.connection is None:
            self._sqlite_create_connection()
        return self.connection.cursor(factory=SQLiteCursorWrapper)

    def close(self):
        # If database is in memory, closing the connection destroys the
        # database. To prevent accidental data loss, ignore close requests on
        # an in-memory db.
        if self.settings_dict['NAME'] != ":memory:":
            BaseDatabaseWrapper.close(self)

class ConnectionProxy():
    def __init__(self, socket_postfix):
        # set up the actual connection
        self.socket_postfix = socket_postfix
        self.conn = Pyro4.Proxy(db_uri(socket_postfix))
        self.conn._pyroSerializer = DB_SERIALIZER 
    def cursor(self, factory = None):
        try:
            id = self.conn.create_cursor()
            new_cursor = SQLiteCursorProxy(self, id)
            if factory:
                return factory(new_cursor)
            return new_cursor
        except Pyro4.errors.CommunicationError, e:
            print db_uri(self.socket_postfix)
            raise e
    def commit(self):
        return self.conn.commit()
    def rollback(self):
        return self.conn.rollback()
    def close(self):
        return self.conn.close()

to_forward = ['callproc', 'close', 'execute',
              'executemany', 'fetchone', 'fetchmany', 'fetchall', 'nextset',
              'get_arraysize', 'setinputsizes', 'setoutputsizes']
attr_forward = ['lastrowid', 'rowcount', 'description']

class SQLiteCursorProxy():
    def __init__(self, conn_proxy, id):
        self.conn_proxy = conn_proxy
        self.id = id

    def __getattr__(self, name):
        # TODO: Pyro calling?
        if name in to_forward:
            def call_wrapper(*args, **kwargs):
                token = get_token()
                call = getattr(self.conn_proxy.conn, "cursor_%s" % name)
                result, new_token = call(self.id, token, *args, **kwargs)
                if new_token != None:
                    set_token(new_token)
                return result
            return call_wrapper
        if name in attr_forward:
            token = get_token()
            call = getattr(self.conn_proxy.conn, "cursor_get_%s" % name)
            result, new_token = call(self.id, token)
            if new_token != None:
                set_token(new_token)
            return result
        raise AttributeError


FORMAT_QMARK_REGEX = re.compile(r'(?<!%)%s')

class SQLiteCursorWrapper():
    """
    Django uses "format" style placeholders, but pysqlite2 uses "qmark" style.
    This fixes it -- but note that if you want to use a literal "%s" in a query,
    you'll need to use "%%s".
    """
    def __init__(self, wrapped_cursor):
        self.wrapped_cursor = wrapped_cursor

    def __getattr__(self, name):
        return getattr(self.wrapped_cursor, name)

    def execute(self, query, params=()):
        query = self.convert_query(query)
        if is_analysis_running():
            mark_sql_call(query, params)
        return self.wrapped_cursor.execute(query, params)
        
    def executemany(self, query, param_list):
        query = self.convert_query(query)
        if is_analysis_running():
            for params in param_list:
                mark_sql_call(query, params)

        return self.wrapped_cursor.executemany(query, param_list)
    
    def convert_query(self, query):
        return FORMAT_QMARK_REGEX.sub('?', query).replace('%%','%')

