"""
PostgreSQL database backend for Django.

Requires psycopg 2: http://initd.org/projects/psycopg2
"""

import sys, Pyro4
from django.analysis.tracer import mark_sql_call, is_analysis_running
from django.analysis.persisted import db_uri
from django.htoken import set_token, get_token

import django.conf

from django.db import utils
from django.db.backends import *
from django.db.backends.signals import connection_created
from django.db.backends.postgresql.operations import DatabaseOperations as PostgresqlDatabaseOperations
from django.db.backends.postgresql.client import DatabaseClient
from django.db.backends.postgresql.creation import DatabaseCreation
from django.db.backends.postgresql.version import get_version
from django.db.backends.postgresql_psycopg2.introspection import DatabaseIntrospection
from django.utils.safestring import SafeUnicode, SafeString

try:
    import psycopg2 as Database
    import psycopg2.extensions
except ImportError, e:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("Error loading psycopg2 module: %s" % e)

import django.htoken.serializer
DB_SERIALIZER = django.htoken.serializer.Serializer() # I'm great at naming.

DatabaseError = Database.DatabaseError
IntegrityError = Database.IntegrityError

class CursorWrapper(object):
    """
    A thin wrapper around psycopg2's normal cursor class so that we can catch
    particular exception instances and reraise them with the right types.
    """

    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, query, args=None):
        # NOTE : This is the separation / injection point...?
        try:
            return self.cursor.execute(query, args)
        except Database.IntegrityError, e:
            raise utils.IntegrityError, utils.IntegrityError(*tuple(e)), sys.exc_info()[2]
        except Database.DatabaseError, e:
            raise utils.DatabaseError, utils.DatabaseError(*tuple(e)), sys.exc_info()[2]

    def executemany(self, query, args):
        try:
            return self.cursor.executemany(query, args)
        except Database.IntegrityError, e:
            raise utils.IntegrityError, utils.IntegrityError(*tuple(e)), sys.exc_info()[2]
        except Database.DatabaseError, e:
            raise utils.DatabaseError, utils.DatabaseError(*tuple(e)), sys.exc_info()[2]

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        else:
            return getattr(self.cursor, attr)

    def __iter__(self):
        return iter(self.cursor)

class DatabaseFeatures(BaseDatabaseFeatures):
    needs_datetime_string_cast = False
    can_return_id_from_insert = False
    requires_rollback_on_dirty_transaction = True
    has_real_datatype = True
    can_defer_constraint_checks = True

class DatabaseOperations(PostgresqlDatabaseOperations):
    def last_executed_query(self, cursor, sql, params):
        # With psycopg2, cursor objects have a "query" attribute that is the
        # exact query sent to the database. See docs here:
        # http://www.initd.org/tracker/psycopg/wiki/psycopg2_documentation#postgresql-status-message-and-executed-query
        return cursor.query

    def return_insert_id(self):
        return "RETURNING %s", ()

class DatabaseWrapper(BaseDatabaseWrapper):
    vendor = 'postgresql'
    operators = {
        'exact': '= %s',
        'iexact': '= UPPER(%s)',
        'contains': 'LIKE %s',
        'icontains': 'LIKE UPPER(%s)',
        'regex': '~ %s',
        'iregex': '~* %s',
        'gt': '> %s',
        'gte': '>= %s',
        'lt': '< %s',
        'lte': '<= %s',
        'startswith': 'LIKE %s',
        'endswith': 'LIKE %s',
        'istartswith': 'LIKE UPPER(%s)',
        'iendswith': 'LIKE UPPER(%s)',
    }

    def __init__(self, *args, **kwargs):
        super(DatabaseWrapper, self).__init__(*args, **kwargs)

        self.features = DatabaseFeatures(self)
        autocommit = self.settings_dict["OPTIONS"].get('autocommit', False)
        self.features.uses_autocommit = autocommit
        self._set_isolation_level(int(not autocommit))
        self.ops = DatabaseOperations(self)
        self.client = DatabaseClient(self)
        self.creation = DatabaseCreation(self)
        self.introspection = DatabaseIntrospection(self)
        self.validation = BaseDatabaseValidation(self)

    def _cursor(self):
        new_connection = False
        set_tz = False
        settings_dict = self.settings_dict
        if self.connection is None:
            new_connection = True
            set_tz = settings_dict.get('TIME_ZONE')
            import django.conf
            self.connection = ConnectionProxy(django.conf.view_id)
            self.connection.set_isolation_level(self.isolation_level)
            connection_created.send(sender=self.__class__, connection=self)
        cursor = self.connection.cursor()
#        cursor.tzinfo_factory = None
        if new_connection:
            if set_tz:
                pass
#                cursor.execute("SET TIME ZONE %s", [settings_dict['TIME_ZONE']])
            if not hasattr(self, '_version'):
                self.__class__._version = (8,4) #get_version(cursor)
            if self._version[0:2] < (8, 0):
                # No savepoint support for earlier version of PostgreSQL.
                self.features.uses_savepoints = False
            if self.features.uses_autocommit:
                if self._version[0:2] < (8, 2):
                    # FIXME: Needs extra code to do reliable model insert
                    # handling, so we forbid it for now.
                    from django.core.exceptions import ImproperlyConfigured
                    raise ImproperlyConfigured("You cannot use autocommit=True with PostgreSQL prior to 8.2 at the moment.")
                else:
                    # FIXME: Eventually we're enable this by default for
                    # versions that support it, but, right now, that's hard to
                    # do without breaking other things (#10509).
                    self.features.can_return_id_from_insert = True
        return CursorWrapper(cursor)

    def _enter_transaction_management(self, managed):
        """
        Switch the isolation level when needing transaction support, so that
        the same transaction is visible across all the queries.
        """
        if self.features.uses_autocommit and managed and not self.isolation_level:
            self._set_isolation_level(1)

    def _leave_transaction_management(self, managed):
        """
        If the normal operating mode is "autocommit", switch back to that when
        leaving transaction management.
        """
        if self.features.uses_autocommit and not managed and self.isolation_level:
            self._set_isolation_level(0)

    def _set_isolation_level(self, level):
        """
        Do all the related feature configurations for changing isolation
        levels. This doesn't touch the uses_autocommit feature, since that
        controls the movement *between* isolation levels.
        """
        assert level in (0, 1)
        try:
            if self.connection is not None:
                self.connection.set_isolation_level(level)
        finally:
            self.isolation_level = level
            self.features.uses_savepoints = bool(level)

    def _commit(self):
        if self.connection is not None:
            try:
                return self.connection.commit()
            except Database.IntegrityError, e:
                raise utils.IntegrityError, utils.IntegrityError(*tuple(e)), sys.exc_info()[2]

to_forward = ['callproc', 'close', 'execute',
              'executemany', 'fetchone', 'fetchmany', 'fetchall', 'nextset',
              'get_arraysize', 'setinputsizes', 'setoutputsizes']
attr_forward = ['lastrowid', 'rowcount', 'description']

class CursorProxy():
    def __init__(self, conn_proxy, id):
        self.conn_proxy = conn_proxy
        self.id = id
        self.query = None

    def __getattr__(self, name):
        # TODO: Pyro calling?
        if name in to_forward:
            def call_wrapper(*args, **kwargs):
                if name == 'execute' or name == 'executemany':
                    self.query = args[0]
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
    def __del__(self):
        self.conn_proxy.conn.destroy_cursor(self.id)


class ConnectionProxy():
    def __init__(self, socket_postfix):
        # set up the actual connection
        self.socket_postfix = socket_postfix
        self.conn = Pyro4.Proxy(db_uri(socket_postfix))
        self.conn._pyroSerializer = DB_SERIALIZER 
    def cursor(self, factory = None):
        id = self.conn.create_cursor()
        new_cursor = CursorProxy(self, id)
        if factory:
            return factory(new_cursor)
        return new_cursor
    def commit(self):
        return self.conn.commit()
    def rollback(self):
        return self.conn.rollback()
    def close(self):
        return self.conn.close()
    def set_isolation_level(self, level):
        return self.conn.set_isolation_level(level)
