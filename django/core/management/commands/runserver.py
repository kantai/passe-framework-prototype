from optparse import make_option
import os
import re
import sys
import socket
import Pyro4

from django.core.management.base import BaseCommand, CommandError
from django.core.handlers.wsgi import WSGIHandler
from django.core.servers.basehttp import AdminMediaHandler, run, WSGIServerException
from django.utils import autoreload
from django.core.management import call_command
from django.contrib.sessions.server import fork_session_daemon
from django.contrib.auth.server import fork_auth_daemon
from django.db.proxy.proxy import fork_off_db_proxies
from django.db.models.signals import pre_save as pre_save_signaler
from django.conf import settings

naiveip_re = re.compile(r"""^(?:
(?P<addr>
    (?P<ipv4>\d{1,3}(?:\.\d{1,3}){3}) |         # IPv4 address
    (?P<ipv6>\[[a-fA-F0-9:]+\]) |               # IPv6 address
    (?P<fqdn>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*) # FQDN
):)?(?P<port>\d+)$""", re.X)
DEFAULT_PORT = "8000"

USED_NUMBERS = set()
import random
gen_guess = lambda : random.randint(2**10,2**20)

def pre_save_rejigger(**kwargs):
    sender_class, instance, raw = (kwargs["sender"], kwargs["instance"], kwargs["raw"])
    global USED_NUMBERS, gen_guess
    if raw or instance.id is not None:
        return
    pk = gen_guess()
    while pk in USED_NUMBERS:
        pk = gen_guess()
    USED_NUMBERS.add(pk)

    from django.analysis.tracer import add_view_magic
    add_view_magic(pk)
    instance.id = pk

def disable_transaction_methods():
    transaction.commit = nop
    transaction.rollback = nop
    transaction.enter_transaction_management = nop
    transaction.leave_transaction_management = nop
    transaction.managed = nop

def connections_support_transactions():
    """
    Returns True if all connections support transactions.  This is messy
    because 2.4 doesn't support any or all.
    """
    return all(conn.features.supports_transactions
        for conn in connections.all())

def restore_transaction_methods():
    transaction.commit = real_commit
    transaction.rollback = real_rollback
    transaction.enter_transaction_management = real_enter_transaction_management
    transaction.leave_transaction_management = real_leave_transaction_management
    transaction.managed = real_managed
def dependency_ordered(test_databases, dependencies):
    """Reorder test_databases into an order that honors the dependencies
    described in TEST_DEPENDENCIES.
    """
    ordered_test_databases = []
    resolved_databases = set()
    while test_databases:
        changed = False
        deferred = []

        while test_databases:
            signature, (db_name, aliases) = test_databases.pop()
            dependencies_satisfied = True
            for alias in aliases:
                if alias in dependencies:
                    if all(a in resolved_databases for a in dependencies[alias]):
                        # all dependencies for this alias are satisfied
                        dependencies.pop(alias)
                        resolved_databases.add(alias)
                    else:
                        dependencies_satisfied = False
                else:
                    resolved_databases.add(alias)

            if dependencies_satisfied:
                ordered_test_databases.append((signature, (db_name, aliases)))
                changed = True
            else:
                deferred.append((signature, (db_name, aliases)))

        if not changed:
            raise ImproperlyConfigured("Circular dependency in TEST_DEPENDENCIES")
        test_databases = deferred
    return ordered_test_databases


from django.db import (transaction, connection, connections, DEFAULT_DB_ALIAS,
                       reset_queries)
real_commit = transaction.commit
real_rollback = transaction.rollback
real_enter_transaction_management = transaction.enter_transaction_management
real_leave_transaction_management = transaction.leave_transaction_management
real_managed = transaction.managed

def nop(*args, **kwargs):
    return


class BaseRunserverCommand(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--ipv6', '-6', action='store_true', dest='use_ipv6', default=False,
            help='Tells Django to use a IPv6 address.'),
        make_option('--noreload', action='store_false', dest='use_reloader', default=True,
            help='Tells Django to NOT use the auto-reloader.'),
        make_option('--analyze', action='store_true', dest='hachi_analyze', default=False,
            help='Run as Hachi analysis phase'),
    )
    help = "Starts a lightweight Web server for development."
    args = '[optional port number, or ipaddr:port]'

    # Validation is called explicitly each time the server is reloaded.
    requires_model_validation = False

    def get_handler(self, *args, **options):
        """
        Returns the default WSGI handler for the runner.
        """
        return WSGIHandler()

    def handle(self, addrport='', *args, **options):
        settings.worker_id = 0 # always single-worker runserver!

        self.use_ipv6 = options.get('use_ipv6')
        if self.use_ipv6 and not socket.has_ipv6:
            raise CommandError('Your Python does not support IPv6.')
        if args:
            raise CommandError('Usage is runserver %s' % self.args)
        self._raw_ipv6 = False
        if not addrport:
            self.addr = ''
            self.port = DEFAULT_PORT
        else:
            m = re.match(naiveip_re, addrport)
            if m is None:
                raise CommandError('"%s" is not a valid port number '
                                   'or address:port pair.' % addrport)
            self.addr, _ipv4, _ipv6, _fqdn, self.port = m.groups()
            if not self.port.isdigit():
                raise CommandError("%r is not a valid port number." % self.port)
            if self.addr:
                if _ipv6:
                    self.addr = self.addr[1:-1]
                    self.use_ipv6 = True
                    self._raw_ipv6 = True
                elif self.use_ipv6 and not _fqdn:
                    raise CommandError('"%s" is not a valid IPv6 address.' % self.addr)
        if not self.addr:
            self.addr = self.use_ipv6 and '::1' or '127.0.0.1'
            self._raw_ipv6 = bool(self.use_ipv6)
        self.run(*args, **options)

    def run(self, *args, **options):
        """
        Runs the server, (autoloader has been commented out for now)
        """
        use_reloader = options.get('use_reloader', False)
        import django.analysis.tracer as tracer
        Pyro4.config.HMAC_KEY = 'deadbeef'
        if options.get('hachi_analyze'):
            self.create_test_db()
            # register signal callback...
            pre_save_signaler.connect(pre_save_rejigger) 
        to_kill = []
        try:
            if options.get('hachi_analyze'):
                try:
                    tracer.start_tracer(self.inner_run, args, options)
                finally:
                    self.destroy_test_db()
            else:
                self.inner_run(*args, **options)
        finally:
            for pid_to_kill in to_kill:
                os.kill(pid_to_kill, 2) # SIGINT

    def create_test_db(self):
        self.old_config = self._setup_test_db()
        self._fixture_setup()
    def destroy_test_db(self):
        self._fixture_teardown()
        self.teardown_databases(self.old_config)

    def teardown_databases(self, old_config):
        from django.db import connections
        old_names, mirrors = old_config
        # Point all the mirrors back to the originals
        for alias, old_name in mirrors:
            connections[alias].settings_dict['NAME'] = old_name
        # Destroy all the non-mirror databases
        for connection, old_name, destroy in old_names:
            if destroy:
                connection.creation.destroy_test_db(old_name, 1)
            else:
                connection.settings_dict['NAME'] = old_name

    def _fixture_teardown(self):
        pass

    def _fixture_setup(self):
        # If the test case has a multi_db=True flag, flush all databases.
        # Otherwise, just flush default.

        databases = [DEFAULT_DB_ALIAS]
        for db in databases:
            call_command('flush', verbosity=0, interactive=False, database=db)
            # We have to use this slightly awkward syntax due to the fact
            # that we're using *args and **kwargs together.
            call_command('loaddata', *settings.ANALYSIS_FIXTURES, **{'verbosity': 1, 'database': db})

    def _setup_test_db(self):
        from django.db import connections, DEFAULT_DB_ALIAS

        # First pass -- work out which databases actually need to be created,
        # and which ones are test mirrors or duplicate entries in DATABASES
        mirrored_aliases = {}
        test_databases = {}
        dependencies = {}
        for alias in connections:
            connection = connections[alias]
            if connection.settings_dict['TEST_MIRROR']:
                # If the database is marked as a test mirror, save
                # the alias.
                mirrored_aliases[alias] = connection.settings_dict['TEST_MIRROR']
            else:
                # Store a tuple with DB parameters that uniquely identify it.
                # If we have two aliases with the same values for that tuple,
                # we only need to create the test database once.
                item = test_databases.setdefault(
                    connection.creation.test_db_signature(),
                    (connection.settings_dict['NAME'], [])
                )
                item[1].append(alias)

                if 'TEST_DEPENDENCIES' in connection.settings_dict:
                    dependencies[alias] = connection.settings_dict['TEST_DEPENDENCIES']
                else:
                    if alias != DEFAULT_DB_ALIAS:
                        dependencies[alias] = connection.settings_dict.get('TEST_DEPENDENCIES', [DEFAULT_DB_ALIAS])

        # Second pass -- actually create the databases.
        old_names = []
        mirrors = []
        for signature, (db_name, aliases) in dependency_ordered(test_databases.items(), dependencies):
            # Actually create the database for the first connection
            connection = connections[aliases[0]]
            old_names.append((connection, db_name, True))
            test_db_name = connection.creation.create_test_db(2, autoclobber=True)
            for alias in aliases[1:]:
                connection = connections[alias]
                if db_name:
                    old_names.append((connection, db_name, False))
                    connection.settings_dict['NAME'] = test_db_name
                else:
                    # If settings_dict['NAME'] isn't defined, we have a backend where
                    # the name isn't important -- e.g., SQLite, which uses :memory:.
                    # Force create the database instead of assuming it's a duplicate.
                    old_names.append((connection, db_name, True))
                    connection.creation.create_test_db(2, autoclobber=True)

        for alias, mirror_alias in mirrored_aliases.items():
            mirrors.append((alias, connections[alias].settings_dict['NAME']))
            connections[alias].settings_dict['NAME'] = connections[mirror_alias].settings_dict['NAME']

        return old_names, mirrors



    def inner_run(self, *args, **options):
        from django.conf import settings
        from django.utils import translation

        shutdown_message = options.get('shutdown_message', '')
        quit_command = (sys.platform == 'win32') and 'CTRL-BREAK' or 'CONTROL-C'

        self.stdout.write("Validating models...\n\n")
        self.validate(display_num_errors=True)
        self.stdout.write((
            "Hachi :) version %(version)s, using settings %(settings)r\n"
            "Development server is running at http://%(addr)s:%(port)s/\n"
            "Quit the server with %(quit_command)s.\n"
        ) % {
            "version": self.get_version(),
            "settings": settings.SETTINGS_MODULE,
            "addr": self._raw_ipv6 and '[%s]' % self.addr or self.addr,
            "port": self.port,
            "quit_command": quit_command,
        })
        # django.core.management.base forces the locale to en-us. We should
        # set it up correctly for the first request (particularly important
        # in the "--noreload" case).
        translation.activate(settings.LANGUAGE_CODE)

        try:
            handler = self.get_handler(*args, **options)
            run(self.addr, int(self.port), handler, ipv6=self.use_ipv6)
        except WSGIServerException, e:
            # Use helpful error messages instead of ugly tracebacks.
            ERRORS = {
                13: "You don't have permission to access that port.",
                98: "That port is already in use.",
                99: "That IP address can't be assigned-to.",
            }
            try:
                error_text = ERRORS[e.args[0].args[0]]
            except (AttributeError, KeyError):
                error_text = str(e)
            sys.stderr.write(self.style.ERROR("Error: %s" % error_text) + '\n')
            # Need to use an OS exit because sys.exit doesn't work in a thread
            os._exit(1)
        except KeyboardInterrupt:
            if shutdown_message:
                self.stdout.write("%s\n" % shutdown_message)
            sys.exit(0)

class Command(BaseRunserverCommand):
    option_list = BaseRunserverCommand.option_list + (
        make_option('--adminmedia', dest='admin_media_path', default='',
            help='Specifies the directory from which to serve admin media.'),
    )

    def get_handler(self, *args, **options):
        """
        Serves admin media like old-school (deprecation pending).
        """
        handler = super(Command, self).get_handler(*args, **options)
        return AdminMediaHandler(handler, options.get('admin_media_path', ''))
