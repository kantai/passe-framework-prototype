from django.core.management.base import BaseCommand
from optparse import make_option
from django.contrib.sessions.server import fork_session_daemon
from django.contrib.auth.server import fork_auth_daemon
from django.analysis import tracer

import sys, os
import Pyro4

class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--noinput', action='store_false', dest='interactive', default=True,
            help='Tells Django to NOT prompt the user for input of any kind.'),
        make_option('--failfast', action='store_true', dest='failfast', default=False,
            help='Tells Django to stop running the test suite after first failed test.'),
        make_option('--analyze', action='store_true', dest='hachi_analyze', default=False,
            help='Tells Hachi to run tests in analysis mode.')
    )
    help = 'Runs the test suite for the specified applications, or the entire site if no apps are specified.'
    args = '[appname ...]'

    requires_model_validation = False

    def handle(self, *test_labels, **options):
        from django.conf import settings
        from django.test.utils import get_runner

        verbosity = int(options.get('verbosity', 1))
        interactive = options.get('interactive', True)
        failfast = options.get('failfast', False)

        if options.get('hachi_analyze'):
            from django.test.simple import HachiSuiteRunner
            TestRunner = HachiSuiteRunner
        else:
            TestRunner = get_runner(settings)

        Pyro4.config.HMAC_KEY = 'deadbeef'

        sess_pid = fork_session_daemon()
        auth_pid = fork_auth_daemon()

        failures = None
        try:
            if hasattr(TestRunner, 'func_name'):
                # Pre 1.2 test runners were just functions,
                # and did not support the 'failfast' option.
                import warnings
                warnings.warn(
                    'Function-based test runners are deprecated. Test runners should be classes with a run_tests() method.',
                    DeprecationWarning
                    )
                failures = TestRunner(test_labels, verbosity=verbosity, interactive=interactive)
            else:
                test_runner = TestRunner(verbosity=verbosity, interactive=interactive, failfast=failfast)
                failures = tracer.start_tracer(test_runner.run_tests, [test_labels], {})
        finally:
            os.kill(sess_pid, 2)
            os.kill(auth_pid, 2) # SIGINT
            if failures:
                sys.exit(bool(failures))
            
