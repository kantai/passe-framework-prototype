from optparse import make_option
import os
import re
import sys
import socket
import Pyro4, time

from django.core.management.base import BaseCommand, CommandError
from django.core.handlers.wsgi import WSGIHandler
from django.core.servers.basehttp import AdminMediaHandler, run, WSGIServerException
from django.utils import autoreload
from django.core.management import call_command
from django.contrib.sessions.server import fork_session_daemon
from django.contrib.auth.server import fork_auth_daemon
from django.db.proxy.pgsql_proxy import fork_off_db_proxies as fork_pgsql
from django.db.proxy.proxy import fork_off_db_proxies as fork_sqlite

from django.db.models.signals import pre_save as pre_save_signaler
from django.conf import settings
import threading

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

class Delegator():
    def __init__(self):
        self.lock = threading.Lock()
        self.cur_next = 0
    def get_next_worker_id(self):
        self.lock.acquire()
        rval = self.cur_next
        self.cur_next += 1
        self.lock.release()
        return rval

def start_delegator():
    from django.analysis.persisted import delegator_socket
    daemon = False
    try:
        local = Delegator()
        daemon = Pyro4.Daemon(unixsocket=delegator_socket())
        daemon.register(local, 'delegator')
        daemon.requestLoop()
    finally:
        if daemon:
            daemon.close()


class Command(BaseCommand):
    option_list = BaseCommand.option_list
    help = "Spawns helper processes for the PasseWS."
    args = '[optional worker number]'

    # Validation is called explicitly each time the server is reloaded.
    requires_model_validation = False

    def handle(self, worker=None, *args, **options):
        """
        Runs the server, (autoloader has been commented out for now)
        """
        if worker is None:
            worker = 0
        else:
            worker = int(worker)


        import django.analysis.tracer as tracer
        Pyro4.config.HMAC_KEY = 'deadbeef'
        to_kill = []
        settings.worker_id = 0
        try:

            if worker >= 2: # 
                pid = os.fork()
                if pid == 0:
                    start_delegator()
                    sys.exit(0)
                else:
                    to_kill += [pid]
            for i in range(1, worker):
                pid = os.fork()
                if pid != 0:
                    to_kill += [pid]
                else:
                    settings.worker_id = i
                    to_kill = []
                    break

            to_kill += [fork_auth_daemon()]
            self.stdout.write("Starting %s in run mode!\n" % settings.worker_id)
            if not hasattr(settings, 'HACHI_DB') or \
                    settings.HACHI_DB == "sqlite":
                fork_off_db_proxies = fork_sqlite
            else:
                fork_off_db_proxies = fork_pgsql
            to_kill += fork_off_db_proxies()
            while(True):
                time.sleep(1)
        finally:
            for pid_to_kill in to_kill:
                os.kill(pid_to_kill, 2) # SIGINT
