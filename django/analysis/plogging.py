import Pyro4
Pyro4.config.HMAC_KEY = 'deadbeef'
import os, threading
from Queue import Queue

socket = "/tmp/passe_logger.sock"
uri = "PYRO:logger@./u:%s" % socket


proxy = None
pid = None

def plog(tag, time):
    global proxy, pid
    if proxy == None or os.getpid() != pid:
        pid = os.getpid()
        proxy = Pyro4.Proxy(uri)
    proxy.log(tag, time)

class LogServer:
    def __init__(self):
        self.queue = Queue()
    def log(self, tag, time):
        self.queue.put((tag, time))

def run_log_server():
    server = LogServer()
    
    daemon = Pyro4.Daemon(unixsocket=socket)
    daemon.register(server, 'logger')
    daemon_thread = threading.Thread(target = daemon.requestLoop)
    daemon_thread.start()
    q = server.queue
    logFile = open('/tmp/passe_log', 'w')
    count = 0

    while(True):
        count += 1
        item = q.get()
        logFile.write('%s,%s\n' % item)
        if count % 20 == 0 or item[0] == 'req_finished':
            logFile.flush()
            os.fsync(logFile.fileno())
        q.task_done()

if __name__ == "__main__":
    run_log_server()
