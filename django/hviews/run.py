import sys, importlib, cPickle
import imp, os

def my_import(name):
    m = __import__(name)
    for n in name.split(".")[1:]:
        m = getattr(m, n)
    return m

def main(settings_module, view_id, worker_id = 0):
    import django.hviews as hviews
    settings_str = os.environ.get("HACHISETTINGS", "settings")
    settings = my_import(settings_str)

#    settings = imp.find_module(settings_str)
#    import settings
#    settings = importlib.import_module(settings_module)
    import django.core.management as manage
    manage.setup_environ(settings)
    import django.conf
    django.conf.settings.worker_id = 0
    for w_id in range(1, worker_id):
        pid = os.fork()
        if pid == 0:
            django.conf.settings.worker_id = w_id
            break

    hviews.run_view_server(view_id)

if __name__ == "__main__":
#    f = open("/tmp/hachi_sys_path")
#    sys.path, settings_module = cPickle.load(f)
#    f.close()
    sys.path.append(os.getcwd())
    view_id = sys.argv[1]
    if len(sys.argv) > 2:
        worker_id = int(sys.argv[2])
    else:
        worker_id = 0
    main('foo', view_id, worker_id)
