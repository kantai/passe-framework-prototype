Passe Web Framework
===================

Background and Caveats
----------------------

This code is part of the prototype implementation of the Passe system
described in the paper "Automating Isolation and Least Privilege in
Web Services" by Aaron Blankstein and Michael J. Freedman.

A lot of this code is inexplicably bears the name "Hachi". This was an
old name for the project, that has remained in the codebase.

**CAVEAT**: This prototype was used to evaluate the ability of the
project to run efficiently, play nicely with AppArmor, and effectively
generate invariants during the dynamic analysis phase. As such, it is
not a robust codebase and is not meant for production use. Certain
security parameters (such as the secret key used to MAC security
tokens) are hardcoded, compromising the security in real usage
scenarios. Furthermore, the constraint checker in the execution mode
**will not** halt database accesses that violates constraints, rather
it prints the violation to STDOUT.

Using this code
---------------

Getting Passe up and running on your machine is going to be a bit of
an involved process and usually requires somewhat detailed knowledge
of Django 1.4's loading and db syncing process and Python pathing
intricacies.

To successfully run the "analysis phase" of Passe, you will first need
to fetch and build the associated
[taint-tracking version of PyPy](https://github.com/kantai/passe-pypy-taint-tracking).
Secondly, Passe requires Postgres or SQLite3. Once you've got that sorted, you
will need to correctly set your `PYTHONPATH` such that Passe's libraries
are loaded, and your Django application's libraries are loaded.
Auto-generated scripts will assume that the analysis phase's paths are
the same as the execution phase's paths. So if any of your path
variables depend on your working directory, you may have to ensure
that you analyze and execute your application from the same working
directory.

Finally, the secret key used to MAC security token by the database proxy
and other trusted helpers is hardcoded in `htoken/__init__.py`. Obviously,
this is not secure. In production use, this key should be stored in a location
inaccessible to untrusted views, but accessible to the trusted components
(database proxy, dispatcher).

Navigating the Source Code
--------------------------

### Passe Dispatcher

* The dispatcher implementation is in the modifications to the Django
  dispatcher (django/core/handlers/base.py)
* During the execution phase, the handler will ad-hoc spawn middleware
  processes
* The logic of the dispatcher is contained in the `get_response()` function.
* The global variable `building_iframe` controls whether or not the JS
  shim extension is used for interposing on Javascript callbacks.
* The function call `is_analysis_running()` tells the dispatcher whether or
  not we are in the analysis mode or the execution mode.

### Passe Database Proxy

* Database proxies are implemented in django/db/proxy/*.py
* The relevant guard checking code is `check_token` and `_check_args_assert`
* During the analysis phase, special analysis backends are loaded, these are in
  django/db/backends/postgresql_psycopg2/analysis_base.py and
  django/db/backends/sqlite3/analysis_base.py
* During the run phase, the run_base.py backend is used instead, which sets up
  communication with the proxy.

### Passe Isolated Views and Tokens

* Isolated views are wrapped by the code in django/hviews/run.py
* These handle accepting connections from the dispatcher code
* Token management is handled by code in htoken/__init__.py

### Passe Analyzer and Configuration Generator

* The Passe analyzer is contained in django/analysis/tracer.py
* This code runs by installing itself as a tracer in `start_tracer`
* When the tracer sees important calls (database usage, new requests), it receives a
  callback which logs the database query and adds appropriate taints using the PyPy
  tainter.
* On exit, the `finally` branch in `start_tracer` completes the analysis and outputs
  all the Passe configuration files (inferred constraints, spawn scripts for views,
  and starter AppArmor profiles)

Installation
------------

1. Get Python 2.X, PIP, pgsql.
2. Get the modified taint tracking PyPy and build it for use by the
   analysis environment.
 - See (https://github.com/kantai/passe-pypy-taint-tracking)
3. pip install selenium pyyaml pyro4
 - libraries are required for BOTH execution environments
 - the old version of pyro is actually a dependency, because Passe
   plays some tricks to ensure that pyro4 is using a safe deserialization
   technique.
4. clone into repository
5. export PYTHONPATH=$(hachi-framework-toplevel-dir)
6. export HACHIPATH=$(hachi-framework-toplevel-dir)

Running Applications
--------------------

0. General hint: check out the benchmarking application's `settings.py` file.
1. Modify your settings.py:
   Engine should be the `pgsql_psycopg` option

   You can add fixtures to be loaded for the analysis phase with the
   config setting
   `ANALYSIS_FIXTURES = ['authtestdata.json']`
2. If it is a Django 1.4 app, it needs to have logging stuff removed,
   check what the sample app's `LOGGING` settings look like
3. Some middleware may be broken (one version of the CSRF middleware
   was broken by Passe)
4. Make sure your `PYTHONPATH` contains your application *and* the Passe
   library.
5. At this point, you can run `manage.py runserver --analyze` to
   begin the analysis phase. Submit some requests to the server.
6. Once finished (kill server with CTRL-C and wait for the merging of
   analysis) scripts and output will be placed in `/tmp/hachi_*`
7. The output scripts will execute your application with the Django
   test server. However, many environments will likely require some
   editing of these scripts. You will also need to be sure to run
   `syncdb` before trying to execute your application.

   You will have some starter AppArmor comnfiguration files
   (`/tmp/hachi_view_*.a`).  These will need to be modified to match some
   specifics of your OS, if you want to run Passe with AppArmor
   jails. You can also modify the default AppArmor configuration in
   the source code file (`django/analysis/persisted.py:create_apparmor_prof`).
   This function will spit out the Passe specific sockets required for
   communication, and some libraries that were required for my environment.
   You can add additional libraries that need to be loaded
   and given exec privileges.

   The `/tmp/django_analysis` file contains the inferred invariants for
   database queries.

   The `/tmp/hachi_spawn_script.sh` script will spawn all of the Passe
   views, and the Passe helper processes (the dispatcher, isolated
   middleware, and database proxy). This file may need to be modified
   for your particular deployment. To use gunicorn, for example, you
   need to be replace the `manage.py runserver` line with the startup
   call to gunicorn.

   The `/tmp/hachi_view_*` files are spawn scripts which run each Passe view
   in a separate process. They are named such that the associated AppArmor
   profile will be loaded if those profiles are loaded into AppArmor
   (via: `sudo apparmor_parser -C profile-name.a`)


   Spawning multiple workers for each view and helper requires a
   little bit more editing. Each view script accepts a commandline
   argument for it's worker ID, and so too does the spawnhelpers
   call -- so modify the hachi_spawn_script.sh to contain a loop like so:

     ```Shell
     for i in $(seq 0 1 $((PASSE_WORKERS - 1)))
     do
         /tmp/hachi_view_foo $i &
         /tmp/hachi_view_bar $i &
         python manage.py spawnhelpers $i &
     done
     gunicorn -w $PASSE_WORKERS -b 0.0.0.0:8000 foo.wsgi:application
     ```

   The benchmarking application in passe-sample-apps contains a modified
   hachi_spawn_script.sh used to spawn multiple workers.

8. Sometimes, the interaction between the path variables and working
   directories requires that you explicity tell Passe where your settings.py
   file is located. This can be done by setting the environment variable,
   HACHISETTINGS, to the Python module name (e.g., Foo.Bar.settings)
