"""
SQLite3 backend for django.

Python 2.4 requires pysqlite2 (http://pysqlite.org/).

Python 2.5 and later can use a pysqlite2 module or the sqlite3 module in the
standard library.
"""

import re
import sys
import datetime

from django.analysis.tracer import mark_sql_call, is_analysis_running

if is_analysis_running():
    import analysis_base as base
    DatabaseFeatures = base.DatabaseFeatures
    DatabaseOperations = base.DatabaseFeatures
    DatabaseWrapper = base.DatabaseWrapper
else:
    import run_base as base
    DatabaseFeatures = base.DatabaseFeatures
    DatabaseOperations = base.DatabaseFeatures
    DatabaseWrapper = base.DatabaseWrapper
