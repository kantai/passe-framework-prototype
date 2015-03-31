"""
PostgreSQL database backend for Django.

Requires psycopg 2: http://initd.org/projects/psycopg2
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
