import base64
from datetime import datetime, timedelta
import pickle
import shutil
import tempfile

from django.conf import settings
#from django.contrib.sessions.backends.db import SessionStore as DatabaseSession
#from django.contrib.sessions.backends.cache import SessionStore as CacheSession
#from django.contrib.sessions.backends.cached_db import SessionStore as CacheDBSession
#from django.contrib.sessions.backends.file import SessionStore as FileSession
from django.contrib.sessions.models import Session
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpResponse
from django.test import TestCase, RequestFactory
from django.utils import unittest
from django.utils.hashcompat import md5_constructor

# TODO: write better tests for sessions :(
