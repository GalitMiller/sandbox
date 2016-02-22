# -*- coding: utf-8 -*-

import os

from flask import Flask
from flask.ext.cache import Cache
from flask.ext.celery import Celery
from flask.ext.login import LoginManager
from flask.ext.restless import APIManager
from flask.ext.migrate import Migrate

from logging.config import dictConfig

from .db import db
from .users.sessions import BricataSecureCookieSessionInterface

# Application commons ---------------------------------------------------------
app = Flask(__name__)

# Set a secret key to enable the Flask session cookies.
# @TODO: Read secret key from file, or generate random value and store it in
# file to read later, to allow persistence of session between server restarts.
app.secret_key = os.urandom(24)

app.session_interface = BricataSecureCookieSessionInterface()

# Load the default configuration from app/config.py.
# @TODO: Add support for configuration directory (conf.d).
app.config.from_object('app.config')

# Load the file specified by the APP_CONFIG_FILE environment variable.
# Variables defined here will override those in the default configuration.
app.config.from_envvar('APP_CONFIG_FILE', silent=True)

# Logging ---------------------------------------------------------------------
if not os.path.exists(app.config['LOG_ROOT']):
    os.makedirs(app.config['LOG_ROOT'])

dictConfig(app.config['LOGGING'])

# DB --------------------------------------------------------------------------
db.app = app
db.init_app(app)

# Migrations ------------------------------------------------------------------
migrate = Migrate(app, db)

# Caching ---------------------------------------------------------------------
cache = Cache(app)

# Celery ----------------------------------------------------------------------
celery = Celery(app)

# Login manager ---------------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."

# API -------------------------------------------------------------------------
api_manager = APIManager()

# Autodiscovery ---------------------------------------------------------------
from .utils.modules import autodiscover
from . import views

autodiscovered = ['models', 'loaders', ]
for module_name in autodiscovered:
    autodiscover(module_name, app.config['PACKAGE_ROOT'])
