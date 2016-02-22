# -*- coding: utf-8 -*-

import inspect
import itertools
import logging
import operator

from flask import render_template
from flask.ext.restless import url_for as url_for_resource
from flask.ext.login import login_required

from app import app
from app.db import db
from app.utils.modules import autodiscover


LOG = logging.getLogger(__name__)


@app.route('/')
@app.route('/index')
@login_required
def index():

    def is_model(item):
        return (inspect.isclass(item) and issubclass(item, db.Model))

    modules = autodiscover('models', app.config['PACKAGE_ROOT'])
    members = map(inspect.getmembers, modules)
    members = map(operator.itemgetter(1), itertools.chain(*members))
    resources = filter(is_model, members)

    links = [
        (x.__name__, url_for_resource(x))
        for x in resources
    ]
    return render_template('index.html', title='Home', links=links)
