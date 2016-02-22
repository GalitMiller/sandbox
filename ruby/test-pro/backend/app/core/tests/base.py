# -*- coding: utf-8 -*-

import os
import unittest

from app import app, cache
from app.db import db


class AppBaseTestCase(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

        app.config['CACHE_ENABLED'] = False
        cache.init_app(app, config={'CACHE_TYPE': 'null'})

        db.session.remove()

        with app.test_request_context():
            db.create_all(bind=None)

        self.client = app.test_client(self)

    def tearDown(self):
        db.session.remove()
        db.drop_all(bind=None)
        self._remove_log_files()

    def _remove_log_files(self):
        filenames = [app.config['LOG_FILE'], app.config['SENSOR_LOG_FILE'], ]

        for filename in filenames:
            if os.path.exists(filename):
                try:
                    os.remove(filename)
                except OSError:
                    pass
