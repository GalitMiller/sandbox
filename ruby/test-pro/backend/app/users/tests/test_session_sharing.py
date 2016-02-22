# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import urllib

from app.core.tests.base import AppBaseTestCase
from app.db import db
from app.users.sessions import make_session_cookie
from app.users.models import User


class SessionSharingTestCase(AppBaseTestCase):

    def setUp(self):
        super(SessionSharingTestCase, self).setUp()
        self._init_data()

    def _init_data(self):
        user = User(
            login='john',
            email='john@example.com',
            password="foobar",
            name="John Doe",
        )
        db.session.add(user)
        db.session.commit()

    def test_redirect_to_login_page_when_queried_root_without_ruby_cookie(self):
        response = self.client.get("/index")
        self.assertEqual(response.status_code, 302)

        query = urllib.urlencode({'next': "/index"})
        location = "http://localhost/users/login?" + query
        self.assertEqual(response.location, location)

    def test_auth_error_when_queried_without_ruby_cookie(self):
        """
        When API is queried without authorization, then error must be returned,
        not a redirect to a page, to avoid returning of incorrect data to
        caller.
        """
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 401)

    def test_auth_error_with_invalid_session_cookie(self):
        """
        When API is queried with invalid cookie, then error must be returned,
        not a redirect to a page, to avoid returning of incorrect data to
        caller.
        """
        self.client.set_cookie('localhost', '_bricata_session', 'foobar')
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 401)

    def test_no_redirect_with_valid_session_cookie(self):
        cookie = make_session_cookie(user_id=1)
        self.client.set_cookie('localhost', '_bricata_session', cookie)
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 200)

    def test_login_allows_access_to_api(self):
        # Try without login
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 401)

        # Login
        response = self.client.get('/users/login')
        self.assertEqual(response.status_code, 200)

        data = {'username': 'john', }
        login_response = self.client.post('/users/login', data=data)
        self.assertEqual(login_response.status_code, 302)

        # Try again: must pass
        cookie = make_session_cookie(user_id=1)
        self.client.set_cookie('localhost', '_bricata_session', cookie)
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 200)

        # Logout
        response = self.client.get('/users/logout')
        self.assertEqual(response.status_code, 302)

        # Try without login again
        response = self.client.get('/api/v1/policies')
        self.assertEqual(response.status_code, 401)

    def test_login_allows_access_to_current_user(self):
        # Try without cookie: must fail
        response = self.client.get('/api/v1/current_user')
        self.assertEqual(response.status_code, 401)

        # Try with cookie: must pass
        cookie = make_session_cookie(user_id=1)
        self.client.set_cookie('localhost', '_bricata_session', cookie)
        response = self.client.get('/api/v1/current_user')
        self.assertEqual(response.status_code, 200)
