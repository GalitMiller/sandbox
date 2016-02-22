# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from app.core.tests.base import AppBaseTestCase
from app.db import db

from .. models import User


class UserTestCase(AppBaseTestCase):

    def test_make_unique_login(self):
        user = User(
            login='john',
            email='john@example.com',
            password="foobar",
            name="John Doe",
        )
        db.session.add(user)
        db.session.commit()

        login = User.make_unique_login('john')
        self.assertNotEqual(login, 'john')

        user = User(
            login=login,
            email='susan@example.com',
            password="foobaz",
            name="John Doe",
        )
        db.session.add(user)
        db.session.commit()

        new_login = User.make_unique_login('john')
        self.assertNotEqual(new_login, 'john')
        self.assertNotEqual(new_login, login)
