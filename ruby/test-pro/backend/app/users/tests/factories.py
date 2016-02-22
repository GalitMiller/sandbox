# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from factory import alchemy, Iterator, LazyAttribute, post_generation
from factory.fuzzy import FuzzyAttribute
from faker import Faker

from app.db import db

from ..constants import USER_ROLES
from ..models import User


FAKE = Faker()


class UserFactory(alchemy.SQLAlchemyModelFactory):
    name = FuzzyAttribute(FAKE.name)
    login = FuzzyAttribute(FAKE.user_name)
    email = LazyAttribute(
        lambda o: "{login}@{domain}".format(
            login=o.login,
            domain=FAKE.free_email_domain(),
        )
    )
    password = FuzzyAttribute(FAKE.password)
    role = Iterator(
        USER_ROLES._asdict().values()
    )

    @post_generation
    def apply_password(self, create, extracted, **kwargs):
        self.set_password(self.password)

    class Meta:
        model = User
        sqlalchemy_session = db.session
