# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytz
import random

from celery.utils import uuid as celery_uuid
from factory import (
    alchemy, Sequence, Iterator, LazyAttribute, lazy_attribute,
    post_generation, SubFactory, RelatedFactory,
)
from factory.fuzzy import FuzzyAttribute
from faker import Faker

from app.db import db
from app.policies.helpers import generate_policy_rules_filename
from app.signatures.models import Signature
from app.users.models import User
from app.users.tests.factories import UserFactory

from ..constants import POLICY_TYPES, POLICY_DEPLOYMENT_ACTIONS
from ..models import Policy, PolicyApplicationGroup, PolicyApplication


FAKE = Faker()


class PolicyFactory(alchemy.SQLAlchemyModelFactory):
    name = Sequence(
        lambda n: "Policy {0} {1}".format(FAKE.word(), n)
    )
    description = FuzzyAttribute(FAKE.text)
    policy_type = Iterator(
        POLICY_TYPES._asdict().values()
    )
    created_at = FuzzyAttribute(
        lambda: pytz.utc.localize(FAKE.date_time_this_month())
    )
    signatures = LazyAttribute(
        lambda o: Signature.query.filter_by_policy_type(o.policy_type).all()
    )

    @lazy_attribute
    def created_by(self):
        count = User.query.count()

        if count:
            index = random.randint(0, count - 1)
            return User.query[index]
        else:
            return UserFactory()

    class Meta:
        model = Policy
        sqlalchemy_session = db.session


class PolicyApplicationFactory(alchemy.SQLAlchemyModelFactory):
    policy = SubFactory(PolicyFactory)
    action = Iterator(
        POLICY_DEPLOYMENT_ACTIONS._asdict().values()
    )
    target_filename = LazyAttribute(
        lambda o: generate_policy_rules_filename(o.policy)
    )

    class Meta:
        model = PolicyApplication
        sqlalchemy_session = db.session


class PolicyApplicationGroupFactory(alchemy.SQLAlchemyModelFactory):
    task_id = FuzzyAttribute(celery_uuid)
    created_at = FuzzyAttribute(
        lambda: pytz.utc.localize(FAKE.date_time_this_month())
    )
    applications = RelatedFactory(PolicyApplicationFactory, 'group')

    @lazy_attribute
    def created_by(self):
        count = User.query.count()

        if count:
            index = random.randint(0, count - 1)
            return User.query[index]
        else:
            return UserFactory()

    @post_generation
    def sensor_interfaces(self, create, extracted, **kwargs):
        if create and extracted:
            self.sensor_interfaces.extend(extracted)

    class Meta:
        model = PolicyApplicationGroup
        sqlalchemy_session = db.session
