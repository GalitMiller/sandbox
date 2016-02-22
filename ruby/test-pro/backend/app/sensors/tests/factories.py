# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from factory import (
    alchemy, lazy_attribute, Sequence, RelatedFactory, post_generation,
    PostGenerationMethodCall,
)
from factory.fuzzy import FuzzyAttribute
from faker import Faker

from app.db import db

from ..models import Sensor, SensorInterface


FAKE = Faker()


class SensorInterfaceFactory(alchemy.SQLAlchemyModelFactory):
    name = Sequence(
        lambda n: "eth{0}".format(n)
    )
    git_branch_name = PostGenerationMethodCall('ensure_git_branch_name')

    @lazy_attribute
    def hardware_address(self):
        result = FAKE.mac_address()

        while SensorInterface.query.get_by_hardware_address(result):
            result = FAKE.mac_address()

        return result

    class Meta:
        model = SensorInterface
        sqlalchemy_session = db.session


class SensorFactory(alchemy.SQLAlchemyModelFactory):
    name = Sequence(
        lambda n: "Sensor {0} {1}".format(FAKE.word(), n)
    )
    hostname = FuzzyAttribute(FAKE.domain_name)
    is_active = FuzzyAttribute(FAKE.boolean)
    is_controlled_by_cmc = FuzzyAttribute(FAKE.boolean)
    interfaces = RelatedFactory(SensorInterfaceFactory, 'sensor')

    class Meta:
        model = Sensor
        sqlalchemy_session = db.session
