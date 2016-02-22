# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import logging

from isotopic_logging import autoprefix_injector
from sqlalchemy.orm import Query

from app.config import SENSOR_SSH_DEFAULTS
from app.db import db
from app.policies.models import PolicyApplicationGroup
from app.utils import git
from app.utils.encoding import smart_str, smart_bytes

from .helpers import fetch_sensor_interfaces, take_control_over_sensor


LOG = logging.getLogger(__name__)


class SnorbySensor(db.Model):
    __tablename__ = 'sensor'
    __bind_key__ = 'snorby'

    sid = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.String(50),
    )
    hostname = db.Column(
        db.Text,
    )
    interface = db.Column(
        db.Text,
    )
    filter = db.Column(
        db.Text,
    )
    detail = db.Column(
        db.Integer,
    )
    encoding = db.Column(
        db.Integer,
    )
    last_cid = db.Column(
        db.Integer,
    )
    pending_delete = db.Column(
        db.Boolean,
        default=False,
    )
    updated_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
    )
    events_count = db.Column(
        db.Integer,
    )

    def __repr__(self):
        return smart_bytes("<SnorbySensor '{0}'>"
                           .format(self.name or self.hostname))


class SensorQuery(Query):

    def uncontrolled(self):
        return self.filter_by(is_active=True, is_controlled_by_cmc=False)


class Sensor(db.Model):
    __tablename__ = 'sensors'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        nullable=False,
    )
    hostname = db.Column(
        db.Unicode(255),
        nullable=False,
        index=True,
    )
    ssh_port = db.Column(
        db.Integer,
        nullable=False,
        default=SENSOR_SSH_DEFAULTS.PORT,
    )
    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        index=True,
    )
    is_controlled_by_cmc = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    query_class = SensorQuery

    def take_control(
        self, remote_hostname, remote_username=None, remote_password=None,
        conn_timeout=None, exec_timeout=None
    ):
        self.hostname = smart_str(remote_hostname).strip()
        take_control_over_sensor(self,
                                 remote_username,
                                 remote_password,
                                 conn_timeout,
                                 exec_timeout)
        self.is_controlled_by_cmc = True

        try:
            db.session.add(self)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    def refresh_interfaces(self, conn_timeout=None, exec_timeout=None):
        fetched = fetch_sensor_interfaces(self, conn_timeout, exec_timeout)

        for interface in self.interfaces:
            name = fetched.pop(interface.hardware_address.upper(), None)

            if name is None:
                interface.is_active = False
            else:
                interface.is_active = True
                interface.name = name or interface.hardware_address

            db.session.add(interface)

        if fetched:
            self.interfaces.extend([
                SensorInterface(
                    sensor=self,
                    name=name,
                    hardware_address=hardware_address,
                )
                for hardware_address, name in fetched.items()
            ])

        db.session.commit()

    def __repr__(self):
        return smart_bytes("<Sensor '{0}'>".format(self.name))


class SensorInterfaceQuery(Query):

    def get_by_hardware_address(self, value):
        return self.filter_by(hardware_address=value).first()


class SensorInterface(db.Model):
    __tablename__ = 'sensor_interfaces'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Text,
        nullable=False,
    )
    hardware_address = db.Column(
        db.String(17),
        nullable=False,
        unique=True,
    )
    sensor_id = db.Column(
        db.Integer,
        db.ForeignKey('sensors.id'),
    )
    sensor = db.relationship(
        'Sensor',
        backref=db.backref('interfaces', lazy='dynamic'),
    )
    git_branch_name = db.Column(
        db.Unicode(255),
    )
    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    query_class = SensorInterfaceQuery

    @property
    def full_name(self):
        return "{0}:{1}".format(self.sensor.name, self.name)

    def ensure_git_branch_name(self, commit=True):
        if not self.git_branch_name:
            self.git_branch_name = git.format_branch_name(self.full_name)
            db.session.add(self)
            if commit:
                db.session.commit()

    def apply_policies(self, policy_invokation_infos, applied_by):
        with autoprefix_injector():
            group = (PolicyApplicationGroup.query
                     .get_or_create_for_interface(self))
            group.invoke(policy_invokation_infos, applied_by)

        return group

    def __repr__(self):
        return smart_bytes("<SensorInterface '{0}'>".format(self.full_name))
