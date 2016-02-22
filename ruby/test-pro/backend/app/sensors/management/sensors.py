# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.sensors.models import Sensor
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSensor(Command):
    """
    Create new sensor in database.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Sensor name.",
            required=True,
        ),
        Option(
            '--hostname',
            help="Sensor hostname.",
            required=True,
        ),
        Option(
            '--ssh-port',
            help="SSH port. Default: 22.",
            dest="ssh_port",
            type=int,
            default=22,
        ),
        Option(
            '--inactive',
            help="Make sensors inactive (by default sensors are active).",
            dest='is_inactive',
            action='store_true',
        ),
        Option(
            '--controlled',
            help="Make sensors inactive (by default sensors are active).",
            dest='is_controlled_by_cmc',
            action='store_true',
        ),
    )

    def run(self, name, hostname, ssh_port, is_inactive, is_controlled_by_cmc):
        name = smart_str(name).strip()
        hostname = smart_str(hostname).strip()

        sensor = Sensor(
            name=name,
            hostname=hostname,
            ssh_port=ssh_port,
            is_active=not is_inactive,
            is_controlled_by_cmc=is_controlled_by_cmc,
        )
        db.session.add(sensor)
        db.session.commit()

        LOG.debug("Sensor '{name}' is created (id={id})."
                  .format(name=name, id=sensor.id))

        return sensor
