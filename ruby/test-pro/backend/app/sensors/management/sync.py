# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command
from isotopic_logging import autoprefix_injector
from unipath import Path

from app import sensors
from app.db import db
from app.db.utils import execute_script
from app.sensors.models import Sensor, SensorInterface, SnorbySensor


LOG = logging.getLogger(__name__)


class SyncSetup(Command):
    """
    Setup mechanisms for synchronization of users between 'bricata' DB and
    primary DB.
    """
    name = "sync_setup"

    def run(self):
        filename = Path(sensors.__file__).absolute().parent.child(
            'sql', 'triggers', 'sync_sensors.sql'
        )
        execute_script(filename)


class SyncSensors(Command):
    """
    Drop all existing sensors from primary DB and fetch them from 'bricata' DB.
    """
    name = "sync"

    def run(self):
        # TODO: do not delete objects with same ID: update them instead
        with autoprefix_injector():
            self._delete_existing()
            self._grab_new()

    def _delete_existing(self):
        # SQLAlchemy does not handle cascade deletion, so we have to do dirty
        # work manually
        with autoprefix_injector() as inj:
            count = SensorInterface.query.delete()
            LOG.debug(inj.mark(
                "Deleted {0} sensor interface(s).".format(count)))

            count = Sensor.query.delete()
            LOG.debug(inj.mark(
                "Deleted {0} sensor(s).".format(count)))

    def _grab_new(self):
        with autoprefix_injector() as inj:
            sensors = SnorbySensor.query

            count = sensors.count()
            LOG.info(inj.mark(
                "Grabbing {0} sensor(s)...".format(count)))

            try:
                db.session.add_all([
                    Sensor(
                        id=sensor.sid,
                        name=sensor.name,
                        hostname=self._safe_hostname(sensor.hostname),
                        is_active=not sensor.pending_delete,
                    )
                    for sensor in sensors
                ])
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Failed to grab sensors: {e}".format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Sensors were grabbed successfully"))

    @staticmethod
    def _safe_hostname(hostname):
        return hostname.split(':', 1)[0]
