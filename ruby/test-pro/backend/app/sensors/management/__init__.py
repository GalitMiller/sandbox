# -*- coding: utf-8 -*-
"""
Perform sensor-related operations.
"""

from flask.ext.script import Manager

from .interfaces import CreateSensorInterface, ApplyPoliciesToInterface
from .sensors import CreateSensor
from .sync import SyncSetup, SyncSensors


__all__ = [
    'interfaces', 'CreateSensor', 'SyncSetup', 'SyncSensors',
]
__namespace__ = "sensors"


interfaces = Manager(usage="Manage sensor interfaces.")
interfaces.add_command(CreateSensorInterface.name, CreateSensorInterface)
interfaces.add_command(ApplyPoliciesToInterface.name, ApplyPoliciesToInterface)
