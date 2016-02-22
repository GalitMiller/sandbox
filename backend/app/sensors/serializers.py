# -*- coding: utf-8 -*-

from flask.ext.restless.helpers import to_dict
from functools import partial


SENSOR_INCLUDE_COLUMNS = [
    'id', 'name', 'hostname', 'ssh_port', 'git_branch_name', 'is_active',
    'is_controlled_by_cmc',
]
sensor_serializer = partial(to_dict, include=SENSOR_INCLUDE_COLUMNS)

SENSOR_INTERFACE_INCLUDE_COLUMNS = [
    'id', 'name', 'sensor_id', 'is_active',
]
sensor_interface_serializer = partial(
    to_dict, include=SENSOR_INTERFACE_INCLUDE_COLUMNS,
)
