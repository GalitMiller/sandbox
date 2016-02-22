# -*- coding: utf-8 -*-

from flask.ext.restless.helpers import to_dict
from functools import partial


# Policies --------------------------------------------------------------------
POLICY_INCLUDE_COLUMNS_BASE = ['id', 'name', ]

policy_lite_serializer = partial(
    to_dict, include=POLICY_INCLUDE_COLUMNS_BASE
)


POLICY_INCLUDE_COLUMNS = POLICY_INCLUDE_COLUMNS_BASE + [
    'description', 'created_at', 'created_by_id', 'created_by', 'created_by.id',
    'created_by.active', 'created_by.login', 'created_by.name',
    'created_by.role', 'last_applied_by_id', 'last_applied_by',
    'last_applied_by.id', 'last_applied_by.active', 'last_applied_by.login',
    'last_applied_by.name', 'last_applied_by.role', 'policy_type',
]
POLICY_INCLUDE_METHODS = ['signatures_count', 'is_deletable', ]

policy_serializer = partial(
    to_dict,
    include=POLICY_INCLUDE_COLUMNS,
    include_methods=POLICY_INCLUDE_METHODS,
)

# Application groups ----------------------------------------------------------
POLICY_APPLICATION_GROUP_INCLUDE_COLUMNS = [
    'id', 'interface_id', 'task_id',
]
POLICY_APPLICATION_GROUP_INCLUDE_METHODS = ['is_ready', ]

policy_application_group_serializer = partial(
    to_dict,
    include=POLICY_APPLICATION_GROUP_INCLUDE_COLUMNS,
    include_methods=POLICY_APPLICATION_GROUP_INCLUDE_METHODS,
)


POLICY_APPLICATION_INCLUDE_COLUMNS = [
    'id', 'group_id', 'policy_id', 'action',
]

policy_application_serializer = partial(
    to_dict,
    include=POLICY_APPLICATION_INCLUDE_COLUMNS,
)
