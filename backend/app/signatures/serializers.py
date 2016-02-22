# -*- coding: utf-8 -*-

from flask.ext.restless.helpers import to_dict
from functools import partial


# References ------------------------------------------------------------------
SIGNATURE_REFERENCE_INCLUDE_COLUMNS = [
    'id', 'value', 'signature_id', 'reference_type', 'reference_type.id',
    'reference_type.name',
]

SIGNATURE_REFERENCE_TYPE_INCLUDE_COLUMNS = [
    'id', 'name', 'url_prefix',
]
SIGNATURE_REFERENCE_TYPE_INCLUDE_METHODS = [
    'is_deletable',
]

# Categories ------------------------------------------------------------------
SIGNATURE_CATEGORY_INCLUDE_COLUMNS_BASE = [
    'id', 'name',
]
SIGNATURE_CATEGORY_INCLUDE_SIGNATURES_COUNT = [
    'signatures_count',
]
SIGNATURE_CATEGORY_INCLUDE_IS_DELETABLE = [
    'is_deletable',
]
signature_category_lite_serializer = partial(
    to_dict,
    include=SIGNATURE_CATEGORY_INCLUDE_COLUMNS_BASE,
)

signature_category_update_serializer = partial(
    to_dict,
    include=SIGNATURE_CATEGORY_INCLUDE_COLUMNS_BASE,
    include_methods=SIGNATURE_CATEGORY_INCLUDE_SIGNATURES_COUNT,
)

SIGNATURE_CATEGORY_INCLUDE_COLUMNS = SIGNATURE_CATEGORY_INCLUDE_COLUMNS_BASE + [
    'description',
]
SIGNATURE_CATEGORY_INCLUDE_METHODS = (
    SIGNATURE_CATEGORY_INCLUDE_SIGNATURES_COUNT +
    SIGNATURE_CATEGORY_INCLUDE_IS_DELETABLE
)


signature_category_serializer = partial(
    to_dict,
    include=SIGNATURE_CATEGORY_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_CATEGORY_INCLUDE_SIGNATURES_COUNT,
)


def signature_category_heavy_serializer(category):

    def _signature_serializer(item):
        return {
            'id': item.id,
            'name': item.name,
            'category_id': item.category_id,
        }

    result = signature_category_lite_serializer(category)
    result['signatures'] = map(_signature_serializer,
                               category.signatures)
    return result


# Class types -----------------------------------------------------------------
SIGNATURE_CLASS_TYPE_INCLUDE_COLUMNS = [
    'id', 'name', 'short_name', 'priority',
]
SIGNATURE_CLASS_TYPE_INCLUDE_METHODS = [
    'is_deletable',
]

# Severities ------------------------------------------------------------------
SIGNATURE_SEVERITY_INCLUDE_COLUMNS = [
    'id', 'name', 'text_color', 'bg_color', 'weight', 'is_predefined',
]
SIGNATURE_SEVERITY_INCLUDE_METHODS = [
    'signatures_count', 'is_deletable',
]
signature_severity_serializer = partial(
    to_dict, include=SIGNATURE_SEVERITY_INCLUDE_COLUMNS
)

# Protocols -------------------------------------------------------------------
SIGNATURE_PROTOCOL_INCLUDE_COLUMNS = [
    'id', 'name',
]
signature_protocol_serializer = partial(
    to_dict, include=SIGNATURE_PROTOCOL_INCLUDE_COLUMNS
)

# Signatures ------------------------------------------------------------------
SIGNATURE_INCLUDE_COLUMNS_BASE = [
    'id', 'name', 'category_id', 'message',
]

SIGNATURE_INCLUDE_METHODS_BASE = ['is_deletable', ]

signature_lite_serializer = partial(
    to_dict,
    include=SIGNATURE_INCLUDE_COLUMNS_BASE,
    include_methods=SIGNATURE_INCLUDE_METHODS_BASE,
)

SIGNATURE_INCLUDE_RELATIONS = [
    'protocol', 'category', 'class_type', 'severity', 'references',
]
SIGNATURE_INCLUDE_COLUMNS = (
    [
        'action', 'src_host', 'src_port', 'dst_host', 'dst_port',
        'is_bidirectional', 'category.id', 'category.name',
        'flow_control', 'content_control', 'priority', 'sid', 'gid',
        'revision', 'is_editable', 'created_at', 'created_by_id', 'created_by',
        'created_by.active', 'created_by.login', 'created_by.name',
        'created_by.role',
    ]
    + SIGNATURE_INCLUDE_COLUMNS_BASE
    + SIGNATURE_INCLUDE_RELATIONS
)
SIGNATURE_INCLUDE_METHODS = SIGNATURE_INCLUDE_METHODS_BASE
signature_serializer = partial(
    to_dict,
    include=SIGNATURE_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_INCLUDE_METHODS,
    deep={x: {} for x in SIGNATURE_INCLUDE_RELATIONS},
)


SIGNATURE_INCLUDE_COLUMNS_LITE = [
    'id', 'name', 'sid', 'action', 'is_editable', 'created_at',
    'created_by', 'created_by.id', 'created_by.active', 'created_by.login',
    'created_by.name', 'created_by.role', 'severity', 'severity.id',
    'severity.name', 'severity.text_color', 'severity.bg_color',
    'severity.weight',
]

SIGNATURE_INCLUDE_METHODS_LITE = [
    'is_deletable',
]
