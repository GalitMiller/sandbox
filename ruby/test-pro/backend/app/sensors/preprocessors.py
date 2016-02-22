# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-

from flask import jsonify
from flask.ext.restless import ProcessingException
from schematics.exceptions import ModelConversionError, ModelValidationError

from app.policies.objects import PolicyInvokationInfo
from app.utils.encoding import smart_str


def controlled_sensor_get_many_preprocessor(search_params=None, **kwargs):
    if search_params is not None:
        filters = search_params.setdefault('filters', [])

        for item in filters[:]:
            if item.get('name') == 'is_controlled_by_cmc':
                filters.remove(item)

        filters.extend([
            {
                'name': 'is_controlled_by_cmc',
                'op': '==',
                'val': True,
            }
        ])


def uncontrolled_sensor_get_many_preprocessor(search_params=None, **kwargs):
    if search_params is not None:
        filters = search_params.setdefault('filters', [])

        for item in filters[:]:
            name = item.get('name')
            if name and name in {'is_active', 'is_controlled_by_cmc'}:
                filters.remove(item)

        filters.extend([
            {
                'name': 'is_active',
                'op': '==',
                'val': True,
            },
            {
                'name': 'is_controlled_by_cmc',
                'op': '==',
                'val': False,
            }
        ])


def sensor_interface_apply_policies_preprocessor(data):
    policies = data.pop('policies')

    try:
        data['policy_invokation_infos'] = [
            PolicyInvokationInfo.from_dict(p)
            for p in policies
        ]
    except (ModelConversionError, ModelValidationError) as e:
        # TODO: flatten validation messages, use something like APIBadRequest
        response = {
            'message': smart_str(e),
        }
        raise ProcessingException(code=400, response=jsonify(response))
