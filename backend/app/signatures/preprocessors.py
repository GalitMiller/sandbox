# -*- coding: utf-8 -*-

from flask.ext.restless import ProcessingException

from .models import SignatureSeverity


def signature_data_preprocessor(data=None, **kwargs):

    def _process_endpoint(name, info):
        if info:
            host = (None
                    if info['ip']['anyIp'] else
                    info['ip']['ip'] or None)
            port = (None
                    if info['port']['anyPort'] else
                    info['port']['port'] or None)
            return {
                name + '_host': host,
                name + '_port': port,
            }
        else:
            return {}

    if data:
        result = {
            'action': data['action'].lower(),
            'is_bidirectional': not data.get('unidirectional', True),
            'message': data['message'],
            'name': data['name'],
            'class_type_id': data.get('classTypeID'),
            'severity_id': data.get('severityId'),
            'protocol_id': data.get('protocolId'),
        }
        result.update(_process_endpoint('src', data.get('source')))
        result.update(_process_endpoint('dst', data.get('destination')))

        flow_control = data.get('flowControlTxt')
        if flow_control is not None:
            result['flow_control'] = flow_control

        content_control = data.get('contentTxt')
        if content_control is not None:
            result['content_control'] = content_control

        category_id = data.get('categoryId')
        if category_id is not None:
            result['category_id'] = int(category_id)

        priority = data.get('priority')
        if priority is not None:
            result['priority'] = int(priority)

        sid = data.get('sid')
        if sid is not None:
            result['sid'] = int(sid)

        gid = data.get('gid')
        if gid is not None:
            result['gid'] = int(gid)

        revision = data.get('revision')
        if revision is not None:
            result['revision'] = int(revision)

        result['references'] = [
            {
                'reference_type_id': x['typeId'],
                'value': x['value']
            }
            for x in data.get('references', [])
        ]

        return result


def signature_severity_post_preprocessor(data=None, **kwargs):
    if data:
        data.pop('is_predefined', None)
        data.pop('id', None)


def signature_severity_put_preprocessor(instance_id=None, data=None, **kwargs):
    if data:
        data.pop('is_predefined', None)


def signature_severity_delete_preprocessor(instance_id=None, **kwargs):
    if instance_id:
        instance = SignatureSeverity.query.get(instance_id)
        if instance and instance.is_predefined:
            msg = "Deletion of predefined signature severities is not allowed"
            raise ProcessingException(msg, 405)


def import_signature_single_rule_preprocessor(rule_data):
    rule_data['category_id'] = rule_data.pop('categoryId', None)
    rule_data['severity_id'] = rule_data.pop('severityId')


def reference_type_post_preprocessor(data=None, **kwargs):
    if data:
        data.pop('id', None)
