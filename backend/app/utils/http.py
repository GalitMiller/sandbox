# -*- coding: utf-8 -*-

import ujson as json

from base64 import b64encode
from flask import Response as ResponseBase, current_app, request


class JSONResponse(ResponseBase):
    indent = None
    separators = (',', ':')

    code = None
    message = None

    def __init__(self, payload=None, message=None, **kwargs):
        payload = payload or {}

        message = message or self.message
        if message:
            payload['message'] = message

        if (
            current_app.config['JSONIFY_PRETTYPRINT_REGULAR']
            and not request.is_xhr
        ):
            indent = 2
        else:
            indent = kwargs.pop('indent', self.indent)

        # Note that we add '\n' to end of response
        # (see https://github.com/mitsuhiko/flask/pull/1262)
        response = (
            json.dumps(payload, indent),
            '\n',
        )

        kwargs.setdefault('status', self.code)
        kwargs['mimetype'] = 'application/json'

        super(JSONResponse, self).__init__(response, **kwargs)


class FileResponse(ResponseBase):

    def __init__(self, filename, content, **kwargs):
        headers = kwargs.setdefault('headers', {})
        headers.update({
            'Content-Disposition': "attachment;filename=" + filename,
            'Content-Type': "application/download",
        })
        super(FileResponse, self).__init__(content, **kwargs)


def make_cookie(data):
    """
    Encode JSON in base64 and append fake checksum.
    """
    if not isinstance(data, basestring):
        data = json.dumps(data)

    return b64encode(data) + '--fakea6467cf70ed909780fba5836276e6a460c8d'
