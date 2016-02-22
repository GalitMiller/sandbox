# -*- coding: utf-8 -*-
from __future__ import division

import logging
import math
import ujson as json

from flask import request
from flask.ext.restless.helpers import (
    strings_to_dates, get_related_association_proxy_model,
)
from flask.ext.restless.search import search as restless_search
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm.query import Query

from app.db import db
from app.utils.encoding import smart_str
from app.utils.http import JSONResponse


LOG = logging.getLogger(__name__)


def api_url_prefix(version):
    return "/api/v{0}".format(version)


def api_url(route, version):
    return api_url_prefix(version) + route


def paginate_objects(objects, results_per_page=0, page=None, serializer=None):
    """
    Originally extracted from 'flask_restless.views.API._paginated()'
    """
    results_per_page = int(
        request.args.get('results_per_page', results_per_page)
    )

    if not page:
        page = 1

    num_results = (objects.count()
                   if isinstance(objects, Query) else
                   len(objects))

    if results_per_page > 0:
        page = int(request.args.get('page', page))
        start = (page - 1) * results_per_page
        end = min(num_results, start + results_per_page)
        total_pages = int(math.ceil(num_results / results_per_page))
    else:
        page = 1
        start = 0
        end = num_results
        total_pages = 1

    objects = objects[start:end]

    if serializer:
        objects = list(map(serializer, objects))

    return {
        'num_results': num_results,
        'total_pages': total_pages,
        'page': page,
        'objects': objects,
    }


def search(model):
    """
    Originally extracted from 'flask_restless.views.API._search()'
    """
    try:
        search_params = json.loads(request.args.get('q', '{}'))
    except (TypeError, ValueError, OverflowError) as e:
        message = smart_str(e)
        LOG.exception("Unable to decode data to search model '{name}': {e}"
                      .format(name=model.__name__, e=message))
        raise ValueError(message)

    # resolve date-strings as required by the model
    for param in search_params.get('filters', list()):
        if 'name' in param and 'val' in param:
            query_model = model
            query_field = param['name']

            if '__' in param['name']:
                fieldname, relation = param['name'].split('__')
                submodel = getattr(model, fieldname)
                if isinstance(submodel, InstrumentedAttribute):
                    query_model = submodel.property.mapper.class_
                    query_field = relation
                elif isinstance(submodel, AssociationProxy):
                    # For the sake of brevity, rename this function.
                    get_assoc = get_related_association_proxy_model
                    query_model = get_assoc(submodel)
                    query_field = relation

            to_convert = {query_field: param['val']}

            try:
                result = strings_to_dates(query_model, to_convert)
            except ValueError as e:
                message = smart_str(e)
                LOG.exception(
                    "Unable to construct query to search model '{name}': {e}"
                    .format(name=model.__name__, e=message))
                raise ValueError(message)

            param['val'] = result.get(query_field)

    return restless_search(db.session, model, search_params)


class APIResponse(JSONResponse):
    pass


class APISuccess(JSONResponse):
    code = 200


class APIBadRequest(APIResponse):
    code = 400


class APINotFound(APIResponse):
    code = 404
