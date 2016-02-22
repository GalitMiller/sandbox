# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

import ujson as json

from flask import abort, request
from flask.ext.login import current_user
from flask.ext.restless.views import API
from sqlalchemy import func, or_

from app import app, api_manager
from app.core.views.api import (
    api_url, api_url_prefix, paginate_objects, APISuccess, APIBadRequest,
)
from app.db import db
from app.db.sql.types import OmnivorousBoolean
from app.sensors.models import Sensor, SensorInterface
from app.sensors.serializers import (
    sensor_serializer,
)
from app.sensors.views import SENSOR_RESULTS_PER_PAGE
from app.signatures.models import Signature
from app.signatures.views import SIGNATURE_RESULTS_PER_PAGE
from app.users.decorators import api_login_required
from app.users.models import User
from app.utils.encoding import smart_str

from .models import (
    Policy, policy_signatures, PolicyApplicationGroup, PolicyApplication,
)
from .serializers import (
    POLICY_INCLUDE_COLUMNS, POLICY_INCLUDE_METHODS,
    POLICY_APPLICATION_GROUP_INCLUDE_COLUMNS,
    POLICY_APPLICATION_GROUP_INCLUDE_METHODS,
    POLICY_APPLICATION_INCLUDE_COLUMNS,
    policy_serializer, policy_lite_serializer,
)

LOG = logging.getLogger(__name__)


# Policies --------------------------------------------------------------------
POLICY_RESULTS_PER_PAGE = 10


class PolicyView(API):

    dynamic_fields = (POLICY_INCLUDE_METHODS +
                      ['created_by__name', 'last_applied_by__name'])

    def _seek_results(self, params, *args, **kwargs):
        """
        ATTENTION!

        It is assumed that ordering can be done by a single field only.
        """
        order_by = params.get('order_by', [])
        dynamic_order_by = {}

        # Exclude fields which are not DB columns and remember them
        for criterion in order_by[:]:
            fieldname = criterion['field']

            if fieldname in self.dynamic_fields:
                dynamic_order_by[fieldname] = criterion['direction']
                order_by.remove(criterion)

        # Invoke original search
        ignore_order_by = bool(dynamic_order_by)
        query = super(PolicyView, self)._seek_results(params, ignore_order_by)

        # Chain ordering parameters to current query
        for fieldname, direction in dynamic_order_by.items():
            try:
                method = getattr(self, "_order_by_{0}".format(fieldname))
            except AttributeError:
                LOG.error("Failed to get method for ordering by field '{0}'"
                          .format(fieldname))
            else:
                query = method(query, direction)

        return query

    def _order_by_signatures_count(self, query, direction):
        counter = func.count(policy_signatures.c.signature_id)

        if direction:
            counter = getattr(counter, direction.lower())()

        return (query.join(policy_signatures)
                .group_by(Policy.id)
                .order_by(counter))

    def _order_by_is_applied(self, query, direction):
        counter = func.count(PolicyApplication.id)
        is_applied = func.cast(counter, OmnivorousBoolean)

        if direction:
            is_applied = getattr(is_applied, direction.lower())()

        join = query.outerjoin(PolicyApplication,
                               Policy.id == PolicyApplication.policy_id)
        return join.group_by(Policy.id).order_by(is_applied)

    def _order_by_created_by__name(self, query, direction):
        order = getattr(User.name, direction.lower())()
        join = query.outerjoin(User, User.id == Policy.created_by_id)
        return join.group_by(Policy.id).order_by(order)

    def _order_by_last_applied_by__name(self, query, direction):
        order = getattr(User.name, direction.lower())()
        join = query.outerjoin(User, User.id == Policy.last_applied_by_id)
        return join.group_by(Policy.id).order_by(order)


api_manager.create_api(
    model=Policy,
    collection_name='policies',
    include_columns=POLICY_INCLUDE_COLUMNS,
    include_methods=POLICY_INCLUDE_METHODS,
    methods=['GET', 'DELETE', ],
    url_prefix=api_url_prefix(version=1),
    results_per_page=POLICY_RESULTS_PER_PAGE,
    view_class=PolicyView,
)


@app.route(api_url('/policies/lite', version=1), methods=['GET', ])
@api_login_required
def policies_lite_list():
    results = paginate_objects(
        objects=Policy.query,
        results_per_page=POLICY_RESULTS_PER_PAGE,
        serializer=policy_lite_serializer,
    )
    return APISuccess(results)


@app.route(api_url('/policies', version=1), methods=['POST', ])
@api_login_required
def create_policy():
    data = request.get_json() or {}

    policy_type = data.get('type') or abort(400)
    name = data.get('name') or abort(400)

    signatures = Signature.query.filter_by_policy_type(
        policy_type=policy_type,
        signature_ids=data.get('customSignatureIds'),
        category_ids=data.get('customCategoryIds'),
    )

    if not signatures.count():
        message = "There are no signatures to include into policy."
        return APIBadRequest(message=message)

    try:
        policy = Policy(
            name=smart_str(name).strip(),
            description=smart_str(data.get('description')).strip(),
            policy_type=policy_type,
            created_by=current_user,
        )

        db.session.add(policy)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

        message = smart_str(e)
        LOG.error("Failed to create new policy: {0}".format(message))
        return APIBadRequest(message=message)

    try:
        values = [
            (policy.id, v) for (v, ) in signatures.values(Signature.id)
        ]
        db.session.execute(policy_signatures.insert().values(values))
        db.session.commit()
    except Exception as e:
        db.session.rollback()

        message = smart_str(e)
        LOG.error("Failed add signatures to new policy: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        primitive = policy_serializer(policy)
        return APISuccess(primitive)


@app.route(api_url('/policies', version=1), methods=['DELETE', ])
@api_login_required
def delete_policy_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    failed = []

    try:
        for policy_id in q.get('ids', []):
            policy = Policy.query.get(policy_id)
            if policy:
                if policy.is_deletable():
                    db.session.delete(policy)
                else:
                    LOG.error("Failed to delete policy #{id}: applied "
                              "policy cannot be deleted.".format(id=policy.id))
                    failed.append({
                        'id': policy.id,
                        'message':
                            "This policy is applied and cannot be deleted.",
                    })
            else:
                LOG.error("Failed to delete policy in bulk request: policy "
                          "#{id} does not exist.".format(id=policy_id))

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete policies: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


@app.route(api_url('/policies/<int:policy_id>', version=1), methods=['PUT', ])
@api_login_required
def edit_policy(policy_id):
    policy = Policy.query.get(policy_id) or abort(404)
    data = request.get_json() or {}

    name = data.get('name') or abort(400)
    policy_type = data.get('type') or abort(400)

    signatures = Signature.query.filter_by_policy_type(
        policy_type=policy_type,
        signature_ids=data.get('customSignatureIds'),
        category_ids=data.get('customCategoryIds'),
    )

    if not signatures.count():
        message = "There are no signatures to include into policy."
        return APIBadRequest(message=message)

    policy.name = name
    policy.description = data.get('description')
    policy.policy_type = policy_type

    try:
        db.session.add(policy)

        # Update list of signatures: delete all existing and create again
        new_values = [
            (policy.id, v) for (v, ) in signatures.values(Signature.id)
        ]
        db.session.execute(policy_signatures
                           .delete()
                           .where(policy_signatures.c.policy_id == policy_id))
        db.session.execute(policy_signatures.insert().values(new_values))

        db.session.commit()
    except Exception as e:
        db.session.rollback()

        message = smart_str(e)
        LOG.error("Failed to update policy #{id} with data {data}: {message}"
                  .format(id=policy_id, data=data, message=message))
        return APIBadRequest(message=message)
    else:
        # TODO: invoke corrective apply
        primitive = policy_serializer(policy)
        return APISuccess(primitive)


@app.route(api_url('/policies/preview', version=1), methods=['POST', ])
@api_login_required
def preview_policy():
    data = request.get_json() or {}
    policy_type = data.get('type') or abort(400)

    results_per_page = data.get('results_per_page', SIGNATURE_RESULTS_PER_PAGE)
    page = data.get('page')

    def serializer(item):
        return {
            'id': item.id,
            'name': item.name,
            'severity': {
                'id': item.severity_id,
                'name': item.severity.name,
            },
            'category': {
                'id': item.category_id,
                'name': item.category.name,
            },
            'rule': item.to_string(),
        }

    signatures = Signature.query.filter_by_policy_type(
        policy_type=policy_type,
        signature_ids=data.get('customSignatureIds'),
        category_ids=data.get('customCategoryIds'),
    )
    results = paginate_objects(
        objects=signatures,
        results_per_page=results_per_page,
        page=page,
        serializer=serializer,
    )
    return APISuccess(results)


@app.route(api_url('/policies/<int:policy_id>/sensors', version=1),
           methods=['GET', ])
@api_login_required
def policy_sensors(policy_id):
    """
    Stub view which returns sensors a policy is applied to.
    NOTE: policy itself does not have sensors.
    """
    policy = Policy.query.get(policy_id) or abort(404)

    applications = policy.applications
    sensor_ids = set(x.group.interface.sensor_id for x in applications)

    criterion = Sensor.id.in_(sensor_ids)
    sensors = db.session.query(Sensor).filter(criterion)

    results = paginate_objects(
        objects=sensors,
        results_per_page=SENSOR_RESULTS_PER_PAGE,
        serializer=sensor_serializer,
    )
    return APISuccess(results)


@app.route(api_url('/policies/<int:policy_id>/signatures/lite', version=1),
           methods=['GET', ])
@api_login_required
def policy_signatures_lite(policy_id):

    def serializer(item):
        return {
            'id': item.id,
            'name': item.name,
            'category_id': item.category_id,
        }

    signatures = (Signature.query
                  .join((Policy, Signature.policies))
                  .filter(Policy.id == policy_id))

    q = request.args.get('q')
    if q:
        signatures = signatures.filter(Signature.name.like('%' + q + '%'))

    results = paginate_objects(
        objects=signatures,
        results_per_page=SIGNATURE_RESULTS_PER_PAGE,
        serializer=serializer,
    )
    return APISuccess(results)


APPLICATIONS_RESULTS_PER_PAGE = 5


@app.route(api_url('/policies/<int:policy_id>/applications', version=1),
           methods=['GET', ])
@api_login_required
def policy_applications(policy_id):
    """
    View which returns applications for specified policy.
    """
    data = request.get_json() or {}
    policy = Policy.query.get(policy_id) or abort(404)
    results_per_page = data.get('results_per_page',
                                APPLICATIONS_RESULTS_PER_PAGE)
    page = data.get('page')

    def serializer(item):
        last_applied_at, last_applied_by, interface, sensor, action, id_ = item
        return {
            'id': id_,
            'action': action,
            'last_applied_at': last_applied_at.isoformat(),
            'last_applied_by': last_applied_by,
            'interface': interface,
            'sensor': sensor,
        }

    query = (db.session.query(PolicyApplicationGroup.last_applied_at,
                              User.name, SensorInterface.name, Sensor.name,
                              PolicyApplication.action, PolicyApplication.id,)
             .join(User, SensorInterface, Sensor)
             .join(PolicyApplication,
                   PolicyApplicationGroup.id == PolicyApplication.group_id)
             .filter(PolicyApplication.policy_id == policy.id)
             .order_by(PolicyApplicationGroup.last_applied_at.desc()))

    q = request.args.get('q')
    if q:
        q = '%' + q + '%'
        query = query.filter(or_(SensorInterface.name.like(q),
                                 Sensor.name.like(q),
                                 User.name.like(q)))

    results = paginate_objects(
        objects=query,
        results_per_page=results_per_page,
        page=page,
        serializer=serializer,
    )
    return APISuccess(results)


# Applications ----------------------------------------------------------------
api_manager.create_api(
    model=PolicyApplicationGroup,
    collection_name='application_groups',
    include_columns=POLICY_APPLICATION_GROUP_INCLUDE_COLUMNS,
    include_methods=POLICY_APPLICATION_GROUP_INCLUDE_METHODS,
    methods=['GET', ],
    url_prefix=api_url_prefix(version=1) + "/policies",
)

api_manager.create_api(
    model=PolicyApplication,
    collection_name='applications',
    include_columns=POLICY_APPLICATION_INCLUDE_COLUMNS,
    methods=['GET', ],
    url_prefix=api_url_prefix(version=1) + "/policies",
)
