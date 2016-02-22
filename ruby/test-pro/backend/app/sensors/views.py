# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask import abort, jsonify, request
from flask.ext.login import current_user
from flask.views import MethodView
from isotopic_logging import autoprefix_injector
from schematics.exceptions import ModelConversionError, ModelValidationError

from app import app, api_manager, cache
from app.core.views.api import (
    api_url, api_url_prefix, paginate_objects, APISuccess, APIBadRequest,
)
from app.policies.objects import PolicyInvokationInfo
from app.policies.serializers import policy_application_group_serializer
from app.users.decorators import api_login_required
from app.utils.decorators import method_decorator
from app.utils.encoding import smart_str
from app.utils.html import nl2br

from .exceptions import TakeControlOverSensorError, SensorIsAlreadyUnderControl
from .helpers import generate_sensor_initializer
from .models import SnorbySensor, Sensor, SensorInterface
from .preprocessors import (
    controlled_sensor_get_many_preprocessor,
    uncontrolled_sensor_get_many_preprocessor,
    sensor_interface_apply_policies_preprocessor,
)
from .serializers import (
    SENSOR_INCLUDE_COLUMNS, SENSOR_INTERFACE_INCLUDE_COLUMNS,
    sensor_interface_serializer
)


LOG = logging.getLogger(__name__)

SENSOR_RESULTS_PER_PAGE = 10


# Sensors ---------------------------------------------------------------------
@app.route('/utils/sensors/initializer', methods=['GET', ])
@api_login_required
def generate_sensor_initializer_view():
    try:
        output = generate_sensor_initializer()
    except Exception as e:
        output = smart_str(e)
        LOG.error("Failed to generate sensors initializer:\n{output}"
                  .format(output=output))
    finally:
        return nl2br(output)


api_manager.create_api(
    model=SnorbySensor,
    collection_name='snorby_sensors',
    include_columns=[
        'sid', 'name', 'hostname', 'interface', 'filter', 'detail', 'encoding',
        'last_cid', 'pending_delete', 'updated_at', 'events_count',
    ],
    methods=['GET', ],
    url_prefix=api_url_prefix(version=1),
)
api_manager.create_api(
    model=Sensor,
    collection_name='sensors',
    include_columns=SENSOR_INCLUDE_COLUMNS,
    methods=['GET', 'POST', 'DELETE', 'PUT', ],
    url_prefix=api_url_prefix(version=1),
    results_per_page=SENSOR_RESULTS_PER_PAGE,
)
api_manager.create_api(
    model=Sensor,
    collection_name='controlled',
    include_columns=SENSOR_INCLUDE_COLUMNS,
    methods=['GET', ],
    preprocessors={
        'GET_MANY': [controlled_sensor_get_many_preprocessor, ],
    },
    results_per_page=SENSOR_RESULTS_PER_PAGE,
    url_prefix=api_url_prefix(version=1) + '/sensors',
)
api_manager.create_api(
    model=Sensor,
    collection_name='uncontrolled',
    include_columns=SENSOR_INCLUDE_COLUMNS,
    methods=['GET', ],
    preprocessors={
        'GET_MANY': [uncontrolled_sensor_get_many_preprocessor, ],
    },
    results_per_page=SENSOR_RESULTS_PER_PAGE,
    url_prefix=api_url_prefix(version=1) + '/sensors',
)


@app.route(api_url('/sensors/uncontrolled/count', version=1),
           methods=['GET', ])
@api_login_required
def uncontrolled_sensors_count():
    count = Sensor.query.uncontrolled().count()
    return APISuccess({'result': count})


@app.route(api_url('/sensors/<int:sensor_id>/take_control', version=1),
           methods=['POST', ])
@api_login_required
def take_control_over_sensor(sensor_id):
    sensor = Sensor.query.get(sensor_id) or abort(404)
    data = request.get_json() or {}

    succeed = False
    message = None

    with autoprefix_injector() as inj:
        try:
            sensor.take_control(
                remote_hostname=data.get('hostname'),
                remote_username=data.get('username'),
                remote_password=data.get('password'),
                conn_timeout=data.get('conn_timeout'),
                exec_timeout=data.get('exec_timeout'),
            )
        except SensorIsAlreadyUnderControl as e:
            message = smart_str(e)
            LOG.error(inj.mark(message))
        except TakeControlOverSensorError:
            message = (
                "It seems that either SSH connection to this sensor is not "
                "allowed or there was some unexpected issue when CMC tried to "
                "take control over the device.\n"
            )
        except Exception as e:
            reason = smart_str(e)
            message = (
                "Sorry, an internal error has occurred.\n"
                "Raw message: '{reason}'.\n"
                "Please, check the application log file for more details."
                .format(reason=reason))
            LOG.error(inj.mark(
                "Failed to take control over sensor #{id}: {reason}"
                .format(id=sensor_id, reason=reason)))
        else:
            succeed = True
        finally:
            if message:
                message = nl2br(message)

            # TODO: switch to APIResponce
            return jsonify({
                'succeed': succeed,
                'message': message,
            })

# Interfaces ------------------------------------------------------------------
api_manager.create_api(
    model=SensorInterface,
    collection_name='interfaces',
    include_columns=SENSOR_INTERFACE_INCLUDE_COLUMNS,
    methods=['GET', 'POST', 'DELETE', 'PUT', ],
    url_prefix=api_url_prefix(version=1) + "/sensors",
)


@app.route(api_url('/sensors/<int:sensor_id>/interfaces/refresh', version=1),
           methods=['GET', ])
@api_login_required
@cache.cached(timeout=10)
def refresh_sensor_interfaces(sensor_id):
    sensor = Sensor.query.get(sensor_id) or abort(404)

    try:
        conn_timeout = float(request.args.get('conn_timeout'))
    except Exception:
        conn_timeout = None

    try:
        exec_timeout = float(request.args.get('exec_timeout'))
    except Exception:
        exec_timeout = None

    sensor.refresh_interfaces(conn_timeout, exec_timeout)
    objects = map(sensor_interface_serializer, sensor.interfaces)

    return APISuccess({'objects': objects})


class SensorInterfacesApplyPoliciesBulkView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        data = (request.get_json() or {}).get('applications')

        if not data:
            return APIBadRequest(message="No data was specified.")

        self.failed = []

        with autoprefix_injector():
            for d in data:
                self.process_single_interface_safely(d)

        return APISuccess({'failed': self.failed, })

    def process_single_interface_safely(self, data):
        with autoprefix_injector() as inj:
            try:
                self._process_single_interface(data)
            except Exception as e:
                message = (
                    "Failed to process application data '{data}': '{e}'."
                    .format(data=data, e=smart_str(e)))
                LOG.error(inj.mark(message))
                self.failed.append(message)

    def _process_single_interface(self, data):
        with autoprefix_injector() as inj:
            interface_id = data['interface_id']
            interface = SensorInterface.query.get(interface_id)

            if interface:
                data = data['policies']
            else:
                self.failed.append("Interface with id '{id}' does not exist."
                                   .format(id=interface_id))
                return

            try:
                invokation_infos = [
                    PolicyInvokationInfo.from_dict(d)
                    for d in data
                ]
            except (ModelConversionError, ModelValidationError) as e:
                message = (
                    "Failed to process invokation infos for interface "
                    "'{name}' with policies data '{data}': {e}."
                    .format(name=interface.full_name,
                            data=data,
                            e=smart_str(e)))
                LOG.error(inj.mark(message))
                self.failed.append(message)

            try:
                interface.apply_policies(
                    policy_invokation_infos=invokation_infos,
                    applied_by=current_user,
                )
            except Exception as e:
                message = (
                    "Failed to apply policies to interface '{name}' with "
                    "policies data '{data}': {e}."
                    .format(name=interface.full_name,
                            data=data,
                            e=smart_str(e)))
                LOG.error(inj.mark(message))
                self.failed.append(message)


# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/sensors/interfaces/apply_policies', version=1),
    view_func=SensorInterfacesApplyPoliciesBulkView.as_view(
        str('sensor_interface_apply_policies_bulk')
    ),
)


@app.route(api_url('/sensors/interfaces/<int:interface_id>/apply_policies', version=1),
           methods=['POST', ])
@api_login_required
def sensor_interface_apply_policies(interface_id):
    interface = SensorInterface.query.get(interface_id) or abort(404)

    data = request.get_json() or {}
    sensor_interface_apply_policies_preprocessor(data)

    try:
        application_group = interface.apply_policies(
            policy_invokation_infos=data['policy_invokation_infos'],
            applied_by=current_user,
        )
    except Exception as e:
        message = smart_str(e)
        LOG.error(
            "Failed to apply policies to interface #{id} with data {data}: "
            "{message}"
            .format(id=interface_id, data=data, message=message))

        # TODO: another response type?
        return APIBadRequest(message=message)
    else:
        primitive = policy_application_group_serializer(application_group)
        return APISuccess(primitive)


@app.route(api_url('/sensors/interfaces/<int:interface_id>/applied_policies', version=1),
           methods=['GET', ])
@api_login_required
def sensor_interface_applied_policies_list(interface_id):
    from app.policies.views import POLICY_RESULTS_PER_PAGE

    interface = SensorInterface.query.get(interface_id) or abort(404)

    def serializer(application):
        return {
            'policy_id': application.policy_id,
            'action': application.action,
        }

    if interface.application_group:
        objects = interface.application_group.applications
    else:
        objects = []

    results = paginate_objects(
        objects=objects,
        results_per_page=POLICY_RESULTS_PER_PAGE,
        serializer=serializer,
    )
    return APISuccess(results)
