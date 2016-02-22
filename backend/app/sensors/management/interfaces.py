# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.policies.objects import PolicyInvokationInfo
from app.sensors.models import SensorInterface
from app.users.models import User
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSensorInterface(Command):
    """
    Define interface for existing sensor.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Interface name.",
            required=True,
        ),
        Option(
            '-s', '--sensor-id',
            help="Sensor ID this interface belongs to.",
            dest='sensor_id',
            type=int,
            required=True,
        ),
        Option(
            '-a', '--hw-address',
            help="Hardware address, e.g. ab:cd:ef:12:34:56",
            dest='hardware_address',
            required=True,
        ),
        Option(
            '--inactive',
            help="Make interface inactive (by default it is active).",
            dest='is_inactive',
            action='store_true',
        ),
    )

    def run(self, sensor_id, name, hardware_address, is_inactive):
        name = smart_str(name).strip()
        hardware_address = smart_str(hardware_address).strip()

        interface = SensorInterface(
            name=name,
            sensor_id=sensor_id,
            hardware_address=hardware_address,
            is_active=not is_inactive,
        )

        db.session.add(interface)
        db.session.commit()

        LOG.debug("Interface '{full_name}' is created (id={id})."
                  .format(full_name=interface.full_name, id=interface.id))


class ApplyPoliciesToInterface(Command):
    """
    Apply existing policies to specific sensor interface.
    """
    name = "apply_policies"

    option_list = (
        Option(
            '-i', '--interface-id',
            help="ID of interface which policies are applied to.",
            dest='interface_id',
            type=int,
            required=True,
        ),
        Option(
            '-p', '--policies',
            help="List of policy invokation infos (policy_id:action), "
                 "e.g.: '1:block 2:alert')",
            type=str,
            nargs='+',
            dest='policy_infos',
            required=True,
        ),
        Option(
            '--applied-by',
            help="ID of user who applies policies.",
            dest='applied_by_id',
            type=int,
            required=True,
        ),
    )

    def run(self, interface_id, policy_infos, applied_by_id):
        interface = SensorInterface.query.get(interface_id)
        if not interface:
            raise ValueError("Sensor interface #{id} does not exist"
                             .format(id=interface_id))

        applied_by = User.query.get(applied_by_id)
        if not applied_by:
            raise ValueError("User #{id} does not exist"
                             .format(id=applied_by_id))

        infos = []

        for policy in policy_infos:
            policy_id, action = policy.split(':')

            info = PolicyInvokationInfo({
                'policy_id': int(policy_id),
                'action': smart_str(action),
            })
            info.validate()
            infos.append(info)

        application_group = interface.apply_policies(infos, applied_by)

        LOG.debug(
            "Policy application group for interface '{full_name}' is created "
            "and scheduled (id={group.id}, task_id={group.task_id})."
            .format(full_name=interface.full_name,
                    group=application_group))
