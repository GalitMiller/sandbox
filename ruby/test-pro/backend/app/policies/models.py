# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import logging

from isotopic_logging import autoprefix_injector
from sqlalchemy.orm import Query

from app import celery
from app.db import db
from app.signatures.models import Signature
from app.utils import six
from app.utils.encoding import smart_str, smart_bytes

from .constants import POLICY_TYPES, POLICY_DEPLOYMENT_ACTIONS
from .tasks import invoke_policy_application_group


LOG = logging.getLogger(__name__)


class Policy(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
        nullable=False,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
    )
    description = db.Column(
        db.Unicode(255),
    )
    policy_type = db.Column(
        db.Enum(*POLICY_TYPES._asdict().values()),
        nullable=False,
    )
    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
    )
    created_by_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
    )
    created_by = db.relationship(
        'User',
        backref=db.backref('created_policies', lazy='dynamic'),
        foreign_keys=[created_by_id],
    )
    last_applied_at = db.Column(
        db.DateTime,
        nullable=True,
    )
    last_applied_by_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
    )
    last_applied_by = db.relationship(
        'User',
        foreign_keys=[last_applied_by_id],
    )
    signatures = db.relationship(
        'Signature',
        secondary=lambda: policy_signatures,
        backref=db.backref('policies', lazy='dynamic'),
    )

    @property
    def signatures_count(self):
        return Signature.query.with_parent(self, "signatures").count()

    def is_applied(self):
        return db.session.query(self.applications.exists()).scalar()

    def is_deletable(self):
        return not self.is_applied()

    def validate(self):
        # TODO: use some sqlalchemy-validation library
        if not self.signatures:
            raise ValueError("No signatures were specified")

    def __repr__(self):
        return smart_bytes("<Policy '{0}'>".format(self.name))


policy_signatures = db.Table(
    'policy_signatures',
    db.Column(
        'policy_id',
        db.Integer,
        db.ForeignKey('policy.id'),
        primary_key=True,
    ),
    db.Column(
        'signature_id',
        db.Integer,
        db.ForeignKey('signature.id'),
        primary_key=True,
    ),
)


class PolicyApplicationGroupQuery(Query):

    def get_or_create_for_interface(self, interface, commit=True):
        if not interface.application_group:
            interface.application_group = PolicyApplicationGroup(
                interface=interface,
            )

            db.session.add(interface.application_group)
            if commit:
                db.session.commit()

        return interface.application_group


class PolicyApplicationGroup(db.Model):
    __tablename__ = 'policy_application_group'

    id = db.Column(
        db.Integer,
        primary_key=True,
        nullable=False,
    )
    interface_id = db.Column(
        db.Integer,
        db.ForeignKey('sensor_interfaces.id'),
        unique=True,
    )
    interface = db.relationship(
        'SensorInterface',
        backref=db.backref('application_group', uselist=False),
    )
    task_id = db.Column(
        db.Unicode(255),
        index=True,
    )
    last_applied_at = db.Column(
        db.DateTime,
    )
    last_applied_by_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
    )
    last_applied_by = db.relationship(
        'User',
        backref=db.backref('application_groups', lazy='dynamic'),
    )

    query_class = PolicyApplicationGroupQuery

    @property
    def is_ready(self):
        return (self.task_id is not None
                and celery.AsyncResult(self.task_id).ready())

    def invoke(self, policy_invokation_infos, applied_by):
        """
        Create or update applications of policies using `PolicyInvokationInfo`
        and apply policies to sensor interface.
        """
        with autoprefix_injector():
            self._prepare_applications(policy_invokation_infos)
            self.last_applied_by = applied_by
            self.last_applied_at = datetime.datetime.utcnow()

            db.session.add(self)
            db.session.commit()

            return self._invoke()

    def _prepare_applications(self, policy_invokation_infos):
        new_actions = {x.policy_id: x.action for x in policy_invokation_infos}

        with autoprefix_injector() as inj:
            for application in self.applications[:]:
                # Remove action from 'new_actions' if policy was already
                # included into this application group, so new application will
                # not be created below
                new_action = new_actions.pop(application.policy_id, None)

                if new_action:
                    LOG.warning(inj.mark(
                        "'{policy_name}' is already applied to interface "
                        "'{interface_name}'"
                        .format(policy_name=application.policy.name,
                                interface_name=self.interface.full_name)))
                    self._check_existing_action(application, new_action)
                else:
                    self._exclude_application(application)

        self.applications.extend([
            PolicyApplication(
                action=action,
                policy_id=policy_id,
            )
            for policy_id, action in six.iteritems(new_actions)
        ])

    def _check_existing_action(self, application, new_action):
        with autoprefix_injector() as inj:
            old_action = application.action

            if new_action != old_action:
                LOG.warning(inj.mark(
                    "Action for '{policy_name}' will be changed from "
                    "'{old_action}' to '{new_action}'."
                    .format(policy_name=application.policy.name,
                            old_action=old_action,
                            new_action=new_action)))

                application.action = new_action
                db.session.add(application)

    def _exclude_application(self, application):
        with autoprefix_injector() as inj:
            LOG.warning(inj.mark(
                "Policy '{policy_name}' will be excluded from application."
                .format(policy_name=application.policy.name)))

            self.applications.remove(application)
            self._update_policy_application_info(application)
            db.session.delete(application)

    @staticmethod
    def _update_policy_application_info(application):
        group = (db.session.query(PolicyApplicationGroup)
                 .join(PolicyApplication,
                       PolicyApplicationGroup.id == PolicyApplication.group_id)
                 .filter(PolicyApplication.policy_id == application.policy_id)
                 .order_by(PolicyApplicationGroup.last_applied_at.desc())
                 .first())

        p = application.policy
        p.last_applied_at = group.last_applied_at if group else None
        p.last_applied_by = group.last_applied_by if group else None
        db.session.add(p)

    def _invoke(self):
        """
        Run background task to apply policies to sensor interface.
        """
        with autoprefix_injector() as inj:
            task = invoke_policy_application_group.apply_async(
                (self.id, inj.prefix, )
            )
            self.task_id = smart_str(task.id)

            db.session.add(self)
            db.session.commit()

            return self.task_id

    def __repr__(self):
        return smart_bytes(
            "<PolicyApplicationGroup for '{interface_name}'>"
            .format(interface_name=self.interface.full_name))


class PolicyApplication(db.Model):
    __tablename__ = 'policy_application'

    id = db.Column(
        db.Integer,
        primary_key=True,
        nullable=False,
    )
    group_id = db.Column(
        db.Integer,
        db.ForeignKey('policy_application_group.id'),
    )
    group = db.relationship(
        'PolicyApplicationGroup',
        backref=db.backref('applications', lazy='dynamic'),
    )
    policy_id = db.Column(
        db.Integer,
        db.ForeignKey('policy.id'),
    )
    policy = db.relationship(
        'Policy',
        backref=db.backref('applications', lazy='dynamic'),
    )
    action = db.Column(
        db.Enum(*POLICY_DEPLOYMENT_ACTIONS._asdict().values()),
        nullable=False,
    )
    target_filename = db.Column(
        db.Unicode(255),
    )

    __table_args__ = (
        db.UniqueConstraint(
            'group_id',
            'policy_id',
            name='application_group_can_include_single_policy_only_once',
        ),
    )

    def __repr__(self):
        return smart_bytes(
            "<PolicyApplication '{policy_name}' -> '{interface_name}'>"
            .format(policy_name=self.policy.name,
                    interface_name=self.group.interface.full_name))
