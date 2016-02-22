# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.policies.constants import POLICY_TYPES
from app.policies.models import Policy, Signature
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreatePolicy(Command):
    """
    Create new policy.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Policy name.",
            required=True,
        ),
        Option(
            '-d', '--description',
            help="Policy description.",
        ),
        Option(
            '-t', '--policy-type',
            help="Policy type.",
            dest='policy_type',
            choices=POLICY_TYPES._asdict().values(),
        ),
        Option(
            '--created-by',
            help="Policy creator (ID of user).",
            required=True,
            dest='created_by_id',
        ),
        Option(
            '--signatures',
            help="List of IDs of signatures which are included into policy.",
            dest='signature_ids',
            type=int,
            nargs='+',
        ),
        Option(
            '--categories',
            help="List of IDs of signature categories which are included into "
                 "policy.",
            dest='category_ids',
            type=int,
            nargs='+',
        ),
    )

    def run(
        self, name, description, policy_type, created_by_id,
        signature_ids=None, category_ids=None,
    ):
        signatures = Signature.query.filter_by_policy_type(
            policy_type=policy_type,
            signature_ids=signature_ids,
            category_ids=category_ids,
        )
        policy = Policy(
            name=smart_str(name).strip(),
            description=smart_str(description).strip(),
            policy_type=policy_type,
            signatures=list(signatures),
            created_by_id=created_by_id,
        )

        policy.validate()
        db.session.add(policy)
        db.session.commit()

        LOG.debug("Policy '{name}' is created (id={id})."
                  .format(name=name, id=policy.id))

        return policy
