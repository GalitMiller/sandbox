# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from app.core.tests.base import AppBaseTestCase
from app.db import db
from app.policies.constants import POLICY_TYPES
from app.policies.models import Policy
from app.signatures.constants import RULE_ACTIONS
from app.signatures.models import Signature, SignatureProtocol
from app.users.models import User


class PolicyTestCase(AppBaseTestCase):

    def test_flow(self):
        user = User(
            login="john",
            email="john@example.com",
            password="foobar",
            name="John Doe",
        )
        db.session.add(user)

        protocol = SignatureProtocol(name='tcp')
        db.session.add(protocol)

        signature = Signature(
            action=RULE_ACTIONS.PASS,
            protocol=protocol,
            src_host='$HOME_NET',
            dst_host='$EXTERNAL_NET',
            name="A signature",
            message="ET EXPLOIT xp_enumdsn access",
        )
        db.session.add(signature)

        policy = Policy(
            name="A test policy",
            description="A test policy description",
            policy_type=POLICY_TYPES.PRO_ACCEL_ALL,
            created_by=user,
        )
        policy.signatures.append(signature)
        db.session.add(policy)
        db.session.commit()

        db.session.delete(policy)
        db.session.commit()

        self.assertFalse(Policy.query.all())
