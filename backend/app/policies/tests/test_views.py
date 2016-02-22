# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import urllib

from app.core.tests.base import AppBaseTestCase
from app.db import db
from app.policies.constants import POLICY_TYPES
from app.policies.models import Policy
from app.signatures.constants import RULE_ACTIONS
from app.signatures.models import Signature, SignatureProtocol
from app.users.sessions import make_session_cookie
from app.users.models import User


class ApiTestCase(AppBaseTestCase):

    def setUp(self):
        super(ApiTestCase, self).setUp()
        self._set_cookies()
        self._init_data()

    def _set_cookies(self):
        cookie = make_session_cookie(user_id=1)
        self.client.set_cookie('localhost', '_bricata_session', cookie)

    def _init_data(self):
        self._init_user()
        self._init_signature()
        self._init_policy()
        db.session.commit()

    def _init_user(self):
        self.user = User(
            login='admin',
            email='bricata@bricata.com',
            password="bricata",
            name="Administrator",
        )
        db.session.add(self.user)

    def _init_signature(self):
        self.protocol = SignatureProtocol(name='tcp')
        db.session.add(self.protocol)

        self.signature = Signature(
            action=RULE_ACTIONS.PASS,
            protocol=self.protocol,
            src_host='$HOME_NET',
            dst_host='$EXTERNAL_NET',
            name="A signature",
            message="ET EXPLOIT xp_enumdsn access",
        )
        db.session.add(self.signature)

    def _init_policy(self):
        self.policy = Policy(
            name="A test policy",
            description="A test policy description",
            policy_type=POLICY_TYPES.PRO_ACCEL_ALL,
            created_by=self.user,
        )
        self.policy.signatures.append(self.signature)
        db.session.add(self.policy)

    def test_delete_policy(self):
        # Check is policy accessible
        data = {'filters': [{'name': 'id', 'op': 'in', 'val': [1, ]}, ]}
        query = urllib.urlencode({'q': json.dumps(data)})
        response = self.client.get('/api/v1/policies?' + query)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['num_results'], 1)

        # Delete policy
        data = {'ids': [1, ]}
        query = urllib.urlencode({'q': json.dumps(data)})
        response = self.client.delete('/api/v1/policies?' + query)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['failed'], [])

        # Validata is policy deleted
        self.assertFalse(Policy.query.all())

        # Check is policy accessible
        data = {'filters': [{'name': 'id', 'op': 'in', 'val': [1, ]}, ]}
        query = urllib.urlencode({'q': json.dumps(data)})
        response = self.client.get('/api/v1/policies?' + query)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['num_results'], 0)
