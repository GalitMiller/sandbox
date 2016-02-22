# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from freezegun import freeze_time
from superdict import SuperDict

from app.core.tests.base import AppBaseTestCase
from app.db import db
from app.signatures.constants import RULE_ACTIONS
from app.signatures.models import (
    SignatureReference, SignatureReferenceType, SignatureClassType,
    SignatureProtocol, Signature,
)


class SignatureTestCase(AppBaseTestCase):

    maxDiff = None

    def setUp(self):
        super(SignatureTestCase, self).setUp()
        self._init_data()

    def _init_data(self):
        self._init_protocols()
        self._init_reference_type()
        self._init_class_type()
        db.session.commit()

    def _init_protocols(self):
        self.protocols = SuperDict({
            'tcp': SignatureProtocol(name='tcp'),
            'udp': SignatureProtocol(name='udp'),
        })
        db.session.add_all(self.protocols.values())

    def _init_reference_type(self):
        self.reference_type = SignatureReferenceType(
            name='url',
            url_prefix='http://',
        )
        db.session.add(self.reference_type)

    def _init_class_type(self):
        self.class_type = SignatureClassType(
            short_name='attempted-dos',
            name='Attempted Denial of Service',
            priority=2,
        )
        db.session.add(self.class_type)

    @freeze_time("2015-04-20")
    def test_make_signature(self):
        signature = Signature(
            action=RULE_ACTIONS.PASS,
            protocol=self.protocols.tcp,
            src_host='$HOME_NET',
            dst_host='$EXTERNAL_NET',
            name="A test signature",
            message="ET EXPLOIT MySQL MaxDB Buffer Overflow",
        )
        db.session.add(signature)
        db.session.commit()

        self.assertEqual(signature.sid, 2015042000)

        signature = Signature(
            action=RULE_ACTIONS.DROP,
            protocol=self.protocols.udp,
            src_host='10.10.10.10',
            dst_host='$EXTERNAL_NET',
            name="Another test signature",
            message="ET DNS Standard query response, Refused",
        )
        db.session.add(signature)
        db.session.commit()

        self.assertEqual(signature.sid, 2015042001)

    def test_make_i18n_signature(self):
        signature = Signature(
            action=RULE_ACTIONS.PASS,
            src_host='$HOME_NET',
            dst_host='$EXTERNAL_NET',
            protocol=self.protocols.tcp,
            name="Тестова сигнатура (a test signature in Ukrainian)",
            message="ET EXPLOIT BMP with invalid bfOffBits",
        )
        db.session.add(signature)
        db.session.commit()

    def test_from_string(self):
        string = """alert tcp $EXTERNAL_NET 31337 -> 10.10.10.10/24 any (msg:"ET EXPLOIT malformed Sack - Snort DoS-by-$um$id"; seq:0; ack:0; window:65535; dsize:0; reference:url,doc.emergingthreats.net/bin/view/Main/2002656; classtype:attempted-dos; sid:2002656; rev:4;)"""
        signature = Signature.from_string(
            s=string,
            name="test rule",
            severity_id=None,
            category_id=None,
        )

        self.assertEqual(Signature.query.count(), 1)
        self.assertEqual(signature.id, 1)
        self.assertEqual(signature.name, "test rule")
        self.assertEqual(signature.action, RULE_ACTIONS.ALERT)
        self.assertEqual(signature.protocol, self.protocols.tcp)
        self.assertEqual(signature.src_host, '$EXTERNAL_NET')
        self.assertEqual(signature.src_port, '31337')
        self.assertEqual(signature.dst_host, '10.10.10.10/24')
        self.assertEqual(signature.dst_port, 'any')
        self.assertFalse(signature.is_bidirectional)
        self.assertEqual(signature.message, "ET EXPLOIT malformed Sack - Snort DoS-by-$um$id")
        self.assertEqual(signature.flow_control, "")
        self.assertEqual(signature.content_control, "seq:0; ack:0; window:65535; dsize:0;")
        self.assertEqual(signature.class_type.short_name, 'attempted-dos')
        self.assertEqual(signature.sid, 2002656)
        self.assertEqual(signature.gid, 1)
        self.assertEqual(signature.revision, 4)

        self.assertEqual(len(signature.references), 1)
        self.assertEqual(SignatureReference.query.count(), 1)
        reference = signature.references[0]
        self.assertEqual(reference.id, 1)
        self.assertEqual(reference.reference_type.name, 'url')
        self.assertEqual(reference.value, "doc.emergingthreats.net/bin/view/Main/2002656")

    def test_to_string(self):
        class_type = (SignatureClassType.query
                      .filter_by(short_name='attempted-dos')
                      .first())
        reference_type = (SignatureReferenceType.query
                          .filter_by(name='url')
                          .first())

        signature = Signature(
            name="test rule",
            action=RULE_ACTIONS.ALERT,
            protocol=self.protocols.tcp,
            src_host='$EXTERNAL_NET',
            src_port='31337',
            dst_host='10.10.10.10/24',
            dst_port='any',
            is_bidirectional=False,
            message="ET EXPLOIT malformed Sack - Snort DoS-by-$um$id",
            flow_control=None,
            content_control="seq:0; ack:0; window:65535; dsize:0;",
            class_type=class_type,
            sid=2002656,
            gid=1,
            revision=4,
        )
        signature.references = [
            SignatureReference(
                reference_type=reference_type,
                value="doc.emergingthreats.net/bin/view/Main/2002656",
            ),
        ]

        rule = """alert tcp $EXTERNAL_NET 31337 -> 10.10.10.10/24 any (msg:"ET EXPLOIT malformed Sack - Snort DoS-by-$um$id"; seq:0; ack:0; window:65535; dsize:0; reference:url,doc.emergingthreats.net/bin/view/Main/2002656; classtype:attempted-dos; sid:2002656; gid:1; rev:4;)"""
        self.assertEqual(signature.to_string(), rule)
