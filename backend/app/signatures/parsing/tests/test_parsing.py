# -*- coding: utf-8 -*-

import unittest

from app.signatures.constants import RULE_ACTIONS
from app.signatures.parsing import parse_rule_string
from app.signatures.parsing.objects import RuleInfo, RuleReferenceInfo


class ParsingTestCaseBase(unittest.TestCase):

    def test_parse_rule(self):
        testee = """alert tcp $EXTERNAL_NET any -> 10.10.10.10 $HTTP_PORTS (msg:"ET EXPLOIT Linksys WRT54g Authentication Bypass Attempt"; flow:established,to_server; content:"/Security.tri"; nocase; http_uri; content:"SecurityMode=0"; nocase; reference:url,secunia.com/advisories/21372/; reference:url,doc.emergingthreats.net/bin/view/Main/2003072; classtype:attempted-admin; sid:2003072; rev:5;)"""

        data = parse_rule_string(testee)
        self.assertEqual(data.action, RULE_ACTIONS.ALERT)
        self.assertEqual(data.protocol, 'tcp')
        self.assertEqual(data.src_host, '$EXTERNAL_NET')
        self.assertEqual(data.src_port, 'any')
        self.assertEqual(data.dst_host, '10.10.10.10')
        self.assertEqual(data.dst_port, '$HTTP_PORTS')
        self.assertFalse(data.is_bidirectional)
        self.assertEqual(data.message, "ET EXPLOIT Linksys WRT54g Authentication Bypass Attempt")
        self.assertEqual(data.flow_control, "flow:established,to_server;")
        self.assertEqual(data.content_control, """content:"/Security.tri"; nocase; http_uri; content:"SecurityMode=0"; nocase;""")
        self.assertEqual(data.class_type, 'attempted-admin')
        self.assertEqual(data.sid, 2003072)
        self.assertEqual(data.revision, 5)
        self.assertEqual(data.reference_infos, [
            RuleReferenceInfo({
                'type_name': 'url',
                'value': "secunia.com/advisories/21372/",
            }),
            RuleReferenceInfo({
                'type_name': 'url',
                'value': "doc.emergingthreats.net/bin/view/Main/2003072",
            }),
        ])


class RuleInfoTestCase(unittest.TestCase):

    def test_to_string(self):
        info = RuleInfo({
            'action': RULE_ACTIONS.ALERT,
            'protocol': 'tcp',
            'src_host': "$EXTERNAL_NET",
            'src_port': None,
            'is_bidirectional': False,
            'dst_host': "10.10.10.10",
            'dst_port': "$HTTP_PORTS",
            'message': "ET EXPLOIT Linksys WRT54g Authentication Bypass Attempt",
            'flow_control': "flow:established,to_server;",
            'content_control': """content:"/Security.tri"; nocase; http_uri; content:"SecurityMode=0"; nocase;""",
            'class_type': "attempted-admin",
            'sid': 2003072,
            'gid': None,
            'revision': 5,
            'reference_infos': [
                RuleReferenceInfo({
                    'type_name': 'url',
                    'value': "secunia.com/advisories/21372/",
                }),
                RuleReferenceInfo({
                    'type_name': 'url',
                    'value': "doc.emergingthreats.net/bin/view/Main/2003072",
                }),
            ],
        })
        info.validate()
        rule = info.to_string()
        self.assertEqual(rule, """alert tcp $EXTERNAL_NET any -> 10.10.10.10 $HTTP_PORTS (msg:"ET EXPLOIT Linksys WRT54g Authentication Bypass Attempt"; flow:established,to_server; content:"/Security.tri"; nocase; http_uri; content:"SecurityMode=0"; nocase; reference:url,secunia.com/advisories/21372/; reference:url,doc.emergingthreats.net/bin/view/Main/2003072; classtype:attempted-admin; sid:2003072; rev:5;)""")

    def test_to_string_minimal_data(self):
        info = RuleInfo({
            'action': RULE_ACTIONS.ALERT,
            'protocol': 'tcp',
            'is_bidirectional': False,
            'message': "some message",
            'sid': 2003072,
        })
        info.validate()
        rule = info.to_string()
        self.assertEqual(rule, """alert tcp any any -> any any (msg:"some message"; sid:2003072;)""")
