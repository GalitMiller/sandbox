# -*- coding: utf-8 -*-

import re
import unittest

from app.signatures.constants import RULE_ACTIONS, DIRECTIONS
from app.signatures.parsing.grammar import (
    VARIABLE_GRAMMAR, HOST_SEQUENCE_GRAMMAR, IPv4_GRAMMAR, HOST_GRAMMAR,
    PORT_SEQUENCE_GRAMMAR, PORT_GRAMMAR, DIRECTION_GRAMMAR, OPTION_GRAMMAR,
    RULE_GRAMMAR,
)


class GrammarTestCaseBase(unittest.TestCase):

    def setUp(self):
        self.regex = re.compile(self.testee, re.VERBOSE)

    @property
    def testee(self):
        raise NotImplementedError

    def parse(self, string):
        return self.regex.match(string)

    def extract_info(self, string):
        match = self.parse(string)
        self.assertIsNotNone(match)
        return match.groupdict()


class IPv4GrammarTestCase(GrammarTestCaseBase):

    testee = '^' + IPv4_GRAMMAR + '$'

    def test_valid_addresses(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))
            self.assertIsNotNone(self.parse(value + '/16'))
            self.assertIsNotNone(self.parse(value + '/24'))

        map(_assert, [
            '1.1.1.1',
            '10.1.1.1',
            '10.10.1.1',
            '10.255.255.254',
            '127.0.0.1',
            '132.254.111.10',
            '172.0.0.1',
            '172.16.0.1',
            '172.255.255.254',
            '172.31.255.254',
            '192.168.1.1',
            '192.168.255.254',
            '255.255.255.255',
            '26.10.2.10',
            '63.212.171.1',
            '63.212.171.254',
            '8.8.4.4',
            '8.8.8.8',
        ])

    def test_invalid_addresses(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            '10.10.10',
            '10.10',
            '10',
            'a.a.a.a',
            '10.0.0.a',
            '2222.22.22.22',
            '22.2222.22.2',
            '1.1.1.1/0',
            '1.1.1.1/32',
        ])


class VariableGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + VARIABLE_GRAMMAR + '$'

    def test_valid_variables(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            '$HOME_NET',
            '$EXTERNAL_NET',
        ])

    def test_invalid_variables(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            '$$FOO',
            '$FOO$',
            '$EXTERNAL\nNET',
        ])


class HostSequenceGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + HOST_SEQUENCE_GRAMMAR + '$'

    def test_valid_sequences(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            '[12,34,56]',
            '[ab, cd, ef]',
            '[any [text [at, ![all]]]]',
        ])

    def test_invalid_sequences(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            # '(12, 34)',
            # '(56, [78, 90])',
        ])


class HostGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + HOST_GRAMMAR + '$'

    def test_valid_hosts(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            '1.1.1.1',
            '!1.1.1.1',
            '! 1.1.1.1',
            '$HOME_NET',
            '!$HOME_NET',
            '! $HOME_NET',
            'any',
            '[98.126.44.98]',
            '[72.20.18.2,72.20.18.3]',
            '![1.1.1.1, 1.1.1.2]',
            '[$EXTERNAL_NET, !$HOME_NET]',
            '[10.0.0.0/24, !10.0.0.5]',
            '![66.220.157.64/26,66.220.157.16/29,66.220.157.48/28,66.220.157.24/29,66.220.144.128/27,66.220.157.128/27,66.220.144.160/29,66.220.157.160/29,66.220.144.168/29,66.220.157.168/29]',
        ])

    def test_invalid_hosts(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            # '1.1.1.1111',
            # '!!1.1.1.1',
            # '!  1.1.1.1',
            # '$$HOME_NET',
            # '!!$HOME_NET',
            # '!  $HOME_NET',
            # '!any',
            # '(1.1.1.1, 2.2.2.2)',
        ])


class PortSequenceGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + PORT_SEQUENCE_GRAMMAR + '$'

    def test_valid_sequences(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            "1024:",
            "80:82",
            "[1024:]",
            "[1024: ]",
            "[80,81,82]",
            "[80, 81, 82]",
            "[80:82]",
            "[80: 82]",
            "[80:100,!99]",
            "[1:80,![2,4]]",
        ])

    def test_invalid_sequences(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            # '(80, 443)',
        ])


class PortGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + PORT_GRAMMAR + '$'

    def test_valid_ports(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            '0',
            '80',
            '65535',
            '!80',
            '$SOME_PORT',
            '!$SOME_PORT',
            '! $SOME_PORT',
            'any',
        ])

    def test_invalid_ports(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            # '-1',
            # '65536',
            # '99999',
            # '!!80',
            # '!  80',
            # '$$SOME_PORT',
            # '!!$SOME_PORT',
            # '!  $SOME_PORT',
            # '!any',
        ])


class DirectionGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + DIRECTION_GRAMMAR + '$'

    def test_valid_directions(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            '->',
            '<>',
        ])

    def test_invalid_directions(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            '<-',
            '><',
            '!->',
            '<-!',
        ])


class OptionGrammarTestCase(GrammarTestCaseBase):

    testee = '^' + OPTION_GRAMMAR + '$'

    def test_valid_options(self):

        def _assert(value):
            self.assertIsNotNone(self.parse(value))

        map(_assert, [
            'msg:"ET EXPLOIT Invalid fragment - ACK reset";',
            'fragbits: M;',
            'flags: !A,12;',
            'reference:url,doc.emergingthreats.net/bin/view/Main/2001023;',
            'classtype:bad-unknown;',
            'flow: established,from_server;',
            'file_data;',
            'content:"|89 50 4E 47 0D 0A 1A 0A|";',
            'depth:8;',
            'byte_test:4,>,0x80000000,8,relative,big,string,hex;',
            'sid:2001023;',
            'rev:5;',
        ])

    def test_invalid_options(self):

        def _assert(value):
            self.assertIsNone(self.parse(value))

        map(_assert, [
            'flags',
            'flags;;',
            'rev 1',
            'rev 1;',
            'foo bar: 1;',
        ])


class RuleGrammarTestCase(GrammarTestCaseBase):

    testee = RULE_GRAMMAR

    def test_rule_info(self):
        rule = """alert tcp 1.1.1.1 80 -> $HOME_NET $HTTP_PORTS (msg:"ET EXPLOIT Possible CVE-2014-6271 Attempt Against SIP Proxy"; flow:to_server; content:"|28 29 20 7b|"; fast_pattern:only; reference:url,github.com/zaf/sipshock; classtype:attempted-admin; sid:2019289; rev:3;)"""
        info = self.extract_info(rule)

        self.assertEqual(info['action'], RULE_ACTIONS.ALERT)
        self.assertEqual(info['protocol'], 'tcp')
        self.assertEqual(info['src_host'], '1.1.1.1')
        self.assertEqual(info['src_port'], '80')
        self.assertEqual(info['direction'], DIRECTIONS.UNIDIRECTIONAL)
        self.assertEqual(info['dst_host'], '$HOME_NET')
        self.assertEqual(info['dst_port'], '$HTTP_PORTS')
        self.assertEqual(info['options'], """msg:"ET EXPLOIT Possible CVE-2014-6271 Attempt Against SIP Proxy"; flow:to_server; content:"|28 29 20 7b|"; fast_pattern:only; reference:url,github.com/zaf/sipshock; classtype:attempted-admin; sid:2019289; rev:3;""")
