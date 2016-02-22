# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import string

from flask.ext.script import Command, Option

from app.policies.management.policies import CreatePolicy
from app.sensors.management.interfaces import (
    CreateSensorInterface, ApplyPoliciesToInterface,
)
from app.sensors.management.sensors import CreateSensor
from app.signatures.constants import SEVERITY_WEIGHTS
from app.signatures.management.categories import CreateSignatureCategory
from app.signatures.management.class_types import CreateSignatureClassType
from app.signatures.management.protocols import CreateSignatureProtocol
from app.signatures.management.reference_types import CreateReferenceType
from app.signatures.management.references import CreateReference
from app.signatures.management.severities import CreateSignatureSeverity
from app.signatures.management.signatures import CreateSignature
from app.users.management.users import CreateUser

from app.utils.six.moves import map, filter


LOG = logging.getLogger(__name__)


class PrepopulateDatabase(Command):
    """
    Prepopulate empty DB with initial data.
    """
    name = "prepopulate"

    option_list = (
        Option(
            '-x', '--extra',
            help="Put extra data (signatures, policies, etc.). Used mainly "
                 "for local development",
            action='store_true',
        ),
    )

    def run(self, extra):
        self._create_primary_data()
        if extra:
            self._create_extra_data()

    def _create_primary_data(self):
        LOG.debug("Filling up DB with primary data")
        self._create_signature_classtypes()
        self._create_signature_severities()
        self._create_signature_reference_types()
        self._create_signature_protocols()
        self._create_signature_categories()

    def _create_signature_classtypes(self):
        # TODO: extract importer to a separate command
        create = CreateSignatureClassType().run

        lines = [
            "config classification: not-suspicious,Not Suspicious Traffic,3",
            "config classification: unknown,Unknown Traffic,3",
            "config classification: bad-unknown,Potentially Bad Traffic, 2",
            "config classification: attempted-recon,Attempted Information Leak,2",
            "config classification: successful-recon-limited,Information Leak,2",
            "config classification: successful-recon-largescale,Large Scale Information Leak,2",
            "config classification: attempted-dos,Attempted Denial of Service,2",
            "config classification: successful-dos,Denial of Service,2",
            "config classification: attempted-user,Attempted User Privilege Gain,1",
            "config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1",
            "config classification: successful-user,Successful User Privilege Gain,1",
            "config classification: attempted-admin,Attempted Administrator Privilege Gain,1",
            "config classification: successful-admin,Successful Administrator Privilege Gain,1",
            "config classification: rpc-portmap-decode,Decode of an RPC Query,2",
            "config classification: shellcode-detect,Executable Code was Detected,1",
            "config classification: string-detect,A Suspicious String was Detected,3",
            "config classification: suspicious-filename-detect,A Suspicious Filename was Detected,2",
            "config classification: suspicious-login,An Attempted Login Using a Suspicious Username was Detected,2",
            "config classification: system-call-detect,A System Call was Detected,2",
            "config classification: tcp-connection,A TCP Connection was Detected,4",
            "config classification: trojan-activity,A Network Trojan was Detected, 1",
            "config classification: unusual-client-port-connection,A Client was Using an Unusual Port,2",
            "config classification: network-scan,Detection of a Network Scan,3",
            "config classification: denial-of-service,Detection of a Denial of Service Attack,2",
            "config classification: non-standard-protocol,Detection of a Non-Standard Protocol or Event,2",
            "config classification: protocol-command-decode,Generic Protocol Command Decode,3",
            "config classification: web-application-activity,Access to a Potentially Vulnerable Web Application,2",
            "config classification: web-application-attack,Web Application Attack,1",
            "config classification: misc-activity,Misc activity,3",
            "config classification: misc-attack,Misc Attack,2",
            "config classification: icmp-event,Generic ICMP event,3",
            "config classification: inappropriate-content,Inappropriate Content was Detected,1",
            "config classification: policy-violation,Potential Corporate Privacy Violation,1",
            "config classification: default-login-attempt,Attempt to Login By a Default Username and Password,2",
        ]
        lines = map(string.strip, lines)
        lines = filter(lambda x: x and not x.startswith('#'), lines)

        for line in lines:
            meaningful_part = line.split(": ", 1)[1]
            short_name, name, priority = meaningful_part.split(',')

            create(name=name, short_name=short_name, priority=int(priority))

    def _create_signature_severities(self):
        create = CreateSignatureSeverity().run
        data = [
            ("High", "#FFF", "#F00", SEVERITY_WEIGHTS.HIGH.default, True, ),
            ("Medium", "#FFF", "#FAB908", SEVERITY_WEIGHTS.MEDIUM.default, True, ),
            ("Low", "#FFF", "#3A781A", SEVERITY_WEIGHTS.LOW.default, True, ),
        ]

        for name, text_color, bg_color, weight, is_predefined in data:
            create(
                name=name,
                text_color=text_color,
                bg_color=bg_color,
                weight=weight,
                is_predefined=is_predefined,
            )

    def _create_signature_reference_types(self):
        # TODO: extract importer to a separate command
        create = CreateReferenceType().run

        lines = [
            "# config reference: system URL",
            "",
            "config reference: bugtraq   http://www.securityfocus.com/bid/",
            "config reference: bid       http://www.securityfocus.com/bid/",
            "config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=",
            "#config reference: cve       http://cvedetails.com/cve/",
            "config reference: secunia   http://www.secunia.com/advisories/",
            "",
            "#whitehats is unfortunately gone",
            "config reference: arachNIDS http://www.whitehats.com/info/IDS",
            "",
            "config reference: McAfee    http://vil.nai.com/vil/content/v_",
            "config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=",
            "config reference: url       http://",
            "config reference: et        http://doc.emergingthreats.net/",
            "config reference: etpro     http://doc.emergingthreatspro.com/",
            "config reference: telus     http://",
            "config reference: osvdb     http://osvdb.org/show/osvdb/",
            "config reference: threatexpert http://www.threatexpert.com/report.aspx?md5=",
            "config reference: md5       http://www.threatexpert.com/report.aspx?md5=",
            "config reference: exploitdb http://www.exploit-db.com/exploits/",
            "config reference: openpacket https://www.openpacket.org/capture/grab/",
            "config reference: securitytracker http://securitytracker.com/id?",
            "# config reference: secunia   http://secunia.com/advisories/",
            "config reference: xforce    http://xforce.iss.net/xforce/xfdb/",
            "config reference: msft      http://technet.microsoft.com/security/bulletin/",
        ]
        lines = map(string.strip, lines)
        lines = filter(lambda x: x and not x.startswith('#'), lines)

        for line in lines:
            meaningful_part = line.split(": ", 1)[1]
            name, url_prefix = meaningful_part.split()
            create(name=name, url_prefix=url_prefix)

    def _create_signature_protocols(self):
        create = CreateSignatureProtocol().run
        data = [
            'tcp', 'udp', 'ip', 'dns', 'ftp', 'http', 'icmp', 'smb', 'tls',
        ]

        for name in data:
            create(name=name)

    def _create_signature_categories(self):
        create = CreateSignatureCategory().run
        data = {
            'name': 'Imported',
            'description': 'Category for imported signatures.'
        }

        create(name=data['name'], description=data['description'])

    def _create_extra_data(self):
        LOG.debug("Filling up DB with extra data")
        self._create_extra_users()
        self._create_extra_signature_categories()
        self._create_extra_signatures()
        self._create_extra_sensors()
        self._create_extra_policies()
        self._apply_extra_policies()

    def _create_extra_users(self):
        create = CreateUser().run
        data = [
            ('admin', 'p@$$w0rd', 'John Doe', 'root@localhost.localdomain', 'admin', True, ),
            ('oper', 'p@$$w0rd', 'Lena Ophra', 'lena@localhost.localdomain', 'operator', True, ),
            ('analyst', 'p@$$w0rd', 'Omar Kumar', 'omar@localhost.localdomain', 'analyst', True, ),
            ('user1', 'p@$$w0rd', 'User1', 'user1@domain.net', 'operator', True, ),
            ('user2', 'p@$$w0rd', 'User2', 'user2@domain.net', 'operator', False, ),
            ('user3', 'p@$$w0rd', 'User3', 'user3@domain.net', 'operator', False, ),
            ('вася', 'p@$$w0rd', 'Вася Пупкін (Vasya Pupkin)', 'вася@м’ясо.укр', 'analyst', False, ),
        ]

        for login, password, name, email, role, active in data:
            create(
                login=login,
                password=password,
                name=name,
                email=email,
                role=role,
                active=active,
            )

    def _create_extra_signature_categories(self):
        create = CreateSignatureCategory().run
        data = [
            {
                'name': 'Primary category',
                'description': 'Primary category for signatures.'
            },
            {
                'name': 'Secondary category',
                'description': 'Secondary category for signatures.'
            },
        ]

        for item in data:
            create(name=item['name'], description=item['description'])

    def _create_extra_signatures(self):
        create_signature = CreateSignature().run
        create_reference = CreateReference().run

        # Signature #1 --------------------------------------------------------
        signature = create_signature(
            action='pass',
            protocol_id=1,
            src_host='$HOME_NET',
            src_port='10000',
            dst_host='$EXTERNAL_NET',
            dst_port=None,
            is_bidirectional=False,
            name="First signature",
            message="""ET CHAT IRC USER command""",
            flow="""flow:established,to_server; flowbits:set,ET.Tomcat.login.attempt;""",
            content="""dsize:<135; content:"THCTHCTHCTHCTHC|20 20 20|";""",
            category_id=1,
            class_type_id=1,
            severity_id=1,
            priority=1,
            sid=None,
            gid=1,
            revision=1,
            is_non_editable=False,
            created_by_id=1,
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=2,
            value="6241",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=3,
            value="2002-1317",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=4,
            value="11188",
        )

        # Signature #2 --------------------------------------------------------
        signature = create_signature(
            action='drop',
            protocol_id=2,
            src_host='$HOME_NET',
            src_port=None,
            dst_host='$EXTERNAL_NET',
            dst_port='9100',
            is_bidirectional=True,
            name="Second signature",
            message="""GPL CHAT MSN outbound file transfer request""",
            flow="""flow:to_server;""",
            content="""content:"User-Agent|3a| bsqlbf"; fast_pattern:only; http_header; nocase;""",
            category_id=2,
            class_type_id=3,
            severity_id=2,
            priority=2,
            sid=None,
            gid=2,
            revision=3,
            is_non_editable=False,
            created_by_id=2,
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=2,
            value="5731",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=2,
            value="6024",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=3,
            value="2002-1226",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=3,
            value="2002-1235",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=7,
            value="www.kb.cert.org/vuls/id/875073",
        )

        # Signature #3 --------------------------------------------------------
        signature = create_signature(
            action='reject',
            protocol_id=3,
            src_host='$EXTERNAL_NET',
            src_port='HTTP_PORTS',
            dst_host='$HOME_NET',
            dst_port='4242',
            is_bidirectional=False,
            name="Third signature",
            message="""ET EXPLOIT JamMail Jammail.pl Remote Command Execution Attempt""",
            flow="""flow: established; flowbits:isset,ET.Tomcat.login.attempt;""",
            content="""content:"ENTER LANGUAGE ="; depth:50; nocase; isdataat:55,relative; content:!"|0A|"; within:55; pcre:"/ENTER\x20LANGUAGE\x20\x3D.{55}/smi";""",
            category_id=3,
            class_type_id=10,
            severity_id=3,
            priority=255,
            sid=None,
            gid=4,
            revision=10,
            is_non_editable=False,
            created_by_id=2,
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=2,
            value="1065",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=2,
            value="968",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=3,
            value="2000-0071",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=3,
            value="2000-0126",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=4,
            value="10115",
        )
        create_reference(
            signature_id=signature.id,
            reference_type_id=5,
            value="553",
        )

    def _create_extra_sensors(self):
        create_sensor = CreateSensor().run
        create_interface = CreateSensorInterface().run

        # Sensor #1 -----------------------------------------------------------
        sensor = create_sensor(
            name="Alpha sensor",
            hostname="10.10.10.10",
            ssh_port=None,
            is_inactive=False,
            is_controlled_by_cmc=True,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth0",
            hardware_address="0C:F5:B7:A8:2E:9E",
            is_inactive=False,
        )

        # Sensor #2 -----------------------------------------------------------
        sensor = create_sensor(
            name="Bravo sensor",
            hostname="20.20.20.20",
            ssh_port=None,
            is_inactive=True,
            is_controlled_by_cmc=True,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth0",
            hardware_address="2A:CD:8A:A5:D2:C8",
            is_inactive=False,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth1",
            hardware_address="3D:B3:33:C7:F9:24",
            is_inactive=False,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth2",
            hardware_address="E8:36:47:53:66:53",
            is_inactive=True,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth3",
            hardware_address="56:78:03:94:31:98",
            is_inactive=True,
        )

        # Sensor #3 -----------------------------------------------------------
        sensor = create_sensor(
            name="Charlie sensor",
            hostname="30.30.30.30",
            ssh_port=2222,
            is_inactive=False,
            is_controlled_by_cmc=False,
        )
        create_interface(
            sensor_id=sensor.id,
            name="eth0",
            hardware_address="88:B0:76:65:AD:17",
            is_inactive=False,
        )
        create_interface(
            sensor_id=sensor.id,
            name="wlan0",
            hardware_address="5A:9B:B5:81:5A:F9",
            is_inactive=False,
        )

    def _create_extra_policies(self):
        create_policy = CreatePolicy().run

        create_policy(
            name="First policy",
            description="First policy for testing.",
            policy_type='proAccelAll',
            created_by_id=1,
        )
        create_policy(
            name="Second policy",
            description="Second policy for testing.",
            policy_type='proAccelHigh',
            created_by_id=2,
        )
        create_policy(
            name="Third policy",
            description="Third policy for testing.",
            policy_type='proAccelCategories',
            created_by_id=3,
            category_ids=[1, 3, ],
        )
        create_policy(
            name="Fourth policy",
            description="Fourth policy for testing.",
            policy_type='proAccelCustom',
            created_by_id=4,
            signature_ids=[1, 2, 3, ],
        )

    def _apply_extra_policies(self):
        apply_policy = ApplyPoliciesToInterface().run

        apply_policy(
            interface_id=1,
            policy_infos=["1:alert", "2:block", "3:alert", "4:block", ],
            applied_by_id=1,
        )
        apply_policy(
            interface_id=2,
            policy_infos=["2:alert", "4:block", ],
            applied_by_id=1,
        )
        apply_policy(
            interface_id=3,
            policy_infos=["1:alert", "2:alert", ],
            applied_by_id=2,
        )
        apply_policy(
            interface_id=4,
            policy_infos=["2:block", "3:block", ],
            applied_by_id=3,
        )
