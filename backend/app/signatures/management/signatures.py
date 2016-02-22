# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import random

from flask.ext.script import Command, Option
from isotopic_logging import autoprefix_injector
from unipath import Path

from app.config import RULES_PRIMARY_FILE_EXTENSION
from app.db import db
from app.signatures.constants import RULE_FORMATS
from app.signatures.models import Signature, SignatureCategory
from app.signatures.parsing import parse_rule_stream
from app.signatures.parsing.objects import RuleInfo
from app.utils.encoding import smart_str
from app.utils.six.moves import range
from app.utils.text import slug_to_name, generate_prefixed_filename


LOG = logging.getLogger(__name__)


class CreateSignature(Command):
    """
    Create new signature in database.
    """
    name = "create"

    option_list = (
        Option(
            '-a', '--action',
            help="Rule action",
            required=True,
        ),
        Option(
            '--protocol-id',
            help="Signature protocol ID.",
            required=True,
            dest='protocol_id',
            type=int,
        ),
        Option(
            '--src-host',
            help="Source host",
            dest='src_host',
        ),
        Option(
            '--src-port',
            help="Source port",
            dest='src_port',
        ),
        Option(
            '--dst-host',
            help="Destination host",
            dest='dst_host',
        ),
        Option(
            '--dst-port',
            help="Destination port",
            dest='dst_port',
        ),
        Option(
            '-b', '--bidirectional',
            help="Is rule bidirectional. Default: false (unidirectional).",
            dest='is_bidirectional',
            action='store_true',
        ),
        Option(
            '-n', '--name',
            help="Signature name",
            required=True,
        ),
        Option(
            '-c', '--category-id',
            help="Signature category ID.",
            required=True,
            dest='category_id',
            type=int,
        ),
        Option(
            '-m', '--message',
            required=True,
            help="Signature metamessage",
        ),
        Option(
            '--flow',
            help="Flow control options",
        ),
        Option(
            '--content',
            help="Content control options",
        ),
        Option(
            '-t', '--class-type-id',
            help="Signature class type ID.",
            dest='class_type_id',
            type=int,
        ),
        Option(
            '--severity-id',
            help="ID of signature severity.",
            dest='severity_id',
            type=int,
        ),
        Option(
            '--priority',
            help="Priority. Default: 1",
            type=int,
            default=1,
        ),
        Option(
            '-s', '--sid',
            help="Signature ID",
            type=int,
        ),
        Option(
            '-g', '--gid',
            help="Group ID. Default: 1",
            type=int,
            default=1,
        ),
        Option(
            '-r', '--revision',
            help="Group ID. Default: 1",
            type=int,
            default=1,
        ),
        Option(
            '--non-editable',
            help="Is rule non-editable. By default it's editable.",
            dest='is_non_editable',
            action='store_true',
        ),
        Option(
            '--created-by',
            help="Signature creator (ID of user).",
            dest='created_by_id',
        ),
    )

    def run(
        self, action, protocol_id, src_host, src_port, dst_host, dst_port,
        is_bidirectional, name, category_id, message, flow, content,
        class_type_id, severity_id, priority, sid, gid, revision,
        is_non_editable, created_by_id,
    ):
        action = smart_str(action).strip()
        src_host = smart_str(src_host).strip()
        dst_host = smart_str(dst_host).strip()
        name = smart_str(name).strip()
        message = smart_str(message).strip()

        signature = Signature(
            action=action,
            protocol_id=protocol_id,
            src_host=src_host,
            dst_host=dst_host,
            is_bidirectional=is_bidirectional,
            name=name,
            category_id=category_id,
            message=message,
            class_type_id=class_type_id,
            severity_id=severity_id,
            priority=priority,
            sid=Signature.generate_sid(base=sid),
            gid=gid,
            revision=revision,
            is_editable=not is_non_editable,
            created_by_id=created_by_id,
        )
        if src_port:
            signature.src_port = smart_str(src_port).strip()
        if dst_port:
            signature.dst_port = smart_str(dst_port).strip()
        if flow:
            signature.flow_control = smart_str(flow).strip()
        if content:
            signature.content_control = smart_str(content).strip()

        db.session.add(signature)
        db.session.commit()

        LOG.debug("Signature '{name}' is created (id={id})."
                  .format(name=name, id=signature.id))

        return signature


class ImportSignatures(Command):
    """
    Import signatures from rules file.
    """
    name = "import"

    option_list = (
        Option(
            '-p', '--filepath',
            help="Path to a '*.rules' file which is going to be imported.",
            required=True,
        ),
        Option(
            '-f', '--format',
            help="Format of rules which are going to be imported. "
                 "Default: '{0}'"
                 .format(RULE_FORMATS.SURICATA),
            choices=RULE_FORMATS._asdict().values(),
            default=RULE_FORMATS.SURICATA,
        ),
        Option(
            '-e', '--editable',
            help="Defines whether imported rules are editable. By default "
                 "they are non-editable.",
            dest='is_editable',
            action='store_true',
        ),
    )

    def run(self, filepath, format, is_editable):
        # TODO: format is currently not used

        self.filepath = Path(filepath)
        self.is_editable = is_editable

        succeded, failed = 0, 0

        LOG.info("Importing signatures from file '{filepath}"
                 .format(filepath=self.filepath))

        with open(self.filepath) as f:
            self._inject_category_id()

            for parsing_result in parse_rule_stream(f):
                signature = self._create_signature(parsing_result)
                if signature:
                    succeded += 1
                else:
                    failed += 1

        LOG.info("Succeded: {0}. Failed: {1}".format(succeded, failed))

    def _inject_category_id(self):
        category_name = slug_to_name(self.filepath.name.stem)
        category = SignatureCategory.query.get_or_create_by_name(category_name)
        self.category_id = category.id

        LOG.debug("Using category '{0}'".format(category.name))

    def _create_signature(self, parsing_result):
        with autoprefix_injector() as inj:
            if parsing_result.is_valid:
                try:
                    signature = Signature.from_info(
                        info=parsing_result.info,
                        category_id=self.category_id,
                        is_editable=self.is_editable,
                    )
                    signature.to_string_cache_set(parsing_result.source)
                except Exception as e:
                    LOG.error(inj.mark(
                        "Failed to import signature from rule '{rule}': {e}"
                        .format(rule=parsing_result.source, e=e)))
                else:
                    LOG.debug(inj.mark(
                        "Signature '{name}' is successfully imported "
                        "(id={id})."
                        .format(name=signature.name, id=signature.id)))
                    return True

            return False


class GenerateSignatures(Command):
    """
    Generate rules file.
    """
    name = "generate"

    class_types = [
        'attempted-admin', 'attempted-dos', 'attempted-recon',
        'attempted-user', 'bad-unknown', 'default-login-attempt',
        'denial-of-service', 'icmp-event', 'inappropriate-content',
        'misc-activity', 'misc-attack', 'network-scan',
        'non-standard-protocol', 'not-suspicious', 'policy-violation',
        'protocol-command-decode', 'rpc-portmap-decode', 'shellcode-detect',
        'string-detect', 'successful-admin', 'successful-dos',
        'successful-recon-largescale', 'successful-recon-limited',
        'successful-user', 'suspicious-filename-detect', 'suspicious-login',
        'system-call-detect', 'tcp-connection', 'trojan-activity', 'unknown',
        'unsuccessful-user', 'unusual-client-port-connection',
        'web-application-activity', 'web-application-attack',
    ]
    reference_types = [
        'arachNIDS', 'bid', 'bugtraq', 'cve', 'et', 'etpro', 'exploitdb',
        'McAfee', 'md5', 'msft', 'nessus', 'openpacket', 'osvdb', 'secunia',
        'securitytracker', 'telus', 'threatexpert', 'url', 'xforce',
    ]
    protocols = [
        'dns', 'ftp', 'http', 'icmp', 'ip', 'smb', 'tcp', 'tls', 'udp',
    ]

    option_list = (
        Option(
            '-c', '--count',
            help="Number of signatures to generate. Default: 1000",
            type=int,
            default=1000,
        ),
        Option(
            '-f', '--format',
            help="Format of rules which are going to be generated. "
                 "Default: '{0}'"
                 .format(RULE_FORMATS.SURICATA),
            choices=RULE_FORMATS._asdict().values(),
            default=RULE_FORMATS.SURICATA,
        ),
        Option(
            '-o', '--output',
            help="Path to a '*.rules' file which is going to be generated.",
            dest='filepath',
        ),
    )

    def run(self, count, format, filepath):
        # TODO: format is currently not used

        assert count > 0

        if not filepath:
            filepath = generate_prefixed_filename("generated",
                                                  RULES_PRIMARY_FILE_EXTENSION)

        filepath = Path(filepath).absolute()

        LOG.info("Generating {count} rule(s) to file '{filepath}'"
                 .format(count=count, filepath=filepath))

        with open(filepath, 'w') as f:
            for i in range(count):
                f.write(self.generate_rule() + '\n')

            f.flush()

        LOG.info("Done.")

    @classmethod
    def generate_rule(cls):
        info = RuleInfo.get_mock_object(overrides={
            'protocol': random.choice(cls.protocols),
            'class_type': random.choice(cls.class_types),
        })

        for ri in info.reference_infos:
            ri.type_name = random.choice(cls.reference_types)

        return info.to_string()
