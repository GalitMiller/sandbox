# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import difflib
import logging
import operator

from isotopic_logging import autoprefix_injector
from sqlalchemy import sql
from sqlalchemy.orm import Query

from app import app, cache
from app.config import RULES_DEFAULTS, CACHE_KEY_PREFIX
from app.db import db
from app.db.utils import raise_db_error
from app.utils.encoding import smart_bytes, smart_str
from app.utils.text import slug_to_name
from app.utils.transforms import flatten_values

from .constants import (
    RULE_ACTIONS, SEVERITY_LEVELS, SEVERITY_WEIGHTS,
    SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG
)
from .exceptions import (
    SignatureClassTypeAnalysisError, SignatureAnalysisError,
    SignatureReferenceTypeAnalysisError,
)
from .helpers import (
    signature_references_from_infos, severity_level_to_priority,
    priority_to_severity_level
)
from .parsing import parse_rule_string, parse_rule_class_type_string
from .parsing.objects import (
    RuleInfo, RuleReferenceInfo, RuleReferenceTypeInfo, RuleClassTypeInfo,
)
from .utils import generate_sid_base, generate_signature_name


LOG = logging.getLogger(__name__)


class SignatureCategoryQuery(Query):

    def get_or_create_default(self):
        return self.get_or_create_by_name(RULES_DEFAULTS.CATEGORY_NAME)

    def get_or_create_by_name(self, name):
        with autoprefix_injector() as inj:
            result = self.filter_by(name=name).first()

            if result is None:
                LOG.warning(inj.mark(
                    "Failed to detect signature category by name '{name}'."
                    .format(name=name)))
                result = self._create_from_name(name)

            return result

    @staticmethod
    def _create_from_name(name):
        with autoprefix_injector() as inj:
            LOG.info(inj.mark(
                "Trying to create new signature category '{name}'..."
                .format(name=name)))

            try:
                result = SignatureCategory(
                    name=name,
                )
                db.session.add(result)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Category was not created: {e}".format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Category was created successfully"))
                return result


class SignatureCategory(db.Model):
    """
    Groups signatures.
    """
    __tablename__ = 'signature_category'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
        index=True,
    )
    description = db.Column(
        db.Unicode(255),
        nullable=True,
    )

    query_class = SignatureCategoryQuery

    def is_deletable(self):
        return not db.session.query(self.signatures.exists()).scalar()

    def signatures_count(self):
        return self.signatures.count()

    def __repr__(self):
        return smart_bytes("<SignatureCategory '{0}'>".format(self.name))


class SignatureClassTypeQuery(Query):

    def get_or_create_by_short_name(self, short_name):
        with autoprefix_injector() as inj:
            result = self.get_by_short_name(short_name)

            if result is None:
                LOG.warning(inj.mark(
                    "Failed to detect class type by short name '{short_name}'."
                    .format(short_name=short_name)))
                result = self._create_from_short_name(short_name)

            return result

    def get_by_short_name(self, short_name):
        return self.filter_by(short_name=short_name).first()

    @staticmethod
    def name_exists(name):
        e = sql.exists().where(SignatureClassType.name == name)
        return db.session.query(e).scalar()

    @staticmethod
    def short_name_exists(short_name):
        e = sql.exists().where(SignatureClassType.short_name == short_name)
        return db.session.query(e).scalar()

    @staticmethod
    def _create_from_short_name(short_name):
        with autoprefix_injector() as inj:
            name = SignatureClassType.generate_name(short_name)

            LOG.info(inj.mark(
                "Trying to create new class type '{name}' ('{short_name}')..."
                .format(name=name, short_name=short_name)))

            try:
                result = SignatureClassType(
                    name=name,
                    short_name=short_name,
                )
                db.session.add(result)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Class type was not created: {e}".format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Class type was created successfully"))
                return result


class SignatureClassType(db.Model):
    __tablename__ = 'signature_class_type'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
    )
    short_name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
        index=True,
    )
    priority = db.Column(
        db.SmallInteger,
        nullable=False,
        default=severity_level_to_priority(SEVERITY_LEVELS.MEDIUM),
    )

    query_class = SignatureClassTypeQuery

    @staticmethod
    def generate_name(s):
        return slug_to_name(s)

    def is_deletable(self):
        return not db.session.query(self.signatures.exists()).scalar()

    @classmethod
    def from_string(cls, s):
        info = parse_rule_class_type_string(s)
        return cls.from_info(info)

    def to_string(self):
        return self.to_info().to_string()

    @classmethod
    def from_info(cls, info):
        instance = cls(
            name=info.name,
            short_name=info.short_name,
            priority=info.priority,
        )
        instance.save()
        return instance

    def to_info(self):
        return RuleClassTypeInfo(dict(
            name=self.name,
            short_name=self.short_name,
            priority=self.priority,
        ))

    @classmethod
    def analyze_info(cls, class_type_info):
        """
        May raise 'SignatureClassTypeAnalysisError'.
        """
        messages = []

        if SignatureClassType.query.name_exists(class_type_info.name):
            messages.append(
                "Class type with name '{name}' already exists."
                .format(name=class_type_info.name))

        if (
            SignatureClassType.query
            .short_name_exists(class_type_info.short_name)
        ):
            messages.append(
                "Class type with short name '{short_name}' already exists."
                .format(short_name=class_type_info.short_name))

        if messages:
            raise SignatureClassTypeAnalysisError(messages)

    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise_db_error(e)

    def __repr__(self):
        return smart_bytes("<SignatureClassType '{0}'>".format(self.name))


class SignatureSeverityQuery(Query):

    def __init__(self, *args, **kwargs):
        super(SignatureSeverityQuery, self).__init__(*args, **kwargs)
        self._predicates = {
            level: operator.and_(
                SignatureSeverity.weight >= the_range.min,
                SignatureSeverity.weight <= the_range.max
            )
            for level, the_range in SEVERITY_WEIGHTS.items()
        }

    def filter_by_severity_levels(self, *levels):
        predicate = reduce(operator.or_, [
            self._predicates[level] for level in levels
        ])
        return SignatureSeverity.query.filter(predicate)

    def get_or_create_default(self):
        return self.get_or_create_by_name(RULES_DEFAULTS.SEVERITY_NAME)

    def get_or_create_by_name(self, name):
        with autoprefix_injector() as inj:
            result = self.filter_by(name=name).first()

            if result is None:
                LOG.warning(inj.mark(
                    "Failed to detect signature severity by name '{name}'."
                    .format(name=name)))
                result = self._create_from_name(name)

            return result

    @staticmethod
    def _create_from_name(name):
        with autoprefix_injector() as inj:
            LOG.info(inj.mark(
                "Trying to create new signature severity '{name}'..."
                .format(name=name)))

            try:
                result = SignatureSeverity(
                    name=name,
                )
                db.session.add(result)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Severity was not created: {e}".format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Severity was created successfully"))
                return result


class SignatureSeverity(db.Model):
    __tablename__ = 'signature_severity'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
        index=True,
    )
    # TODO: use 'sqlalchemy_utils.ColorType'
    text_color = db.Column(
        db.String(255),
        nullable=False,
        index=True,
        default="#FFF",
    )
    # TODO: use 'sqlalchemy_utils.ColorType'
    bg_color = db.Column(
        db.String(255),
        nullable=False,
        index=True,
        default="#DDD",
    )
    weight = db.Column(
        db.SmallInteger,
        nullable=False,
        default=1,
    )
    is_predefined = db.Column(
        db.Boolean,
        default=False,
    )

    query_class = SignatureSeverityQuery

    def signatures_count(self):
        return self.signatures.count()

    def is_deletable(self):
        return not (self.is_predefined
                    or db.session.query(self.signatures.exists()).scalar())

    def __repr__(self):
        return smart_bytes("<SignatureSeverity '{0}'>".format(self.name))


class SignatureProtocolQuery(Query):

    def get_or_create_by_name(self, name):
        with autoprefix_injector() as inj:
            result = self.get_by_name(name)

            if result is None:
                LOG.warning(inj.mark(
                    "Failed to detect protocol by name '{name}'."
                    .format(name=name)))
                result = self._create_from_name(name)

            return result

    def get_by_name(self, name):
        return self.filter_by(name=name).first()

    @staticmethod
    def name_exists(name):
        e = sql.exists().where(SignatureProtocol.name == name)
        return db.session.query(e).scalar()

    @staticmethod
    def _create_from_name(name):
        with autoprefix_injector() as inj:
            LOG.info(inj.mark(
                "Trying to create new protocol '{name}'..."
                .format(name=name)))

            try:
                result = SignatureProtocol(
                    name=name,
                )
                db.session.add(result)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Protocol was not created: {e}".format(e=e)))
            else:
                LOG.info(inj.mark("Protocol was created successfully"))
                return result


class SignatureProtocol(db.Model):
    __tablename__ = 'signature_protocol'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
        index=True,
    )

    query_class = SignatureProtocolQuery

    def __repr__(self):
        return smart_bytes("<SignatureProtocol '{0}'>".format(self.name))


class SignatureQuery(Query):

    def empty_set(self):
        # TODO: extract to a base class
        return self.filter(sql.false())

    def get_by_sid(self, sid):
        return self.filter_by(sid=sid).first()

    @staticmethod
    def sid_exists(sid):
        e = sql.exists().where(Signature.sid == sid)
        return db.session.query(e).scalar()

    def filter_by_severity_levels(self, *levels):
        # TODO: optimize
        query = SignatureSeverity.query.filter_by_severity_levels(*levels)
        severity_ids = flatten_values(query.values('id'))

        if severity_ids:
            criterion = Signature.severity_id.in_(severity_ids)
            return db.session.query(Signature).filter(criterion)

        return self.empty_set()

    def filter_by_policy_type(self, policy_type,
                              signature_ids=None, category_ids=None):
        getter_name = '_filter_by_policy_type_' + policy_type
        getter = getattr(self, getter_name, None)

        if getter:
            result = getter(signature_ids=signature_ids,
                            category_ids=category_ids)
        else:
            result = None

        return result or self.empty_set()

    def _filter_by_policy_type_proAccelAll(self, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_ALL.
        """
        return self

    def _filter_by_policy_type_proAccelHigh(self, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_HIGH.
        """
        return self.filter_by_severity_levels(SEVERITY_LEVELS.HIGH)

    def _filter_by_policy_type_proAccelHighMedium(self, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_HIGH_N_MEDIUM.
        """
        return self.filter_by_severity_levels(SEVERITY_LEVELS.HIGH,
                                              SEVERITY_LEVELS.MEDIUM)

    def _filter_by_policy_type_proAccelLow(self, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_LOW.
        """
        return self.filter_by_severity_levels(SEVERITY_LEVELS.LOW)

    @staticmethod
    def _filter_by_policy_type_proAccelCustom(signature_ids, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_CUSTOM.
        """
        if signature_ids:
            criterion = Signature.id.in_(signature_ids)
            return db.session.query(Signature).filter(criterion)

    @staticmethod
    def _filter_by_policy_type_proAccelCategories(category_ids, **kwargs):
        """
        Return signatures for POLICY_TYPES.PRO_ACCEL_CATEGORIES.
        """
        if category_ids:
            criterion = Signature.category_id.in_(category_ids)
            return db.session.query(Signature).filter(criterion)


class Signature(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    action = db.Column(
        db.Enum(*RULE_ACTIONS._asdict().values()),
        nullable=False,
    )
    protocol_id = db.Column(
        db.Integer,
        db.ForeignKey('signature_protocol.id'),
    )
    protocol = db.relationship(
        'SignatureProtocol',
        backref=db.backref('signatures', lazy='dynamic'),
    )
    src_host = db.Column(
        db.Text,
    )
    src_port = db.Column(
        db.Text,
    )
    dst_host = db.Column(
        db.Text,
    )
    dst_port = db.Column(
        db.Text,
    )
    is_bidirectional = db.Column(
        db.Boolean,
        default=False,
    )
    name = db.Column(
        db.Text,
        nullable=False,
    )
    category_id = db.Column(
        db.Integer,
        db.ForeignKey('signature_category.id'),
    )
    category = db.relationship(
        'SignatureCategory',
        backref=db.backref('signatures', lazy='dynamic'),
    )
    message = db.Column(
        db.Text,
        nullable=False,
    )
    flow_control = db.Column(
        db.Text,
    )
    content_control = db.Column(
        db.Text,
    )
    class_type_id = db.Column(
        db.Integer,
        db.ForeignKey('signature_class_type.id'),
    )
    class_type = db.relationship(
        'SignatureClassType',
        backref=db.backref('signatures', lazy='dynamic'),
    )
    severity_id = db.Column(
        db.Integer,
        db.ForeignKey('signature_severity.id'),
    )
    severity = db.relationship(
        'SignatureSeverity',
        backref=db.backref('signatures', lazy='dynamic'),
    )
    priority = db.Column(
        db.SmallInteger,
    )
    sid = db.Column(
        db.BigInteger,
        unique=True,
        nullable=False,
        index=True,
        default=lambda: Signature.generate_sid(),
    )
    gid = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )
    revision = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )
    is_editable = db.Column(
        db.Boolean,
        default=True,
    )
    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
    )
    created_by_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=True,
    )
    created_by = db.relationship(
        'User',
        backref=db.backref('signatures', lazy='dynamic'),
    )

    query_class = SignatureQuery

    @classmethod
    def generate_sid(cls, base=None):
        sid = base if base is not None else generate_sid_base()

        while cls.query.sid_exists(sid):
            sid += 1

        return sid

    @staticmethod
    def generate_name(rule_info):
        # Some DB-related things can be done here in future
        return generate_signature_name(rule_info)

    def is_deletable(self):
        return not db.session.query(self.policies.exists()).scalar()

    @classmethod
    def from_string(
        cls, s, severity_id=SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG,
        category_id=None, name=None, is_editable=None, created_by=None
    ):
        info = parse_rule_string(s)
        instance = cls.from_info(
            info, severity_id, category_id, name, is_editable, created_by
        )
        instance.to_string_cache_set(s)
        return instance

    def to_string(self):
        s = cache.get(self._to_string_cache_key)

        if s is None:
            s = self.to_info().to_string()
            self.to_string_cache_set(s)

        return smart_str(s)

    def to_string_cache_set(self, value):
        """
        Use raw cache backend object to have infinite TTL.
        We need to use '.set()' instead of '.setex()', as it is done in
        'werkzeug' by default (see http://git.io/vqTmt).
        """
        if app.config['CACHE_ENABLED']:
            raw_key = CACHE_KEY_PREFIX + self._to_string_cache_key
            cache.cache._client.set(raw_key, smart_bytes(value))

    def to_string_cache_delete(self):
        if app.config['CACHE_ENABLED']:
            cache.delete(self._to_string_cache_key)

    @property
    def _to_string_cache_key(self):
        return "signature_to_string_%d" % self.sid

    def to_rule(self):
        return "# {name} ({sid})\n{rule}".format(
            name=self.name,
            sid=self.sid,
            rule=self.to_string()
        )

    @classmethod
    def from_info(
        cls, info, severity_id=SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG,
        category_id=None, name=None, is_editable=None, created_by=None
    ):
        with autoprefix_injector() as inj:
            if cls.query.sid_exists(info.sid):
                LOG.warning(inj.mark(
                    "Found existing signature with sid '{sid}'."
                    .format(sid=info.sid)))

                signature = cls.query.get_by_sid(info.sid)
                signature.update_from_info(
                    info, severity_id, category_id, name, is_editable,
                )
            else:
                signature = cls.create_from_info(
                    info, severity_id, category_id, name, is_editable,
                    created_by,
                )

            return signature

    @classmethod
    def create_from_info(
        cls, info, severity_id=SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG,
        category_id=None, name=None, is_editable=None, created_by=None
    ):
        name = name or cls.generate_name(info)
        protocol = (SignatureProtocol.query
                    .get_or_create_by_name(info.protocol))

        if info.class_type:
            class_type = (SignatureClassType.query
                          .get_or_create_by_short_name(info.class_type))
        else:
            class_type = None

        if info.priority is not None:
            priority = info.priority
        elif class_type:
            priority = class_type.priority
        else:
            priority = None

        if severity_id == SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG:
            if class_type:
                severity_level = priority_to_severity_level(
                    class_type.priority
                )
                severity_id = (SignatureSeverity.query
                               .get_or_create_by_name(severity_level)
                               .id)
            else:
                severity_id = (SignatureSeverity.query
                               .get_or_create_default()
                               .id)

        signature = cls(
            name=name,
            severity_id=severity_id,
            category_id=category_id,
            action=info.action,
            protocol=protocol,
            src_host=info.src_host,
            src_port=info.src_port,
            is_bidirectional=info.is_bidirectional,
            dst_host=info.dst_host,
            dst_port=info.dst_port,
            message=info.message,
            flow_control=info.flow_control,
            content_control=info.content_control,
            class_type=class_type,
            priority=priority,
            sid=info.sid,
            gid=info.gid,
            revision=info.revision,
            created_by=created_by,
        )

        if is_editable is not None:
            signature.is_editable = is_editable

        signature.references = list(signature_references_from_infos(
            info.reference_infos
        ))
        signature.save()

        return signature

    def update_from_info(
        self, info, severity_id=SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG,
        category_id=None, name=None, is_editable=None
    ):
        # We do not update signature created_by field.
        # TODO: refactor
        old_name = self.name[:]
        old_rule = self.to_string()
        old_severity_id = self.severity_id

        old_category_id = self.category_id
        if category_id is None:
            category_id = old_category_id
        category_id_changed = old_category_id != category_id

        old_is_editable = self.is_editable
        if is_editable is None:
            is_editable = old_is_editable
        is_editable_changed = old_is_editable != is_editable

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Updating signature '{name}'...".format(name=self.name)))

            self.name = name or self.generate_name(info)
            self.category_id = category_id
            self.action = info.action

            if info.protocol != self.protocol.name:
                self.protocol = (SignatureProtocol.query
                                 .get_or_create_by_name(info.protocol))

            self.src_host = info.src_host
            self.src_port = info.src_port
            self.is_bidirectional = info.is_bidirectional
            self.dst_host = info.dst_host
            self.dst_port = info.dst_port
            self.message = info.message
            self.flow_control = info.flow_control
            self.content_control = info.content_control

            if (
                info.class_type is not None
                and info.class_type != self.class_type.short_name
            ):
                self.class_type = (
                    SignatureClassType.query
                    .get_or_create_by_short_name(info.class_type)
                )

            if info.priority is not None:
                self.priority = info.priority
            elif self.class_type:
                self.priority = self.class_type.priority
            else:
                self.priority = None

            if severity_id == SEVERITY_BASED_ON_CLASS_TYPE_PRIORITY_FLAG:
                if self.class_type:
                    severity_level = priority_to_severity_level(
                        self.class_type.priority)
                    severity_id = (SignatureSeverity.query
                                   .get_or_create_by_name(severity_level)
                                   .id)
                else:
                    severity_id = (SignatureSeverity.query
                                   .get_or_create_default()
                                   .id)

            if severity_id is None:
                severity_id = old_severity_id
            severity_id_changed = old_severity_id != severity_id
            self.severity_id = severity_id

            self.gid = (
                info.gid or Signature.gid.property.columns[0].default.arg
            )
            self.revision = (
                info.revision
                or Signature.revision.property.columns[0].default.arg
            )
            self.is_editable = is_editable

            # Calculate which references must go away and which must be left
            new_references = {
                hash(x): x for x in info.reference_infos
            }
            old_references = {
                hash(x): x for x in self.references
            }
            obsolete_references = [
                old_references.pop(k)
                for k in old_references.keys()
                if k not in new_references
            ]

            for x in obsolete_references:
                self.references.remove(x)

            self.references.extend([
                # SQLAlchemy will add fresh objects to session automatically
                SignatureReference.from_info(v)
                for k, v in new_references.items()
                if k not in old_references
            ])

            new_rule = self.to_string()
            rule_changed = new_rule != old_rule

            if rule_changed:
                diff = difflib.Differ().compare([old_rule, ], [new_rule, ])
                diff = '\n'.join(diff)

                LOG.debug(inj.mark(
                    "Rule '{name}' was updated. Difference:\n{diff}"
                    .format(name=old_name, diff=diff)))

                for x in obsolete_references:
                    db.session.delete(x)

            if category_id_changed:
                LOG.debug(inj.mark(
                    "Category ID was changed from '{old}' to '{new}'."
                    .format(old=old_category_id, new=category_id)))

            if severity_id_changed:
                LOG.debug(inj.mark(
                    "Severity ID was changed from '{old}' to '{new}'."
                    .format(old=old_severity_id, new=severity_id)))

            if is_editable_changed:
                LOG.debug(inj.mark(
                    "Editability was changed from '{old}' to '{new}'."
                    .format(old=old_is_editable, new=is_editable)))

            if (
                rule_changed
                or is_editable_changed
                or category_id_changed
                or severity_id_changed
            ):
                self.save()
            else:
                LOG.debug(inj.mark("No changes were found."))

    def save(self):
        try:
            db.session.add(self)
            db.session.add_all(self.references)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise_db_error(e)

    def to_info(self):
        reference_infos = map(operator.methodcaller('to_info'),
                              self.references)
        return RuleInfo(dict(
            action=self.action,
            protocol=self.protocol.name,
            src_host=self.src_host,
            src_port=self.src_port,
            dst_host=self.dst_host,
            dst_port=self.dst_port,
            is_bidirectional=self.is_bidirectional,
            message=self.message,
            flow_control=self.flow_control,
            content_control=self.content_control,
            class_type=self.class_type.short_name if self.class_type else None,
            priority=self.priority,
            sid=self.sid,
            gid=self.gid,
            revision=self.revision,
            reference_infos=reference_infos,
        ))

    @classmethod
    def analyze_info(cls, rule_info):
        """
        Returns list of analysis messages.
        May raise 'SignatureAnalysisError'.
        """
        # TODO: refactor
        messages = []

        # Check for critical issues -------------------------------------------
        signature = Signature.query.get_by_sid(rule_info.sid)
        if signature and not signature.is_editable:
            messages.append(
                "Rule with SID '{sid}' already exists and it is non-editable."
                .format(sid=rule_info.sid))

        if messages:
            raise SignatureAnalysisError(messages)

        # Check for minor issues ----------------------------------------------
        if signature:
            messages.append(
                "Rule with SID '{sid}' already exists and it will be updated."
                .format(sid=rule_info.sid))

        if not SignatureProtocol.query.name_exists(rule_info.protocol):
            messages.append(
                "New protocol '{protocol}' will be added to CMC."
                .format(protocol=rule_info.protocol))

        short_name = rule_info.class_type
        if (
            short_name
            and not SignatureClassType.query.short_name_exists(short_name)
        ):
            name = SignatureClassType.generate_name(short_name)
            messages.append(
                "New class type '{name}' will be added to CMC."
                .format(name=name))

        for reference_info in rule_info.reference_infos:
            name = reference_info.type_name
            if not SignatureReferenceType.query.name_exists(name):
                messages.append(
                    "New reference type '{name}' will be added to CMC."
                    .format(name=name))

        return messages

    def __repr__(self):
        return smart_bytes("<Signature '{0}'>".format(self.name))


class SignatureReferenceTypeQuery(Query):

    def get_or_create_by_name(self, name):
        with autoprefix_injector() as inj:
            result = self.get_by_name(name)

            if result is None:
                LOG.warning(inj.mark(
                    "Failed to detect type of reference '{name}'."
                    .format(name=name)))
                result = self._create_from_name(name)

            return result

    def get_by_name(self, name):
        return self.filter_by(name=name).first()

    @staticmethod
    def name_exists(name):
        e = sql.exists().where(SignatureReferenceType.name == name)
        return db.session.query(e).scalar()

    @staticmethod
    def _create_from_name(name):
        with autoprefix_injector() as inj:
            LOG.info(inj.mark(
                "Trying to create new reference type '{name}'..."
                .format(name=name)))

            result = SignatureReferenceType(name=name)

            try:
                db.session.add(result)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Signature reference type was not created: {e}"
                    .format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Signature reference type was created successfully"))
                return result


class SignatureReferenceType(db.Model):
    __tablename__ = 'reference_type'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    name = db.Column(
        db.Unicode(255),
        unique=True,
        nullable=False,
        index=True,
    )
    # NOTE:
    #   This field is not used by CMC currently.
    #   It is assumed reference types will be imported from 'reference.config'
    #   in future during DB initialization.
    #   See example of 'reference.config': http://git.io/vUbMj
    url_prefix = db.Column(
        db.Unicode(255),
    )

    query_class = SignatureReferenceTypeQuery

    def is_deletable(self):
        return not db.session.query(self.references.exists()).scalar()

    @classmethod
    def from_string(cls, s):
        info = parse_rule_class_type_string(s)
        return cls.from_info(info)

    def to_string(self):
        return self.to_info().to_string()

    @classmethod
    def from_info(cls, info):
        instance = cls(
            name=info.name,
            url_prefix=info.url_prefix,
        )
        instance.save()
        return instance

    def to_info(self):
        return RuleReferenceTypeInfo(dict(
            name=self.name,
            url_prefix=self.url_prefix,
        ))

    @classmethod
    def analyze_info(cls, reference_type_info):
        """
        May raise 'SignatureReferenceTypeAnalysisError'.
        """
        messages = []

        if SignatureReferenceType.query.name_exists(reference_type_info.name):
            messages.append(
                "Reference type with name '{name}' already exists."
                .format(**reference_type_info))

        if messages:
            raise SignatureReferenceTypeAnalysisError(messages)

    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise_db_error(e)

    def __repr__(self):
        return smart_bytes("<SignatureReferenceType '{0}'>".format(self.name))


class SignatureReference(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )
    value = db.Column(
        db.Text,
        nullable=False,
    )
    reference_type_id = db.Column(
        db.Integer,
        db.ForeignKey('reference_type.id'),
    )
    reference_type = db.relationship(
        'SignatureReferenceType',
        backref=db.backref('references', lazy='dynamic'),
    )
    signature_id = db.Column(
        db.Integer,
        db.ForeignKey('signature.id'),
    )
    signature = db.relationship(
        'Signature',
        backref=db.backref('references', lazy='joined'),
    )

    @property
    def reference_type_name(self):
        if not self.reference_type:
            self.reference_type = SignatureReferenceType.query.get(
                self.reference_type_id
            )
        return self.reference_type.name if self.reference_type else "?"

    @classmethod
    def from_info(cls, reference_info):
        reference_type = (SignatureReferenceType.query
                          .get_or_create_by_name(reference_info.type_name))

        with db.session.no_autoflush:
            return SignatureReference(
                reference_type=reference_type,
                reference_type_id=reference_type.id,
                value=reference_info.value,
            )

    def to_info(self):
        return RuleReferenceInfo({
            'type_name': self.reference_type_name,
            'value': self.value,
        })

    def __repr__(self):
        return smart_bytes("<SignatureReference '{0}:{1}'>"
                           .format(self.reference_type_name,
                                   self.value))

    def __hash__(self):
        s = (self.reference_type_name + self.value).lower()
        return hash(s)
