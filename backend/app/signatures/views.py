# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import os
import ujson as json

from flask import abort, request
from flask.ext.login import current_user
from flask.ext.restless.views import API
from flask.views import MethodView
from isotopic_logging import autoprefix_injector
from schematics.exceptions import ValidationError
from sqlalchemy import func

from app import app, api_manager
from app.core.views.api import (
    api_url, api_url_prefix, paginate_objects, APISuccess, APIBadRequest,
    APINotFound,
)
from app.db import db
from app.users.decorators import api_login_required
from app.users.models import User
from app.utils import six
from app.utils.decorators import method_decorator
from app.utils.encoding import smart_str
from app.utils.http import FileResponse
from app.utils.text import generate_prefixed_filename
from app.utils.transforms import to_string_list

from .exceptions import (
    SignatureAnalysisError, SignatureClassTypeAnalysisError,
    SignatureReferenceTypeAnalysisError, InvalidRulesFileError,
    InvalidRuleClassTypesFileError, InvalidRuleReferenceTypesFileError,
)
from .helpers import (
    signatures_to_rules, signature_reference_types_to_strings,
    signature_class_types_to_strings, snorby_signature_ids_by_sid,
)
from .models import (
    SignatureReferenceType, SignatureReference, SignatureClassType,
    SignatureSeverity, SignatureCategory, SignatureProtocol, Signature,
)
from .parsing import (
    parse_rule_stream, parse_rule_reference_type_stream,
    parse_rule_class_type_stream,
)
from .parsing.objects import RuleInfo, RuleReferenceInfo
from .preprocessors import (
    signature_data_preprocessor, signature_severity_post_preprocessor,
    signature_severity_put_preprocessor,
    signature_severity_delete_preprocessor,
    import_signature_single_rule_preprocessor,
    reference_type_post_preprocessor,
)
from .serializers import (
    SIGNATURE_REFERENCE_INCLUDE_COLUMNS,
    SIGNATURE_REFERENCE_TYPE_INCLUDE_COLUMNS,
    SIGNATURE_REFERENCE_TYPE_INCLUDE_METHODS,
    SIGNATURE_CATEGORY_INCLUDE_COLUMNS, SIGNATURE_CATEGORY_INCLUDE_METHODS,
    SIGNATURE_CLASS_TYPE_INCLUDE_COLUMNS, SIGNATURE_CLASS_TYPE_INCLUDE_METHODS,
    SIGNATURE_SEVERITY_INCLUDE_COLUMNS, SIGNATURE_SEVERITY_INCLUDE_METHODS,
    SIGNATURE_PROTOCOL_INCLUDE_COLUMNS, SIGNATURE_INCLUDE_METHODS,
    SIGNATURE_INCLUDE_COLUMNS_LITE, SIGNATURE_INCLUDE_METHODS_LITE,
    signature_category_serializer, signature_category_heavy_serializer,
    signature_category_update_serializer, signature_category_lite_serializer,
    signature_severity_serializer, signature_serializer,
)


LOG = logging.getLogger(__name__)


# References ------------------------------------------------------------------
api_manager.create_api(
    model=SignatureReference,
    collection_name='references',
    include_columns=SIGNATURE_REFERENCE_INCLUDE_COLUMNS,
    methods=['GET', 'POST', 'DELETE', 'PUT', ],
    url_prefix=api_url_prefix(version=1),
)


# Reference types -------------------------------------------------------------
api_manager.create_api(
    model=SignatureReferenceType,
    collection_name='reference_types',
    include_columns=SIGNATURE_REFERENCE_TYPE_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_REFERENCE_TYPE_INCLUDE_METHODS,
    methods=['GET', 'POST', 'PUT', ],
    preprocessors={
        'POST': [reference_type_post_preprocessor, ],
    },
    url_prefix=api_url_prefix(version=1),
)


@app.route(api_url('/reference_types', version=1), methods=['DELETE', ])
@api_login_required
def delete_signature_reference_types_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    failed = []

    try:
        for reference_type_id in q.get('ids', []):
            reference_type = (SignatureReferenceType.query
                              .get(reference_type_id))
            if reference_type:
                if reference_type.is_deletable():
                    db.session.delete(reference_type)
                else:
                    LOG.error("Failed to delete reference type #{id}: "
                              "reference type which included in reference "
                              "cannot be deleted."
                              .format(id=reference_type.id))
                    failed.append({
                        'id': reference_type.id,
                        'name': reference_type.name,
                        'message': "This reference type is included in "
                                   "reference and cannot be deleted.",
                    })
            else:
                LOG.error("Failed to delete reference type in bulk"
                          "request: reference type #{id} does not exist."
                          .format(id=reference_type_id))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete reference types: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


class ImportSignatureReferenceTypeView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        """
        Returns info list about invalid reference types.
        All valid reference types will be saved to DB.
        """
        with autoprefix_injector() as inj:
            try:
                self._inject_file()
            except InvalidRuleReferenceTypesFileError as e:
                LOG.error(e.message)
                return APIBadRequest(message=e.message)

            try:
                failed = list(self._parse_stream())
            except Exception as e:
                failed = []
                LOG.error(inj.mark(
                    "Failed to import reference types from file '{filename}': "
                    "{e}"
                    .format(filename=self.file.filename, e=e)))
            finally:
                self.file.stream.seek(0)

        return APISuccess({'failed': failed})

    def _inject_file(self):
        self.file = request.files.get('file')

        if not self.file:
            raise InvalidRuleReferenceTypesFileError(
                "Failed to import reference types: file was not provided.")

        self._ensure_file_extension()

    def _ensure_file_extension(self):
        extension = os.path.splitext(self.file.filename)[1][1:]

        if not extension:
            raise InvalidRuleReferenceTypesFileError(
                "Failed to import reference types: unsupported format.")

        extensions = app.config['RULE_REFERENCE_TYPES_ALLOWED_EXTENSIONS']
        if extension not in extensions:
            raise InvalidRuleReferenceTypesFileError(
                "Failed to import reference types: unsupported format '{0}'."
                .format(extension))

    def _parse_stream(self):
        results = parse_rule_reference_type_stream(self.file.stream)
        failed = map(self._process_result, results)
        return filter(bool, failed)

    @classmethod
    def _process_result(cls, parsing_result):
        if parsing_result.is_valid:
            try:
                SignatureReferenceType.analyze_info(parsing_result.info)
                SignatureReferenceType.from_info(parsing_result.info)
            except SignatureReferenceTypeAnalysisError as e:
                cls._on_processing_error(parsing_result, e.messages)
            except Exception as e:
                cls._on_processing_error(parsing_result, [e.message, ])

        # Return failed results only
        if not parsing_result.is_valid:
            return parsing_result.to_primitive()

    @staticmethod
    def _on_processing_error(parsing_result, messages):
        # TODO: extract to base class
        parsing_result.is_valid = False
        parsing_result.messages.extend(messages)

        with autoprefix_injector() as inj:
            reason = to_string_list(messages)
            LOG.error(inj.mark(
                "Failed to import reference type from string '{source}': "
                "{reason}"
                .format(source=parsing_result.source, reason=reason)))


# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/reference_types/import', version=1),
    view_func=ImportSignatureReferenceTypeView.as_view(
        str('import_signature_reference_types')
    ),
)


@app.route(api_url('/reference_types/export', version=1), methods=['GET', ])
@api_login_required
def export_signature_reference_types():
    q = request.args.get('q')
    q = json.loads(q) if q else {}

    type_ids = q.get('ids', [])
    results = (db.session
               .query(SignatureReferenceType)
               .filter(SignatureReferenceType.id.in_(type_ids))
               if type_ids else
               SignatureReferenceType.query)

    if results.count():
        extension = app.config['RULE_REFERENCE_TYPES_PRIMARY_FILE_EXTENSION']
        filename = generate_prefixed_filename(
            prefix='exported_reference_types',
            extension=extension,
        )
        return FileResponse(
            filename=filename,
            content=signature_reference_types_to_strings(results),
            mimetype='text/plain',
        )
    else:
        return APINotFound(
            message="Sorry, there are no reference types to export."
        )


# Categories ------------------------------------------------------------------
SIGNATURE_CATEGORY_RESULTS_PER_PAGE = 10


class SignatureCategoryView(API):

    dynamic_fields = SIGNATURE_CATEGORY_INCLUDE_METHODS

    def _seek_results(self, params, *args, **kwargs):
        """
        ATTENTION!

        It is assumed that ordering can be done by a single field only.
        """
        order_by = params.get('order_by', [])
        dynamic_order_by = {}

        # Exclude fields which are not DB columns and remember them
        for criterion in order_by[:]:
            fieldname = criterion['field']

            if fieldname in self.dynamic_fields:
                dynamic_order_by[fieldname] = criterion['direction']
                order_by.remove(criterion)

        # Invoke original search
        ignore_order_by = bool(dynamic_order_by)
        query = (super(SignatureCategoryView, self)
                 ._seek_results(params, ignore_order_by))

        # Chain ordering parameters to current query
        for fieldname, direction in dynamic_order_by.items():
            try:
                method = getattr(self, "_order_by_{0}".format(fieldname))
            except AttributeError:
                LOG.error("Failed to get method for ordering by field '{0}'"
                          .format(fieldname))
            else:
                query = method(query, direction)

        return query

    def _order_by_signatures_count(self, query, direction):
        counter = func.count(Signature.category_id)

        if direction:
            counter = getattr(counter, direction.lower())()

        return (query
                .outerjoin(Signature,
                           SignatureCategory.id == Signature.category_id)
                .group_by(SignatureCategory.id)
                .order_by(counter))


api_manager.create_api(
    model=SignatureCategory,
    collection_name='signature_categories',
    include_columns=SIGNATURE_CATEGORY_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_CATEGORY_INCLUDE_METHODS,
    methods=['POST', 'GET'],
    url_prefix=api_url_prefix(version=1),
    results_per_page=SIGNATURE_CATEGORY_RESULTS_PER_PAGE,
    view_class=SignatureCategoryView,
)


@app.route(api_url('/signature_categories/lite', version=1), methods=['GET', ])
@api_login_required
def signature_categories_lite_list():
    results = paginate_objects(
        objects=SignatureCategory.query,
        results_per_page=SIGNATURE_CATEGORY_RESULTS_PER_PAGE,
        serializer=signature_category_lite_serializer,
    )
    return APISuccess(results)


@app.route(api_url('/signature_categories/heavy', version=1),
           methods=['GET', ])
@api_login_required
def signature_categories_heavy_list():
    results = paginate_objects(
        objects=SignatureCategory.query,
        results_per_page=SIGNATURE_CATEGORY_RESULTS_PER_PAGE,
        serializer=signature_category_heavy_serializer,
    )
    return APISuccess(results)


@app.route(api_url('/signature_categories/updates', version=1),
           methods=['GET', ])
@api_login_required
def signature_categories_updates_list():
    results = paginate_objects(
        objects=SignatureCategory.query,
        results_per_page=SIGNATURE_CATEGORY_RESULTS_PER_PAGE,
        serializer=signature_category_update_serializer,
    )
    return APISuccess(results)


@app.route(api_url('/signature_categories', version=1), methods=['DELETE', ])
@api_login_required
def delete_signature_category_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    failed = []

    try:
        for category_id in q.get('ids', []):
            category = SignatureCategory.query.get(category_id)
            if category:
                if category.is_deletable():
                    db.session.delete(category)
                else:
                    LOG.error("Failed to delete category #{id}: category "
                              "which contains signatures cannot be deleted."
                              .format(id=category.id))
                    failed.append({
                        'id': category.id,
                        'name': category.name,
                        'message':
                            "This category contains signatures and cannot "
                            "be deleted.",
                    })
            else:
                LOG.error("Failed to delete signature category in bulk "
                          "request: category #{id} does not exist."
                          .format(id=category_id))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete signature categories: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


@app.route(api_url('/signature_categories/<int:category_id>', version=1),
           methods=['GET', ])
@api_login_required
def get_signature_category(category_id):
    category = SignatureCategory.query.get(category_id) or abort(404)
    result = signature_category_serializer(category)
    return APISuccess({'objects': [result, ]})


@app.route(api_url('/signature_categories/<int:category_id>/signatures', version=1),
           methods=['GET', ])
@api_login_required
def get_signatures_for_category(category_id):
    category = SignatureCategory.query.get(category_id) or abort(404)

    def serializer(item):
        return {
            'id': item.id,
            'name': item.name,
        }

    signatures = category.signatures

    q = request.args.get('q')
    if q:
        signatures = signatures.filter(Signature.name.like('%' + q + '%'))

    results = paginate_objects(
        objects=signatures,
        results_per_page=SIGNATURE_RESULTS_PER_PAGE,
        serializer=serializer,
    )
    return APISuccess(results)


@app.route(api_url('/signature_categories/<int:category_id>', version=1),
           methods=['PUT', ])
@api_login_required
def edit_signature_category(category_id):
    category = SignatureCategory.query.get(category_id) or abort(404)
    data = request.get_json() or {}

    category.name = data.get('name')
    category.description = data.get('description')

    try:
        db.session.add(category)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

        message = smart_str(e)
        LOG.error("Failed to update category #{id} with data {data}: {message}"
                  .format(id=category_id, data=data, message=message))
        return APIBadRequest(message=message)
    else:
        result = signature_category_serializer(category)
        return APISuccess({'objects': [result, ]})


# Class types -----------------------------------------------------------------
api_manager.create_api(
    model=SignatureClassType,
    collection_name='signature_class_types',
    include_columns=SIGNATURE_CLASS_TYPE_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_CLASS_TYPE_INCLUDE_METHODS,
    methods=['GET', 'POST', 'PUT', ],
    url_prefix=api_url_prefix(version=1),
)


@app.route(api_url('/signature_class_types', version=1), methods=['DELETE', ])
@api_login_required
def delete_signature_class_types_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    failed = []

    try:
        for class_type_id in q.get('ids', []):
            class_type = SignatureClassType.query.get(class_type_id)
            if class_type:
                if class_type.is_deletable():
                    db.session.delete(class_type)
                else:
                    LOG.error("Failed to delete class type #{id}: class type "
                              "which contains signatures cannot be deleted."
                              .format(id=class_type.id))
                    failed.append({
                        'id': class_type.id,
                        'name': class_type.name,
                        'message':
                            "This class type contains signatures and cannot "
                            "be deleted.",
                    })
            else:
                LOG.error("Failed to delete class type in bulk"
                          "request: class type #{id} does not exist."
                          .format(id=class_type_id))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete class types: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


class ImportSignatureClassTypesView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        """
        Returns info list about invalid class types.
        All valid class types will be saved to DB.
        """
        with autoprefix_injector() as inj:
            try:
                self._inject_file()
            except InvalidRuleClassTypesFileError as e:
                LOG.error(e.message)
                return APIBadRequest(message=e.message)

            try:
                failed = list(self._parse_stream())
            except Exception as e:
                failed = []
                LOG.error(inj.mark(
                    "Failed to import class types from file '{filename}': {e}"
                    .format(filename=self.file.filename, e=e)))
            finally:
                self.file.stream.seek(0)

        return APISuccess({'failed': failed})

    def _inject_file(self):
        self.file = request.files.get('file')

        if not self.file:
            raise InvalidRuleClassTypesFileError(
                "Failed to import class types: file was not provided.")

        self._ensure_file_extension()

    def _ensure_file_extension(self):
        extension = os.path.splitext(self.file.filename)[1][1:]

        if not extension:
            raise InvalidRuleClassTypesFileError(
                "Failed to import class types: unsupported format.")

        if extension not in app.config['RULE_CLASS_TYPES_ALLOWED_EXTENSIONS']:
            raise InvalidRuleClassTypesFileError(
                "Failed to import class types: unsupported format '{0}'."
                .format(extension))

    def _parse_stream(self):
        results = parse_rule_class_type_stream(self.file.stream)
        failed = map(self._process_result, results)
        return filter(bool, failed)

    @classmethod
    def _process_result(cls, parsing_result):
        if parsing_result.is_valid:
            try:
                SignatureClassType.analyze_info(parsing_result.info)
                SignatureClassType.from_info(parsing_result.info)
            except SignatureClassTypeAnalysisError as e:
                cls._on_processing_error(parsing_result, e.messages)
            except Exception as e:
                cls._on_processing_error(parsing_result, [e.message, ])

        # Return failed results only
        if not parsing_result.is_valid:
            return parsing_result.to_primitive()

    @staticmethod
    def _on_processing_error(parsing_result, messages):
        # TODO: extract to base class
        parsing_result.is_valid = False
        parsing_result.messages.extend(messages)

        with autoprefix_injector() as inj:
            reason = to_string_list(messages)
            LOG.error(inj.mark(
                "Failed to import class type from string '{source}': {reason}"
                .format(source=parsing_result.source, reason=reason)))


# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/signature_class_types/import', version=1),
    view_func=ImportSignatureClassTypesView.as_view(
        str('import_signature_class_types')
    ),
)


@app.route(api_url('/signature_class_types/export', version=1),
           methods=['GET', ])
@api_login_required
def export_signature_class_types():
    q = request.args.get('q')
    q = json.loads(q) if q else {}

    type_ids = q.get('ids', [])
    results = (db.session
               .query(SignatureClassType)
               .filter(SignatureClassType.id.in_(type_ids))
               if type_ids else
               SignatureClassType.query)

    if results.count():
        filename = generate_prefixed_filename(
            prefix='exported_classification',
            extension=app.config['RULE_CLASS_TYPES_PRIMARY_FILE_EXTENSION'],
        )
        return FileResponse(
            filename=filename,
            content=signature_class_types_to_strings(results),
            mimetype='text/plain',
        )
    else:
        return APINotFound(
            message="Sorry, there are no class types to export."
        )


# Severities ------------------------------------------------------------------
SIGNATURE_SEVERITY_RESULTS_PER_PAGE = 10


class SeverityView(API):

    dynamic_fields = SIGNATURE_SEVERITY_INCLUDE_METHODS

    def _seek_results(self, params, *args, **kwargs):
        """
        ATTENTION!

        It is assumed that ordering can be done by a single field only.
        """
        order_by = params.get('order_by', [])
        dynamic_order_by = {}

        # Exclude fields which are not DB columns and remember them
        for criterion in order_by[:]:
            fieldname = criterion['field']

            if fieldname in self.dynamic_fields:
                dynamic_order_by[fieldname] = criterion['direction']
                order_by.remove(criterion)

        # Invoke original search
        ignore_order_by = bool(dynamic_order_by)
        query = super(SeverityView, self)._seek_results(params,
                                                        ignore_order_by)

        # Chain ordering parameters to current query
        for fieldname, direction in dynamic_order_by.items():
            try:
                method = getattr(self, "_order_by_{0}".format(fieldname))
            except AttributeError:
                LOG.error("Failed to get method for ordering by field '{0}'"
                          .format(fieldname))
            else:
                query = method(query, direction)

        return query

    def _order_by_signatures_count(self, query, direction):
        counter = func.count(Signature.severity_id)

        if direction:
            counter = getattr(counter, direction.lower())()

        return (query
                .outerjoin(Signature,
                           SignatureSeverity.id == Signature.severity_id)
                .group_by(SignatureSeverity.id)
                .order_by(counter))


api_manager.create_api(
    model=SignatureSeverity,
    collection_name='signature_severities',
    include_columns=SIGNATURE_SEVERITY_INCLUDE_COLUMNS,
    include_methods=SIGNATURE_SEVERITY_INCLUDE_METHODS,
    methods=['POST', 'GET', 'PUT', ],
    preprocessors={
        'POST': [signature_severity_post_preprocessor, ],
        'DELETE_SINGLE': [signature_severity_delete_preprocessor, ],
        'PUT_SINGLE': [signature_severity_put_preprocessor, ],
    },
    url_prefix=api_url_prefix(version=1),
    results_per_page=SIGNATURE_SEVERITY_RESULTS_PER_PAGE,
    view_class=SeverityView,
)


@app.route(api_url('/signature_severities', version=1), methods=['DELETE', ])
@api_login_required
def delete_signature_severities_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    failed = []

    try:
        for severity_id in q.get('ids', []):
            severity = SignatureSeverity.query.get(severity_id)
            if severity:
                if severity.is_deletable():
                    db.session.delete(severity)
                else:
                    LOG.error("Failed to delete severity #{id}: "
                              "severity contains signatures cannot be deleted."
                              .format(id=severity.id))
                    failed.append({
                        'id': severity.id,
                        'name': severity.name,
                        'message': "This severity contains signatures and "
                                   "cannot be deleted.",
                    })
            else:
                LOG.error("Failed to delete severity in bulk request: "
                          "severity #{id} does not exist."
                          .format(id=severity_id))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete severities: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


# Protocols -------------------------------------------------------------------
api_manager.create_api(
    model=SignatureProtocol,
    collection_name='signature_protocols',
    include_columns=SIGNATURE_PROTOCOL_INCLUDE_COLUMNS,
    methods=['GET', 'POST', 'DELETE', 'PUT', ],
    url_prefix=api_url_prefix(version=1),
)

# Signatures ------------------------------------------------------------------
SIGNATURE_RESULTS_PER_PAGE = 10


class SignatureLiteView(API):

    dynamic_fields = SIGNATURE_INCLUDE_METHODS + ['created_by__name']

    def _seek_results(self, params, *args, **kwargs):
        """
        ATTENTION!

        It is assumed that ordering can be done by a single field only.
        """
        order_by = params.get('order_by', [])
        dynamic_order_by = {}

        # Exclude fields which are not DB columns and remember them
        for criterion in order_by[:]:
            fieldname = criterion['field']

            if fieldname in self.dynamic_fields:
                dynamic_order_by[fieldname] = criterion['direction']
                order_by.remove(criterion)

        # Invoke original search
        ignore_order_by = bool(dynamic_order_by)
        query = (super(SignatureLiteView, self)
                 ._seek_results(params, ignore_order_by))

        # Chain ordering parameters to current query
        for fieldname, direction in dynamic_order_by.items():
            try:
                method = getattr(self, "_order_by_{0}".format(fieldname))
            except AttributeError:
                LOG.error("Failed to get method for ordering by field '{0}'"
                          .format(fieldname))
            else:
                query = method(query, direction)

        return query

    def _order_by_created_by__name(self, query, direction):
        order = getattr(User.name, direction.lower())()
        join = query.outerjoin(User, User.id == Signature.created_by_id)
        return join.group_by(Signature.id).order_by(order)


api_manager.create_api(
    model=Signature,
    collection_name='signatures/lite',
    include_columns=SIGNATURE_INCLUDE_COLUMNS_LITE,
    include_methods=SIGNATURE_INCLUDE_METHODS_LITE,
    methods=['GET', ],
    url_prefix=api_url_prefix(version=1),
    results_per_page=SIGNATURE_RESULTS_PER_PAGE,
    view_class=SignatureLiteView,
)


@app.route(api_url('/signatures/new_sid', version=1), methods=['GET', ])
@api_login_required
def new_signature_sid():
    return APISuccess({'sid': Signature.generate_sid()})


class SignaturePreviewView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        original_data = request.get_json() or {}

        self.is_new = 'id' not in original_data
        self.original_data = signature_data_preprocessor(original_data)

        try:
            self._prepare_data()

            info = RuleInfo(self.data)
            info.validate()

            messages = Signature.analyze_info(info)
            rule = info.to_string()
        except (ValidationError, SignatureAnalysisError) as e:
            messages = to_string_list(e.messages)
            return self._on_error(messages)
        except Exception as e:
            messages = [smart_str(e), ]
            return self._on_error(messages)
        else:
            return self._on_success(rule, messages)

    def _prepare_data(self):
        self.data = self.original_data.copy()

        self.data.pop('name', None)
        self.data.pop('category_id', None)
        self.data.pop('severity_id', None)

        self._prepare_sid()
        self._prepare_protocol()
        self._prepare_class_type()
        self._prepare_reference_infos()

    def _prepare_sid(self):
        if self.is_new:
            sid_base = self.data.get('sid')
            self.data['sid'] = Signature.generate_sid(base=sid_base)

    def _prepare_protocol(self):
        protocol_id = self.data.pop('protocol_id', None)
        if protocol_id:
            protocol = SignatureProtocol.query.get(protocol_id)
            if protocol:
                self.data['protocol'] = protocol.name

    def _prepare_class_type(self):
        class_type_id = self.data.pop('class_type_id', None)
        if class_type_id:
            class_type = SignatureClassType.query.get(class_type_id)
            if class_type:
                self.data['class_type'] = class_type.short_name

    def _prepare_reference_infos(self):
        reference_datas = self.data.pop('references', [])
        self.data['reference_infos'] = map(self._process_reference_data,
                                           reference_datas)

    @staticmethod
    def _process_reference_data(reference_data):
        reference_type_id = reference_data.pop('reference_type_id')
        reference_type = SignatureReferenceType.query.get(reference_type_id)
        reference_data['type_name'] = reference_type.name
        return RuleReferenceInfo(reference_data)

    def _on_error(self, messages):
        reason = '\n'.join(messages)

        LOG.error("Failed to create signature preview from data '{data}'. "
                  "Reason:\n{reason}"
                  .format(data=json.dumps(self.original_data),
                          reason=reason))

        return APIBadRequest(message=messages)

    @staticmethod
    def _on_success(rule, messages):
        kwargs = {
            'payload': {
                'rule': rule,
            },
        }

        if messages:
            kwargs['message'] = messages

        return APISuccess(**kwargs)

# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/signatures/preview', version=1),
    view_func=SignaturePreviewView.as_view(str('signature_preview')),
)


@app.route(api_url('/signatures', version=1), methods=['POST', ])
@api_login_required
def create_signature():
    data = signature_data_preprocessor(request.get_json() or {})
    data['created_by'] = current_user
    reference_datas = data.pop('references', [])

    try:
        signature = Signature(**data)
        signature.references = [
            SignatureReference(**x) for x in reference_datas
        ]

        db.session.add(signature)
        db.session.add_all(signature.references)
        db.session.commit()
    except Exception as e:
        message = smart_str(e)
        LOG.error("Failed to create new signature: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        primitive = signature_serializer(signature)
        primitive['category']['signatures_count'] = (signature.category
                                                     .signatures_count())
        return APISuccess(primitive)


@app.route(api_url('/signatures/<int:signature_id>', version=1),
           methods=['GET', ])
@api_login_required
def get_signature(signature_id):
    signature = Signature.query.get(signature_id) or abort(404)
    primitive = signature_serializer(signature)
    return APISuccess(primitive)


@app.route(api_url('/signatures/<int:signature_id>', version=1),
           methods=['PUT', ])
@api_login_required
def edit_signature(signature_id):
    # TODO: make edition more tight-coupled to creation, i.e., accept same
    # arguments and provide same behaviour

    signature = Signature.query.get(signature_id) or abort(404)
    data = signature_data_preprocessor(request.get_json() or {})
    reference_datas = data.pop('references', [])

    try:
        for key, value in six.iteritems(data):
            setattr(signature, key, value)

        # TODO: this is stupid to delete in for-loop
        for reference in signature.references:
            db.session.delete(reference)

        signature.references = [
            SignatureReference(**x) for x in reference_datas
        ]
        signature.to_string_cache_delete()

        db.session.add(signature)
        db.session.add_all(signature.references)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to update signature #{id}: {e}"
                  .format(id=signature_id, e=message))
        return APIBadRequest(message=message)
    else:
        primitive = signature_serializer(signature)
        return APISuccess(primitive)


@app.route(api_url('/signatures', version=1), methods=['DELETE', ])
@api_login_required
def delete_signatures_many():
    q = request.args.get('q')
    q = json.loads(q) if q else {}
    signature_ids = q.get('ids', [])

    failed = []

    try:
        for signature_id in signature_ids:
            signature = Signature.query.get(signature_id)

            if signature:
                if signature.is_deletable():
                    for reference in signature.references:
                        db.session.delete(reference)

                    db.session.delete(signature)
                    signature.to_string_cache_delete()
                else:
                    LOG.error("Failed to delete signature #{id}: signature "
                              "which belongs to policy cannot be deleted."
                              .format(id=signature.id))
                    failed.append({
                        'id': signature.id,
                        'name': signature.name,
                        'message': "This signature is included in policy and "
                                   "cannot be deleted.",
                    })
            else:
                LOG.error("Failed to delete signature #{id}: such signature "
                          "does not exist."
                          .format(id=signature_id))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        message = smart_str(e)
        LOG.error("Failed to delete signatures: {0}".format(message))
        return APIBadRequest(message=message)
    else:
        return APISuccess({'failed': failed})


class ImportSignaturesPreviewView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        with autoprefix_injector() as inj:
            try:
                self._inject_file()
            except InvalidRulesFileError as e:
                LOG.error(inj.mark(e.message))
                return APIBadRequest(message=e.message)

            self._inject_defaults()

            try:
                primitives = list(self._parse_stream())
            except Exception as e:
                primitives = []
                LOG.error(inj.mark(
                    "Failed to import signatures from file '{filename}': {e}"
                    .format(filename=self.file.filename, e=e)))
            finally:
                self.file.stream.seek(0)

            return APISuccess({
                'rules': primitives,
                'defaults': self.defaults,
            })

    def _inject_file(self):
        self.file = request.files.get('file')

        if not self.file:
            raise InvalidRulesFileError(
                "Failed to import signatures: file was not provided.")

        self._ensure_file_extension()

    def _ensure_file_extension(self):
        extension = os.path.splitext(self.file.filename)[1][1:]

        if not extension:
            raise InvalidRulesFileError(
                "Failed to import signatures: unsupported format.")

        if extension not in app.config['RULES_ALLOWED_EXTENSIONS']:
            raise InvalidRulesFileError(
                "Failed to import signatures: unsupported format '{0}'."
                .format(extension))

    def _inject_defaults(self):
        severity = SignatureSeverity.query.get_or_create_default()
        category = SignatureCategory.query.get_or_create_default()

        self.defaults = {
            'category': signature_category_serializer(category),
            'severity': signature_severity_serializer(severity),
        }

    def _parse_stream(self):
        results = parse_rule_stream(self.file.stream)
        return map(self._process_result, results)

    @classmethod
    def _process_result(cls, parsing_result):
        if parsing_result.is_valid:
            try:
                messages = Signature.analyze_info(parsing_result.info)
            except SignatureAnalysisError as e:
                messages = e.messages
                cls._on_processing_error(parsing_result, messages)
            except Exception as e:
                messages = [smart_str(e), ]
                cls._on_processing_error(parsing_result, messages)
            finally:
                parsing_result.messages.extend(messages)

        primitive = parsing_result.to_primitive()

        if parsing_result.is_valid:
            primitive['name'] = Signature.generate_name(parsing_result.info)

        return primitive

    @staticmethod
    def _on_processing_error(parsing_result, messages):
        # TODO: extract to base class
        parsing_result.is_valid = False

        with autoprefix_injector() as inj:
            reason = to_string_list(messages)
            LOG.error(inj.mark(
                "Failed to import signature from string '{source}': {reason}"
                .format(source=parsing_result.source, reason=reason)))


# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/signatures/import/preview', version=1),
    view_func=ImportSignaturesPreviewView.as_view(
        str('import_signatures_preview')
    ),
)


class ImportSignaturesView(MethodView):

    @method_decorator(api_login_required)
    def post(self):
        data = request.get_json() or {}
        self.is_editable = data.get('editable', None)
        rule_datas = data.get('rules', [])
        self.failed = []

        with autoprefix_injector():
            for rule_data in rule_datas:
                self._process_rule_data(rule_data)

        return APISuccess({'failed': self.failed, })

    def _process_rule_data(self, rule_data):
        try:
            import_signature_single_rule_preprocessor(rule_data)
            Signature.from_string(
                s=rule_data['rule'],
                name=rule_data['name'],
                severity_id=rule_data['severity_id'],
                category_id=rule_data['category_id'],
                is_editable=self.is_editable,
                created_by=current_user,
            )
        except ValidationError as e:
            messages = to_string_list(e.messages)
            self._on_error(rule_data, messages)
        except Exception as e:
            messages = [smart_str(e), ]
            self._on_error(rule_data, messages)

    def _on_error(self, rule_data, messages):
        with autoprefix_injector() as inj:
            reason = "\n".join(messages)

            LOG.error(inj.mark(
                "Failed to import signature from data '{data}'. "
                "Reason:\n{reason}"
                .format(data=rule_data, reason=reason)))

            self.failed.append({
                'rule': rule_data.get('rule'),
                'messages': messages,
            })


# TODO: register in a blueprint in a separate module without 'str' call
app.add_url_rule(
    api_url('/signatures/import', version=1),
    view_func=ImportSignaturesView.as_view(str('import_signatures')),
)


@app.route(api_url('/signatures/export', version=1), methods=['GET', ])
@api_login_required
def export_signatures():
    q = request.args.get('q')
    q = json.loads(q) if q else {}

    signature_ids = q.get('ids', [])
    results = (db.session
               .query(Signature)
               .filter(Signature.id.in_(signature_ids))
               if signature_ids else
               Signature.query)

    if results.count():
        filename = generate_prefixed_filename(
            prefix='exported',
            extension=app.config['RULES_PRIMARY_FILE_EXTENSION'],
        )
        return FileResponse(
            filename=filename,
            content=signatures_to_rules(results),
            mimetype='text/plain',
        )
    else:
        return APINotFound(message="Sorry, there are no signatures to export.")


@app.route(api_url('/signatures/<int:signature_id>/rule', version=1),
           methods=['GET', ])
@api_login_required
def signature_to_rule(signature_id):
    signature = Signature.query.get(signature_id) or abort(404)
    objects = {
        'id': signature.id,
        'details': signature.to_string(),
    }
    return APISuccess({'objects': objects})


@app.route(api_url('/snorby_signatures/by_sid/<int:sid>/ids', version=1),
           methods=['GET', ])
@api_login_required
def get_snorby_signature_ids_by_sid(sid):
    ids = snorby_signature_ids_by_sid(sid)
    return APISuccess({'objects': list(ids)})
