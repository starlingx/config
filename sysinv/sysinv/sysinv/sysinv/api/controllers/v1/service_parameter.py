# Copyright (c) 2015-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import copy
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from fm_api import constants as fm_constants
from fm_api import fm_api

from oslo_log import log
from oslo_utils import excutils
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1.query import Query
from sysinv import objects
from sysinv.common import constants
from sysinv.common import service_parameter
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common.rpc import common as rpc_common

LOG = log.getLogger(__name__)


class ServiceParameterPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return ['/uuid']


class ServiceParameter(base.APIBase):
    """API representation of a Service Parameter instance.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a service
    parameter.
    """

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    service = wtypes.text
    "Name of a service."

    section = wtypes.text
    "Name of a section."

    name = wtypes.text
    "Name of a parameter"

    value = wtypes.text
    "Value of a parameter"

    personality = wtypes.text
    "The host personality to which the parameter is restricted."

    resource = wtypes.text
    "The puppet resource"

    links = [link.Link]
    "A list containing a self link and associated links"

    def __init__(self, **kwargs):
        self.fields = objects.service_parameter.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_service_parameter, expand=True):
        parm = ServiceParameter(**rpc_service_parameter.as_dict())
        if not expand:
            parm.unset_fields_except(['uuid', 'service', 'section',
                                      'name', 'value', 'personality', 'resource'])

        parm.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'parameters', parm.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'parameters', parm.uuid,
                                          bookmark=True)
                      ]
        return parm


class ServiceParameterCollection(collection.Collection):
    """API representation of a collection of service parameters."""

    parameters = [ServiceParameter]
    "A list containing Service Parameter objects"

    def __init__(self, **kwargs):
        self._type = 'parameters'

    @classmethod
    def convert_with_links(cls, rpc_service_parameter, limit, url=None,
                           expand=False,
                           **kwargs):
        collection = ServiceParameterCollection()
        collection.parameters = [ServiceParameter.convert_with_links(p, expand)
                                 for p in rpc_service_parameter]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'ServiceParameterController'


class ServiceParameterController(rest.RestController):
    """REST controller for ServiceParameter."""

    _custom_actions = {
        'apply': ['POST'],
    }

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_service_parameter_collection(self, marker=None, limit=None,
                                          sort_key=None, sort_dir=None,
                                          expand=False, resource_url=None,
                                          q=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        kwargs = {}
        if q is not None:
            for i in q:
                if i.op == 'eq':
                    kwargs[i.field] = i.value
        marker_obj = None
        if marker:
            marker_obj = objects.service_parameter.get_by_uuid(
                pecan.request.context, marker)

        if q is None:
            parms = pecan.request.dbapi.service_parameter_get_list(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            kwargs['limit'] = limit
            kwargs['sort_key'] = sort_key
            kwargs['sort_dir'] = sort_dir
            parms = pecan.request.dbapi.service_parameter_get_all(**kwargs)

        # Before we can return the service parameter collection,
        # we need to ensure that the list does not contain any
        # "protected" service parameters which may need to be
        # obfuscated.
        for idx, svc_param in enumerate(parms):
            service = svc_param['service']
            section = svc_param['section']
            name = svc_param['name']

            if service in service_parameter.SERVICE_PARAMETER_SCHEMA \
                    and section in service_parameter.SERVICE_PARAMETER_SCHEMA[service]:
                schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
                if service_parameter.SERVICE_PARAM_PROTECTED in schema:
                    # atleast one parameter is to be protected
                    if name in schema[service_parameter.SERVICE_PARAM_PROTECTED]:
                        parms[idx]['value'] = service_parameter.SERVICE_VALUE_PROTECTION_MASK

        return ServiceParameterCollection.convert_with_links(
            parms, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @wsme_pecan.wsexpose(ServiceParameterCollection, [Query],
                         types.uuid, wtypes.text,
                         wtypes.text, wtypes.text, wtypes.text)
    def get_all(self, q=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of service parameters."""
        if q is None:
            q = []
        sort_key = ['section', 'name']
        return self._get_service_parameter_collection(marker, limit,
                                                      sort_key,
                                                      sort_dir, q=q)

    @wsme_pecan.wsexpose(ServiceParameter, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given parameter."""
        rpc_parameter = objects.service_parameter.get_by_uuid(
            pecan.request.context, uuid)

        # Before we can return the service parameter, we need
        # to ensure that it is not a "protected" parameter
        # which may need to be obfuscated.
        service = rpc_parameter['service']
        section = rpc_parameter['section']
        name = rpc_parameter['name']

        if service in service_parameter.SERVICE_PARAMETER_SCHEMA \
                and section in service_parameter.SERVICE_PARAMETER_SCHEMA[service]:
            schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
            if service_parameter.SERVICE_PARAM_PROTECTED in schema:
                # parameter is to be protected
                if name in schema[service_parameter.SERVICE_PARAM_PROTECTED]:
                    rpc_parameter['value'] = service_parameter.SERVICE_VALUE_PROTECTION_MASK

        return ServiceParameter.convert_with_links(rpc_parameter)

    @staticmethod
    def _check_read_only_parameter(svc_param):
        """Check the read-only attribute of service parameter"""
        service = svc_param['service']
        section = svc_param['section']
        name = svc_param['name']

        schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
        readonly_parameters = schema.get(service_parameter.SERVICE_PARAM_READONLY, [])
        if name in readonly_parameters:
            msg = _("The parameter '%s' is readonly." % name)
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_parameter_syntax(svc_param):
        """Check the attributes of service parameter"""
        service = svc_param['service']
        section = svc_param['section']
        name = svc_param['name']
        value = svc_param['value']

        schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
        parameters = (schema.get(service_parameter.SERVICE_PARAM_MANDATORY, []) +
                      schema.get(service_parameter.SERVICE_PARAM_OPTIONAL, []))
        has_wildcard = (constants.SERVICE_PARAM_NAME_WILDCARD in parameters)
        if name not in parameters and not has_wildcard:
            msg = _("The parameter name %s is invalid for "
                    "service %s section %s"
                    % (name, service, section))
            raise wsme.exc.ClientSideError(msg)

        if not value:
            msg = _("The service parameter value is mandatory")
            raise wsme.exc.ClientSideError(msg)

        if len(value) > service_parameter.SERVICE_PARAMETER_MAX_LENGTH:
            msg = _("The service parameter value is restricted to at most %d "
                    "characters." % service_parameter.SERVICE_PARAMETER_MAX_LENGTH)
            raise wsme.exc.ClientSideError(msg)

        validators = schema.get(service_parameter.SERVICE_PARAM_VALIDATOR, {})
        validator = validators.get(name)
        if callable(validator):
            validator(name, value)

    @staticmethod
    def _check_custom_parameter_syntax(svc_param):
        """Check the attributes of custom service parameter"""
        service = svc_param['service']
        section = svc_param['section']
        name = svc_param['name']
        value = svc_param['value']
        personality = svc_param['personality']
        resource = svc_param['resource']

        if personality is not None and personality not in constants.PERSONALITIES:
            msg = _("%s is not a supported personality type" % personality)
            raise wsme.exc.ClientSideError(msg)

        if len(resource) > service_parameter.SERVICE_PARAMETER_MAX_LENGTH:
            msg = _("The custom resource option is restricted to at most %d "
                    "characters." % service_parameter.SERVICE_PARAMETER_MAX_LENGTH)
            raise wsme.exc.ClientSideError(msg)

        if service in service_parameter.SERVICE_PARAMETER_SCHEMA \
                and section in service_parameter.SERVICE_PARAMETER_SCHEMA[service]:
            schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
            parameters = (schema.get(service_parameter.SERVICE_PARAM_MANDATORY, []) +
                          schema.get(service_parameter.SERVICE_PARAM_OPTIONAL, []))
            if name in parameters:
                msg = _("The parameter name %s is reserved for "
                        "service %s section %s, and cannot be customized"
                        % (name, service, section))
                raise wsme.exc.ClientSideError(msg)

            if value is not None and len(value) > service_parameter.SERVICE_PARAMETER_MAX_LENGTH:
                msg = _("The service parameter value is restricted to at most %d "
                        "characters." % service_parameter.SERVICE_PARAMETER_MAX_LENGTH)
                raise wsme.exc.ClientSideError(msg)

        mapped_resource = service_parameter.map_resource(resource)
        if mapped_resource is not None:
            msg = _("The specified resource is reserved for "
                    "service=%s section=%s name=%s and cannot "
                    "be customized."
                    % (mapped_resource.get('service'),
                       mapped_resource.get('section'),
                       mapped_resource.get('name')))
            raise wsme.exc.ClientSideError(msg)

    def post_custom_resource(self, body, personality, resource):
        """Create new custom Service Parameter."""

        if resource is None:
            raise wsme.exc.ClientSideError(_("Unspecified resource"))

        service = body.get('service')
        if not service:
            raise wsme.exc.ClientSideError("Unspecified service name")

        section = body.get('section')
        if not section:
            raise wsme.exc.ClientSideError(_("Unspecified section name."))

        new_records = []
        parameters = body.get('parameters')
        if not parameters:
            raise wsme.exc.ClientSideError(_("Unspecified parameters."))

        if len(parameters) > 1:
            msg = _("Cannot specify multiple parameters with custom resource.")
            raise wsme.exc.ClientSideError(msg)

        for name, value in parameters.items():
            new_record = {
                'service': service,
                'section': section,
                'name': name,
                'value': value,
                'personality': personality,
                'resource': resource,
            }
            self._check_custom_parameter_syntax(new_record)

            existing = False
            try:
                pecan.request.dbapi.service_parameter_get_one(
                    service, section, name,
                    personality, resource)
                existing = True
            except exception.NotFound:
                pass
            except exception.MultipleResults:
                # We'll check/handle this in the "finally" block
                existing = True
            finally:
                if existing:
                    msg = _("Service parameter add failed: "
                            "Parameter already exists: "
                            "service=%s section=%s name=%s "
                            "personality=%s resource=%s"
                            % (service, section, name,
                               personality, resource))
                    raise wsme.exc.ClientSideError(msg)

            new_records.append(new_record)

        svc_params = []
        for n in new_records:
            try:
                new_parm = pecan.request.dbapi.service_parameter_create(n)
            except exception.NotFound:
                msg = _("Service parameter add failed:  "
                        "service %s section %s name %s value %s"
                        " personality %s resource %s"
                        % (service, section, n.name, n.value, personality, resource))
                raise wsme.exc.ClientSideError(msg)
            svc_params.append(new_parm)

        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context, service, section=section)
        except rpc_common.RemoteError as e:
            # rollback create service parameters
            for p in svc_params:
                try:
                    pecan.request.dbapi.service_parameter_destroy_uuid(p.uuid)
                    LOG.warn(_("Rollback service parameter create: "
                               "destroy uuid {}".format(p.uuid)))
                except exception.SysinvException:
                    pass
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        return ServiceParameterCollection.convert_with_links(
            svc_params, limit=None, url=None, expand=False,
            sort_key='id', sort_dir='asc')

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(ServiceParameterCollection, body=types.apidict)
    def post(self, body):
        """Create new Service Parameter."""

        resource = body.get('resource')
        personality = body.get('personality')

        if personality is not None or resource is not None:
            return self.post_custom_resource(body, personality, resource)

        service = self._get_service(body)

        section = body.get('section')
        if not section:
            raise wsme.exc.ClientSideError(_("Unspecified section name."))
        elif section not in service_parameter.SERVICE_PARAMETER_SCHEMA[service]:
            msg = _("Invalid service section %s." % section)
            raise wsme.exc.ClientSideError(msg)

        new_records = []
        parameters = body.get('parameters')
        if not parameters:
            raise wsme.exc.ClientSideError(_("Unspecified parameters."))

        for name, value in parameters.items():
            new_record = {
                'service': service,
                'section': section,
                'name': name,
                'value': value,
            }
            self._check_parameter_syntax(new_record)

            existing = False
            try:
                pecan.request.dbapi.service_parameter_get_one(
                    service, section, name)
                existing = True
            except exception.NotFound:
                pass
            except exception.MultipleResults:
                # We'll check/handle this in the "finally" block
                existing = True
            finally:
                if existing:
                    msg = _("Service parameter add failed: "
                            "Parameter already exists: "
                            "service=%s section=%s name=%s"
                            % (service, section, name))
                    raise wsme.exc.ClientSideError(msg)

            new_records.append(new_record)

        svc_params = []
        for n in new_records:
            try:
                new_parm = pecan.request.dbapi.service_parameter_create(n)
            except exception.NotFound:
                msg = _("Service parameter add failed:  "
                        "service %s section %s name %s value %s"
                        % (service, section, n.name, n.value))
                raise wsme.exc.ClientSideError(msg)
            svc_params.append(new_parm)

        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context, service, section=section)
        except rpc_common.RemoteError as e:
            # rollback create service parameters
            for p in svc_params:
                try:
                    pecan.request.dbapi.service_parameter_destroy_uuid(p.uuid)
                    LOG.warn(_("Rollback service parameter create: "
                               "destroy uuid {}".format(p.uuid)))
                except exception.SysinvException:
                    pass
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        return ServiceParameterCollection.convert_with_links(
            svc_params, limit=None, url=None, expand=False,
            sort_key='id', sort_dir='asc')

    def patch_custom_resource(self, uuid, patch, personality, resource):
        """Updates attributes of Service Parameter."""

        parameter = objects.service_parameter.get_by_uuid(
            pecan.request.context, uuid)

        parameter = parameter.as_dict()
        old_parameter = copy.deepcopy(parameter)

        updates = self._get_updates(patch)
        parameter.update(updates)

        self._check_custom_parameter_syntax(parameter)

        updated_parameter = pecan.request.dbapi.service_parameter_update(
            uuid, updates)

        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context,
                parameter['service'],
                section=parameter['section'])
        except rpc_common.RemoteError as e:
            # rollback service parameter update
            try:
                pecan.request.dbapi.service_parameter_update(uuid, old_parameter)
                LOG.warn(_("Rollback service parameter update: "
                           "uuid={}, old_values={}".format(uuid, old_parameter)))
            except exception.SysinvException:
                pass
            raise wsme.exc.ClientSideError(str(e.value))

        return ServiceParameter.convert_with_links(updated_parameter)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [ServiceParameterPatchType])
    @wsme_pecan.wsexpose(ServiceParameter, types.uuid,
                         body=[ServiceParameterPatchType])
    def patch(self, uuid, patch):
        """Updates attributes of Service Parameter."""

        parameter = objects.service_parameter.get_by_uuid(
            pecan.request.context, uuid)
        if parameter.personality is not None or parameter.resource is not None:
            return self.patch_custom_resource(uuid,
                                              patch,
                                              parameter.personality,
                                              parameter.resource)

        parameter = parameter.as_dict()
        old_parameter = copy.deepcopy(parameter)

        updates = self._get_updates(patch)
        parameter.update(updates)

        self._check_parameter_syntax(parameter)
        self._check_read_only_parameter(parameter)

        updated_parameter = pecan.request.dbapi.service_parameter_update(
            uuid, updates)

        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context,
                parameter['service'],
                section=parameter['section'])
        except rpc_common.RemoteError as e:
            # rollback service parameter update
            try:
                pecan.request.dbapi.service_parameter_update(uuid, old_parameter)
                LOG.warn(_("Rollback service parameter update: "
                           "uuid={}, old_values={}".format(uuid, old_parameter)))
            except exception.SysinvException:
                pass
            raise wsme.exc.ClientSideError(str(e.value))

        # Before we can return the service parameter, we need
        # to ensure that this updated parameter is not "protected"
        # which may need to be obfuscated.
        service = updated_parameter['service']
        section = updated_parameter['section']
        name = updated_parameter['name']

        if service in service_parameter.SERVICE_PARAMETER_SCHEMA \
                and section in service_parameter.SERVICE_PARAMETER_SCHEMA[service]:
            schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
            if service_parameter.SERVICE_PARAM_PROTECTED in schema:
                # parameter is to be protected
                if name in schema[service_parameter.SERVICE_PARAM_PROTECTED]:
                    updated_parameter['value'] = service_parameter.SERVICE_VALUE_PROTECTION_MASK

        return ServiceParameter.convert_with_links(updated_parameter)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete a Service Parameter instance."""
        parameter = objects.service_parameter.get_by_uuid(pecan.request.context, uuid)

        if parameter.section == \
                constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE:
            msg = _("Platform Maintenance Parameter '%s' is required." %
                    parameter.name)
            raise wsme.exc.ClientSideError(msg)

        pecan.request.dbapi.service_parameter_destroy_uuid(uuid)
        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context,
                parameter.service,
                section=parameter.section)
        except rpc_common.RemoteError as e:
            # rollback destroy service parameter
            try:
                parameter = parameter.as_dict()
                pecan.request.dbapi.service_parameter_create(parameter)
                LOG.warn(_("Rollback service parameter destroy: "
                           "create parameter with values={}".format(parameter)))
                # rollback parameter has a different uuid
            except exception.SysinvException:
                pass
            raise wsme.exc.ClientSideError(str(e.value))

    @staticmethod
    def _service_parameter_apply_semantic_check_mtce():
        """Semantic checks for the Platform Maintenance Service Type """
        hbs_failure_threshold = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
            name=constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD)

        hbs_degrade_threshold = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE,
            name=constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD)

        if int(hbs_degrade_threshold.value) >= int(hbs_failure_threshold.value):
            msg = _("Unable to apply service parameters. "
                    "Service parameter '%s' should be greater than '%s' "
                    % (
                        constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD,
                        constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD
                    ))
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_http():
        """Semantic checks for the HTTP Service Type """

        # check if a patching operation in progress
        fm = fm_api.FaultAPIs()

        alarms = fm.get_faults_by_id(fm_constants.
                                     FM_ALARM_ID_PATCH_IN_PROGRESS)
        if alarms is not None:
            msg = _("Unable to apply %s service parameters. "
                    "A patching operation is in progress."
                    % constants.SERVICE_TYPE_HTTP)
            raise wsme.exc.ClientSideError(msg)

        # check if a device image update operation is in progress
        alarms = fm.get_faults_by_id(fm_constants.
                                     FM_ALARM_ID_DEVICE_IMAGE_UPDATE_IN_PROGRESS)
        if alarms is not None:
            msg = _("Unable to apply %s service parameters. "
                    "A device image update operation is in progress. "
                    "Please try again later when the operation is complete."
                    % constants.SERVICE_TYPE_HTTP)
            raise wsme.exc.ClientSideError(msg)

        # check if all hosts are unlocked/enabled
        hosts = pecan.request.dbapi.ihost_get_list()
        for host in hosts:
            if (host['administrative'] == constants.ADMIN_UNLOCKED and
                        host['operational'] == constants.OPERATIONAL_ENABLED):
                continue
            else:
                # the host name might be None for a newly discovered host
                if not host['hostname']:
                    host_id = host['uuid']
                else:
                    host_id = host['hostname']
                raise wsme.exc.ClientSideError(
                    _("Host %s must be unlocked and enabled." % host_id))

    @staticmethod
    def _service_parameter_apply_semantic_check_kubernetes():
        """Semantic checks for the Platform Kubernetes Service Type """
        try:
            oidc_issuer_url = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_KUBERNETES,
                section=constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                name=constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL)
        except exception.NotFound:
            oidc_issuer_url = None

        try:
            oidc_client_id = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_KUBERNETES,
                section=constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                name=constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID)
        except exception.NotFound:
            oidc_client_id = None

        try:
            oidc_username_claim = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_KUBERNETES,
                section=constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                name=constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM)
        except exception.NotFound:
            oidc_username_claim = None

        try:
            oidc_groups_claim = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_KUBERNETES,
                section=constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                name=constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM)
        except exception.NotFound:
            oidc_groups_claim = None

        if not ((not oidc_issuer_url and not oidc_client_id and
                 not oidc_username_claim and not oidc_groups_claim) or
                (oidc_issuer_url and oidc_client_id and
                 oidc_username_claim and not oidc_groups_claim) or
                (oidc_issuer_url and oidc_client_id and
                 oidc_username_claim and oidc_groups_claim)):
            msg = _("Unable to apply service parameters. Please choose one of "
                    "the valid Kubernetes OIDC parameter setups: (None) or "
                    "(oidc_issuer_url, oidc_client_id, oidc_username_claim) or "
                    "(the previous 3 plus oidc_groups_claim)")
            raise wsme.exc.ClientSideError(msg)

    def _service_parameter_apply_semantic_check(self, service):
        """Semantic checks for the service-parameter-apply command """

        # Check if all the mandatory parameters have been configured
        for section, schema in service_parameter.SERVICE_PARAMETER_SCHEMA[service].items():
            mandatory = schema.get(service_parameter.SERVICE_PARAM_MANDATORY, [])
            for name in mandatory:
                try:
                    pecan.request.dbapi.service_parameter_get_one(
                        service=service, section=section, name=name)
                except exception.NotFound:
                    msg = _("Unable to apply service parameters. "
                            "Missing service parameter '%s' for service '%s' "
                            "in section '%s'." % (name, service, section))
                    raise wsme.exc.ClientSideError(msg)

        # Apply service specific semantic checks
        if service == constants.SERVICE_TYPE_PLATFORM:
            self._service_parameter_apply_semantic_check_mtce()

        elif service == constants.SERVICE_TYPE_HTTP:
            self._service_parameter_apply_semantic_check_http()

        elif service == constants.SERVICE_TYPE_KUBERNETES:
            self._service_parameter_apply_semantic_check_kubernetes()

    def _get_service(self, body):
        service = body.get('service') or ""
        if not service:
            raise wsme.exc.ClientSideError("Unspecified service name")
        if body['service'] not in service_parameter.SERVICE_PARAMETER_SCHEMA:
            msg = _("Invalid service name %s." % body['service'])
            raise wsme.exc.ClientSideError(msg)
        return service

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose('json', body=six.text_type)
    def apply(self, body):
        """ Apply the service parameters."""
        service = self._get_service(body)
        self._service_parameter_apply_semantic_check(service)
        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context, service, do_apply=True)
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)
