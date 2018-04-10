# Copyright (c) 2015-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import copy
import json
import ldap
import ldapurl
import netaddr
import os
import pecan
from pecan import rest
import re
import rpm
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan
import urlparse

from sysinv.api.controllers.v1 import address_pool
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
from sysinv.openstack.common import log
from sysinv.openstack.common import excutils
from sysinv.openstack.common.gettextutils import _
from sysinv.common.storage_backend_conf import StorageBackendConfig
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

        # filter out desired and applied parameters; they are used to keep
        # track of updates between two consecutive apply actions;
        s_applied = constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED
        s_desired = constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED

        parms = [p for p in parms if not (
                    p.service == constants.SERVICE_TYPE_CEPH and
                    p.section in [s_applied, s_desired])]

        # filter out cinder state
        parms = [p for p in parms if not (
            p.service == constants.SERVICE_TYPE_CINDER and (
                p.section == constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE or
                p.section == constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR_STATE or
                p.section == constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND_STATE))]

        # filter out firewall_rules_id
        parms = [p for p in parms if not (
            p.service == constants.SERVICE_TYPE_PLATFORM and p.section ==
            constants.SERVICE_PARAM_SECTION_PLATFORM_SYSINV and p.name ==
            constants.SERVICE_PARAM_NAME_SYSINV_FIREWALL_RULES_ID)]

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
    def get_all(self, q=[], marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of service parameters."""
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
    def _check_parameter_syntax(svc_param):
        """Check the attributes of service parameter"""
        service = svc_param['service']
        section = svc_param['section']
        name = svc_param['name']
        value = svc_param['value']

        schema = service_parameter.SERVICE_PARAMETER_SCHEMA[service][section]
        parameters = (schema.get(service_parameter.SERVICE_PARAM_MANDATORY, []) +
                      schema.get(service_parameter.SERVICE_PARAM_OPTIONAL, []))
        if name not in parameters:
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

        if service == constants.SERVICE_TYPE_CEPH:
            if not StorageBackendConfig.has_backend_configured(
                    pecan.request.dbapi, constants.CINDER_BACKEND_CEPH):
                msg = _("Ceph backend is required.")
                raise wsme.exc.ClientSideError(msg)

        if len(parameters) > 1:
            msg = _("Cannot specify multiple parameters with custom resource.")
            raise exc.CommandError(msg)

        for name, value in parameters.iteritems():
            new_record = {
                'service': service,
                'section': section,
                'name': name,
                'value': value,
                'personality': personality,
                'resource': resource,
            }
            self._check_custom_parameter_syntax(new_record)
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
                pecan.request.context, service)
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

        if service == constants.SERVICE_TYPE_CEPH:
            if not StorageBackendConfig.has_backend_configured(
                    pecan.request.dbapi, constants.CINDER_BACKEND_CEPH):
                msg = _("Ceph backend is required.")
                raise wsme.exc.ClientSideError(msg)

        for name, value in parameters.iteritems():
            new_record = {
                'service': service,
                'section': section,
                'name': name,
                'value': value,
            }
            self._check_parameter_syntax(new_record)
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
                pecan.request.context, service)
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
                parameter['service'])
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
        if parameter.service == constants.SERVICE_TYPE_CEPH:
            if not StorageBackendConfig.has_backend_configured(
                    pecan.request.dbapi, constants.CINDER_BACKEND_CEPH):
                msg = _("Ceph backend is required.")
                raise wsme.exc.ClientSideError(msg)

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

        if parameter['service'] == constants.SERVICE_TYPE_CINDER:
            if (parameter['name'] ==
                    constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED):
                if (parameter['value'].lower() == 'false' and
                        old_parameter['value'].lower() == 'true'):
                    if not pecan.request.rpcapi.validate_emc_removal(
                            pecan.request.context):
                        msg = _(
                            "Unable to modify service parameter. Can not "
                            "disable %s while in use"
                            % constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX)
                        raise wsme.exc.ClientSideError(msg)

        updated_parameter = pecan.request.dbapi.service_parameter_update(
            uuid, updates)

        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context,
                parameter['service'])
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

        if parameter.service == constants.SERVICE_TYPE_CEPH:
            if not StorageBackendConfig.has_backend_configured(
                    pecan.request.dbapi, constants.CINDER_BACKEND_CEPH):
                msg = _("Ceph backend is required.")
                raise wsme.exc.ClientSideError(msg)

        if parameter.service == constants.SERVICE_TYPE_CINDER:
            if parameter.name == 'data_san_ip':
                msg = _("Parameter '%s' is readonly." % parameter.name)
                raise wsme.exc.ClientSideError(msg)

        if parameter.section == \
                constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE:
            msg = _("Platform Maintenance Parameter '%s' is required." %
                    parameter.name)
            raise wsme.exc.ClientSideError(msg)

        pecan.request.dbapi.service_parameter_destroy_uuid(uuid)
        try:
            pecan.request.rpcapi.update_service_config(
                pecan.request.context,
                parameter.service)
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
    def _cache_tiering_feature_enabled_semantic_check(service):
        if service != constants.SERVICE_TYPE_CEPH:
            return

        # TODO(rchurch): Ceph cache tiering is no longer supported. This will be
        # refactored out in R6. For R5 prevent enabling.
        msg = _("Ceph cache tiering is no longer supported.")
        raise wsme.exc.ClientSideError(msg)

        if not StorageBackendConfig.has_backend_configured(
                pecan.request.dbapi,
                constants.CINDER_BACKEND_CEPH):
            msg = _("Ceph backend is required.")
            raise wsme.exc.ClientSideError(msg)

        section = 'cache_tiering'
        feature_enabled = pecan.request.dbapi.service_parameter_get_one(
                service=service, section=section,
                name=constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED)
        if feature_enabled.value == 'true':
            for name in CEPH_CACHE_TIER_PARAMETER_REQUIRED_ON_FEATURE_ENABLED:
                try:
                    pecan.request.dbapi.service_parameter_get_one(
                        service=service, section=section, name=name)
                except exception.NotFound:
                    msg = _("Unable to apply service parameters. "
                            "Missing service parameter '%s' for service '%s' "
                            "in section '%s'." % (name, service, section))
                    raise wsme.exc.ClientSideError(msg)
        else:
            storage_nodes = pecan.request.dbapi.ihost_get_by_personality(
                    constants.STORAGE)
            ceph_caching_hosts = []
            for node in storage_nodes:
                if node.capabilities.get('pers_subtype') == constants.PERSONALITY_SUBTYPE_CEPH_CACHING:
                    ceph_caching_hosts.append(node['hostname'])
            if len(ceph_caching_hosts):
                msg = _("Unable to apply service parameters. "
                        "Trying to disable CEPH cache tiering feature "
                        "with {} host(s) present: {}. "
                        "Delete host(s) first.").format(
                    constants.PERSONALITY_SUBTYPE_CEPH_CACHING,
                    ", ".join(sorted(ceph_caching_hosts)))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_identity():
        """ Perform checks for the Identity Service Type."""
        identity_driver = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_IDENTITY,
            section=constants.SERVICE_PARAM_SECTION_IDENTITY_IDENTITY,
            name=constants.SERVICE_PARAM_IDENTITY_DRIVER)

        # Check that the LDAP URL is specified if the identity backend is LDAP
        if (identity_driver.value ==
                constants.SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_LDAP):
            try:
                pecan.request.dbapi.service_parameter_get_one(
                    service=constants.SERVICE_TYPE_IDENTITY,
                    section=constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP,
                    name=service_parameter.SERVICE_PARAM_IDENTITY_LDAP_URL)
            except exception.NotFound:
                msg = _("Unable to apply service parameters. "
                        "Missing service parameter '%s' for service '%s' "
                        "in section '%s'." % (
                            service_parameter.SERVICE_PARAM_IDENTITY_LDAP_URL,
                            constants.SERVICE_TYPE_IDENTITY,
                            constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_cinder_default():
        """Semantic checks for the Cinder Service Type: DEFAULT parameters """
        try:
            volume_type = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_CINDER,
                section=constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT,
                name=constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE)
        except exception.MultipleResults:
            msg = (_('Unable to apply service parameters. Multiple parameters '
                     'found for %s/%s/%s. Ensure only one parameter is '
                     'provided.') % (
                         constants.SERVICE_TYPE_CINDER,
                         constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT,
                         constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE))
            raise wsme.exc.ClientSideError(msg)
        except exception.NotFound:
            # not required to be set
            volume_type = None

        if volume_type:
            try:
                volume_types = pecan.request.rpcapi.get_cinder_volume_type_names(
                    pecan.request.context)
            except rpc_common.RemoteError as e:
                raise wsme.exc.ClientSideError(str(e.value))

            if volume_type.value not in volume_types:
                msg = (_('Unable to apply service parameters. Cannot set "%s" '
                         'to value "%s". This is not a valid cinder volume '
                         'type. Acceptable values are: [%s].') % (
                             constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE,
                             volume_type.value, ','.join(volume_types)))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_cinder_emc_vnx():
        """Semantic checks for the Cinder Service Type: EMC VNX backend """
        feature_enabled = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
            name=constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED)

        if feature_enabled.value.lower() == 'true':
            for name in service_parameter.CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED:
                try:
                    pecan.request.dbapi.service_parameter_get_one(
                        service=constants.SERVICE_TYPE_CINDER,
                        section=constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
                        name=name)
                except exception.NotFound:
                    msg = _("Unable to apply service parameters. "
                            "Missing service parameter '%s' for service '%s' "
                            "in section '%s'." % (name,
                                constants.SERVICE_TYPE_CINDER,
                                constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX))
                    raise wsme.exc.ClientSideError(msg)
        else:
            if not pecan.request.rpcapi.validate_emc_removal(
                    pecan.request.context):
                msg = _("Unable to apply service parameters. Can not disable "
                        "%s while in use. Remove any EMC volumes."
                        % constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX)
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _emc_vnx_ip_addresses_reservation():
        """Reserve the provided IP addresses """

        # To keep the EMC IP addresses information between service_parameter
        # db and addresses db in-sync.  So that sysinv won't assign these IP
        # addresses to someone else
        #
        # service_parameter | addresses
        # ------------------------------------------------------------
        # san_ip            | controller-emc-vnx-san-ip-<network-type>
        # (user provides)   |
        # ------------------------------------------------------------
        # san_secondary_ip  | controller-emc-vnx-san-
        # (user provides)   | secondary-ip-<network-type>
        # ------------------------------------------------------------
        # data_san_ip       | controller-emc-vnx-data-san-ip-
        #                   | <network-type> (generated internally)
        # ------------------------------------------------------------
        #
        # controller-emc-vnx-san-ip and controller-emc-vnx-san-secondary-ip
        # are in 'control_network' network and controller-emc-vnx-data-san-ip
        # is in 'data_network' network.

        feature_enabled = service_parameter._emc_vnx_get_param_from_name(
            constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED)
        data_san_ip_param = service_parameter._emc_vnx_get_param_from_name(
            service_parameter.CINDER_EMC_VNX_DATA_SAN_IP)
        prev_data_san_ip_db = service_parameter._emc_vnx_get_address_db(
            service_parameter.CINDER_EMC_VNX_DATA_SAN_IP,
            control_network=False)[0]

        # Always remove the reserved control IP addresses out of network
        # because of the following scenarios:
        #   * feature turned off need to delete
        #   * user modifies 'control_network' parameter from e.g. infra to oam
        # And later will be re-added if neccessary
        prev_san_ip_db, prev_control_network_type = \
            service_parameter._emc_vnx_get_address_db(
                service_parameter.CINDER_EMC_VNX_SAN_IP, control_network=True)
        service_parameter._emc_vnx_db_destroy_address(prev_san_ip_db)
        prev_san_secondary_ip_db = service_parameter._emc_vnx_get_address_db(
            service_parameter.CINDER_EMC_VNX_SAN_SECONDARY_IP,
            network_type=prev_control_network_type)[0]
        service_parameter._emc_vnx_db_destroy_address(prev_san_secondary_ip_db)

        # Enabling emc_vnx feature, we need to
        if feature_enabled.value.lower() == 'true':

            # Control IP, user will provide san_ip and san_secondary_ip
            # (optional). Here we just save these IP addresses into
            # 'control_network' network

            control_network_param = \
                service_parameter._emc_vnx_get_param_from_name(
                    service_parameter.CINDER_EMC_VNX_CONTROL_NETWORK)
            # Don't reserve address for oam network
            if control_network_param.value != constants.NETWORK_TYPE_OAM:
                try:
                    pool_uuid = pecan.request.dbapi.network_get_by_type(
                        control_network_param.value).pool_uuid
                    pool = pecan.request.dbapi.address_pool_get(pool_uuid)
                    service_parameter._emc_vnx_save_address_from_param(
                        service_parameter.CINDER_EMC_VNX_SAN_IP,
                        control_network_param.value, pool)
                    service_parameter._emc_vnx_save_address_from_param(
                        service_parameter.CINDER_EMC_VNX_SAN_SECONDARY_IP,
                        control_network_param.value, pool)
                except exception.NetworkTypeNotFound:
                    msg = _("Unable to apply service parameters. "
                            "Cannot find specified EMC control "
                            "network '%s'" % control_network_param.value)
                    raise wsme.exc.ClientSideError(msg)
                except exception.AddressPoolNotFound:
                    msg = _("Unable to apply service parameters. "
                            "Network '%s' has no address pool associated" %
                                control_network_param.value)
                    raise wsme.exc.ClientSideError(msg)

            # Data IP, we need to assign an IP address out of 'data_network'
            # network set it to readonly service parameter 'data-san-ip'.
            #
            # User can change the data_network (e.g from infra to mgnt)
            # which means we need to remove the existing and assign new IP
            # from new data_network

            data_network_param = service_parameter._emc_vnx_get_param_from_name(
                service_parameter.CINDER_EMC_VNX_DATA_NETWORK)
            try:
                data_network_db = pecan.request.dbapi.network_get_by_type(
                    data_network_param.value)
            except exception.NetworkTypeNotFound:
                msg = _("Unable to apply service parameters. "
                        "Cannot find specified EMC data network '%s'" % (
                            data_network_param.value))
                raise wsme.exc.ClientSideError(msg)

            # If addressses db already contain the address and new request
            # come in with different network we first need to delete the
            # existing one
            if (prev_data_san_ip_db and prev_data_san_ip_db.pool_uuid !=
                    data_network_db.pool_uuid):
                service_parameter._emc_vnx_destroy_data_san_address(
                    data_san_ip_param, prev_data_san_ip_db)
                data_san_ip_param = None

            if not data_san_ip_param:
                try:
                    assigned_address = (
                        address_pool.AddressPoolController.assign_address(
                            None, data_network_db.pool_uuid,
                            service_parameter._emc_vnx_format_address_name_db(
                                service_parameter.CINDER_EMC_VNX_DATA_SAN_IP,
                                data_network_param.value)))
                    pecan.request.dbapi.service_parameter_create({
                        'service': constants.SERVICE_TYPE_CINDER,
                        'section':
                            constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
                        'name': service_parameter.CINDER_EMC_VNX_DATA_SAN_IP,
                        'value': assigned_address.address})
                except exception.AddressPoolExhausted:
                    msg = _("Unable to apply service parameters. "
                            "The address pool '%s' in Data EMC network '%s' "
                            "is full" % (data_network_db.pool_uuid,
                                data_network_param.value))
                    raise wsme.exc.ClientSideError(msg)
                except exception.AddressNotFound:
                    msg = _("Unable to apply service parameters. "
                            "Cannot add generated '%s' address into "
                            "pool '%s'" % (service_parameter.CINDER_EMC_VNX_DATA_SAN_IP,
                                data_network_db.pool_uuid))
                    raise wsme.exc.ClientSideError(msg)
                except exception.ServiceParameterAlreadyExists:
                    # If can not add assigned data san ip address into
                    # service parameter then need to release it too
                    service_parameter._emc_vnx_db_destroy_address(
                        assigned_address)
                    msg = _("Unable to apply service parameters. "
                            "Cannot add generated '%s' address '%s' "
                            "into service parameter '%s'" % (
                                service_parameter.CINDER_EMC_VNX_DATA_SAN_IP,
                                assigned_address.address,
                                data_san_ip_param.value))
                    raise wsme.exc.ClientSideError(msg)
        else:
            # Need to remove the reserved Data IP addresses out of network
            service_parameter._emc_vnx_destroy_data_san_address(
                data_san_ip_param, prev_data_san_ip_db)

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

    def _service_parameter_apply_semantic_check(self, service):
        """Semantic checks for the service-parameter-apply command """

        # Check if all the mandatory parameters have been configured
        for section, schema in service_parameter.SERVICE_PARAMETER_SCHEMA[service].iteritems():
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

        ServiceParameterController._cache_tiering_feature_enabled_semantic_check(service)

        # Apply service specific semantic checks
        if service == constants.SERVICE_TYPE_IDENTITY:
            self._service_parameter_apply_semantic_check_identity()

        if service == constants.SERVICE_TYPE_CINDER:
            # Make sure one of the internal cinder configs is enabled so that we
            # know cinder is operational in this region
            if not StorageBackendConfig.is_service_enabled(pecan.request.dbapi,
                                                           constants.SB_SVC_CINDER,
                                                           filter_shared=True):
                msg = _("Cannot apply Cinder configuration. Cinder is not "
                        "currently enabled on either the %s or %s backends."
                        % (constants.SB_TYPE_LVM, constants.SB_TYPE_CEPH))
                raise wsme.exc.ClientSideError(msg)

            self._service_parameter_apply_semantic_check_cinder_default()

            self._service_parameter_apply_semantic_check_cinder_emc_vnx()
            self._emc_vnx_ip_addresses_reservation()

            self._service_parameter_apply_semantic_check_cinder_hpe3par()
            self._hpe3par_reserve_ip_addresses()

            self._service_parameter_apply_semantic_check_cinder_hpelefthand()
            self._hpelefthand_reserve_ip_addresses()

        if service == constants.SERVICE_TYPE_PLATFORM:
            self._service_parameter_apply_semantic_check_mtce()

    def _get_service(self, body):
        service = body.get('service') or ""
        if not service:
            raise wsme.exc.ClientSideError("Unspecified service name")
        if body['service'] not in service_parameter.SERVICE_PARAMETER_SCHEMA:
            msg = _("Invalid service name %s." % body['service'])
            raise wsme.exc.ClientSideError(msg)
        return service

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose('json', body=unicode)
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

    @staticmethod
    def _hpe3par_reserve_ip_addresses():

        """
        We need to keep the address information between service_parameter
        db and addresses db in-sync so that sysinv won't assign the IP
        addresses to someone else.

        Create an entry in the addresses db for each service parameter.

        Service Parameter    | Address DB Entry Name
        ---------------------------------------------------------------
        hpe3par_api_url      | hpe3par-api-ip
        ---------------------------------------------------------------
        hpe3par_iscsi_ips    | hpe3par-iscsi-ip<n>
        ---------------------------------------------------------------
        san_ip               | hpe3par-san-ip
        ---------------------------------------------------------------

        """

        #
        # Remove current addresses.  They will be added below if the
        # feature is enabled.
        #

        name = "hpe3par-api-ip"
        try:
            addr = pecan.request.dbapi.address_get_by_name(name)
            LOG.debug("Removing address %s" % name)
            pecan.request.dbapi.address_destroy(addr.uuid)
        except exception.AddressNotFoundByName:
            pass

        i = 0
        while True:
            name = "hpe3par-iscsi-ip" + str(i)
            try:
                addr = pecan.request.dbapi.address_get_by_name(name)
                LOG.debug("Removing address %s" % name)
                pecan.request.dbapi.address_destroy(addr.uuid)
                i += 1
            except exception.AddressNotFoundByName:
                break

        name = "hpe3par-san-ip"
        try:
            addr = pecan.request.dbapi.address_get_by_name(name)
            LOG.debug("Removing address %s" % name)
            pecan.request.dbapi.address_destroy(addr.uuid)
        except exception.AddressNotFoundByName:
            pass

        enabled = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
            name="enabled")

        if enabled.value.lower() == 'false':
            return

        #
        # Add the hpe3par-api-ip address.
        #
        api_url = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
            name="hpe3par_api_url")

        url = urlparse.urlparse(api_url.value)
        ip = netaddr.IPAddress(url.hostname)
        pool = service_parameter._get_network_pool_from_ip_address(ip, service_parameter.HPE_DATA_NETWORKS)

        #
        # Is the address in one of the supported network pools?  If so, reserve it.
        #
        if pool is not None:
            try:
                name = "hpe3par-api-ip"
                address = {'address': str(ip),
                           'prefix': pool['prefix'],
                           'family': pool['family'],
                           'enable_dad': constants.IP_DAD_STATES[pool['family']],
                           'address_pool_id': pool['id'],
                           'interface_id': None,
                           'name': name}
                LOG.debug("Reserving address %s" % name)
                pecan.request.dbapi.address_create(address)
            except exception.AddressAlreadyExists:
                msg = _("Unable to apply service parameters. "
                        "Unable to save address '%s' ('%s') into "
                        "pool '%s'" % (name, str(ip), pool['name']))
                raise wsme.exc.ClientSideError(msg)

        #
        # Add the hpe3par-iscsi-ip addresses.
        #
        iscsi_ips = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
            name="hpe3par_iscsi_ips")

        addrs = iscsi_ips.value.split(',')
        i = 0
        for addr in addrs:
            ipstr = addr.split(':')
            ip = netaddr.IPAddress(ipstr[0])
            pool = service_parameter._get_network_pool_from_ip_address(ip, service_parameter.HPE_DATA_NETWORKS)

            #
            # Is the address in one of the supported network pools?  If so, reserve it.
            #
            if pool is not None:
                try:
                    name = "hpe3par-iscsi-ip" + str(i)
                    address = {'address': str(ip),
                               'prefix': pool['prefix'],
                               'family': pool['family'],
                               'enable_dad': constants.IP_DAD_STATES[pool['family']],
                               'address_pool_id': pool['id'],
                               'interface_id': None,
                               'name': name}
                    LOG.debug("Reserving address %s" % name)
                    pecan.request.dbapi.address_create(address)
                except exception.AddressAlreadyExists:
                    msg = _("Unable to apply service parameters. "
                            "Unable to save address '%s' ('%s') into "
                            "pool '%s'" % (name, str(ip), pool['name']))
                    raise wsme.exc.ClientSideError(msg)
                i += 1

        #
        # Optionally add the hpe3par-san-ip address.
        #
        try:
            san_ip = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_CINDER,
                section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
                name="san_ip")
        except exception.NotFound:
            return

        ip = netaddr.IPAddress(san_ip.value)
        pool = service_parameter._get_network_pool_from_ip_address(ip, service_parameter.HPE_DATA_NETWORKS)

        #
        # Is the address in one of the supported network pools?  If so, reserve it.
        #
        if pool is not None:
            try:
                name = "hpe3par-san-ip"
                address = {'address': str(ip),
                           'prefix': pool['prefix'],
                           'family': pool['family'],
                           'enable_dad': constants.IP_DAD_STATES[pool['family']],
                           'address_pool_id': pool['id'],
                           'interface_id': None,
                           'name': name}
                LOG.debug("Reserving address %s" % name)
                pecan.request.dbapi.address_create(address)
            except exception.AddressAlreadyExists:
                msg = _("Unable to apply service parameters. "
                        "Unable to save address '%s' ('%s') into "
                        "pool '%s'" % (name, str(ip), pool['name']))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _hpelefthand_reserve_ip_addresses():
        """
        We need to keep the address information between service_parameter
        db and addresses db in-sync so that sysinv won't assign the IP
        addresses to someone else.

        Create an entry in the addresses db for each service parameter.

        Service Parameter    | Address DB Entry Name
        ---------------------------------------------------------------
        hpelefthand_api_url  | hpelefthand-api-ip
        ---------------------------------------------------------------

        """

        #
        # Remove current addresses.  They will be added below if the
        # feature is enabled.
        #

        name = "hpelefthand-api-ip"
        try:
            addr = pecan.request.dbapi.address_get_by_name(name)
            LOG.debug("Removing address %s" % name)
            pecan.request.dbapi.address_destroy(addr.uuid)
        except exception.AddressNotFoundByName:
            pass

        enabled = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
            name="enabled")

        if enabled.value.lower() == 'false':
            return

        #
        # Add the hplefthand-api-ip address.
        #
        api_url = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
            name="hpelefthand_api_url")

        url = urlparse.urlparse(api_url.value)
        ip = netaddr.IPAddress(url.hostname)

        pool = service_parameter._get_network_pool_from_ip_address(ip, service_parameter.HPE_DATA_NETWORKS)

        if pool is not None:
            try:
                address = {'address': str(ip),
                           'prefix': pool['prefix'],
                           'family': pool['family'],
                           'enable_dad': constants.IP_DAD_STATES[pool['family']],
                           'address_pool_id': pool['id'],
                           'interface_id': None,
                           'name': name}
                LOG.debug("Reserving address %s" % name)
                pecan.request.dbapi.address_create(address)
            except exception.AddressAlreadyExists:
                msg = _("Unable to apply service parameters. "
                        "Unable to save address '%s' ('%s') into "
                        "pool '%s'" % (name, str(ip), pool['name']))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_cinder_hpe3par():
        """Semantic checks for the Cinder Service Type """
        feature_enabled = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
            name=constants.SERVICE_PARAM_CINDER_HPE3PAR_ENABLED)

        if feature_enabled.value.lower() == 'true':
            # Client library installed?  If not fail.
            if not service_parameter._rpm_pkg_is_installed('python-3parclient'):
                msg = _("Unable to apply service parameters. "
                        "Missing client library python-3parclient.")
                raise wsme.exc.ClientSideError(msg)

            for name in service_parameter.CINDER_HPE3PAR_PARAMETER_REQUIRED:
                try:
                    pecan.request.dbapi.service_parameter_get_one(
                        service=constants.SERVICE_TYPE_CINDER,
                        section=constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR,
                        name=name)
                except exception.NotFound:
                    msg = _("Unable to apply service parameters. "
                            "Missing service parameter '%s' for service '%s' "
                            "in section '%s'." % (name,
                                constants.SERVICE_TYPE_CINDER,
                                constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR))
                    raise wsme.exc.ClientSideError(msg)
        else:
            if not pecan.request.rpcapi.validate_hpe3par_removal(
                    pecan.request.context):
                msg = _("Unable to apply service parameters. Can not disable "
                        "%s while in use. Remove any HPE3PAR volumes."
                        % constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR)
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _service_parameter_apply_semantic_check_cinder_hpelefthand():
        """Semantic checks for the Cinder Service Type """
        feature_enabled = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
            name=constants.SERVICE_PARAM_CINDER_HPELEFTHAND_ENABLED)

        if feature_enabled.value.lower() == 'true':
            # Client library installed?  If not fail.
            if not service_parameter._rpm_pkg_is_installed('python-lefthandclient'):
                msg = _("Unable to apply service parameters. "
                        "Missing client library python-lefthandclient.")
                raise wsme.exc.ClientSideError(msg)

            for name in service_parameter.CINDER_HPELEFTHAND_PARAMETER_REQUIRED:
                try:
                    pecan.request.dbapi.service_parameter_get_one(
                        service=constants.SERVICE_TYPE_CINDER,
                        section=constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND,
                        name=name)
                except exception.NotFound:
                    msg = _("Unable to apply service parameters. "
                            "Missing service parameter '%s' for service '%s' "
                            "in section '%s'." % (name,
                                constants.SERVICE_TYPE_CINDER,
                                constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND))
                    raise wsme.exc.ClientSideError(msg)
        else:
            if not pecan.request.rpcapi.validate_hpelefthand_removal(
                    pecan.request.context):
                msg = _("Unable to apply service parameters. Can not disable "
                        "%s while in use. Remove any HPELEFTHAND volumes."
                        % constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND)
                raise wsme.exc.ClientSideError(msg)
