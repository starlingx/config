#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import ptp_parameter
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpInstancePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpInstance(base.APIBase):
    """API representation of a PTP instance.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP instance.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP instance"

    updated_at = wtypes.datetime.datetime
    "Timestamp of update of this PTP instance"

    # Inherited from PtpParameterOwner

    id = int
    "ID (primary key) of this PTP instance"

    uuid = types.uuid
    "Unique UUID for this PTP instance"

    type = wtypes.Enum(str,
                       constants.PTP_PARAMETER_OWNER_INSTANCE,
                       constants.PTP_PARAMETER_OWNER_INTERFACE)
    "Type of parameter owner (PTP_PARAMETER_OWNER_INSTANCE)"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "Capabilities (metadata) of this PTP instance"

    # Fields of PtpInstance

    name = wtypes.text
    "Name given to the PTP instance"

    service = wtypes.Enum(str,
                          constants.PTP_INSTANCE_TYPE_PTP4L,
                          constants.PTP_INSTANCE_TYPE_PHC2SYS,
                          constants.PTP_INSTANCE_TYPE_TS2PHC)
    "Type of service of the PTP instance"

    hostnames = types.MultiType([list])
    "Name(s) of host(s) associated to this PTP instance"

    parameters = types.MultiType([list])
    "List of parameters referred by this PTP instance"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_instance.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_instance, expand=True):
        ptp_instance = PtpInstance(**rpc_ptp_instance.as_dict())
        if not expand:
            ptp_instance.unset_fields_except(['id',
                                              'uuid',
                                              'type',
                                              'capabilities',
                                              'name',
                                              'service',
                                              'hostnames',
                                              'parameters',
                                              'created_at',
                                              'updated_at'])

        LOG.debug("PtpInstance.convert_with_links: converted %s" %
                  ptp_instance.as_dict())
        return ptp_instance


class PtpInstanceCollection(collection.Collection):
    """API representation of a collection of PTP instances."""

    ptp_instances = [PtpInstance]
    "A list containing PTP instance objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_instances'

    @classmethod
    def convert_with_links(cls, rpc_ptp_instances, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpInstanceCollection()
        collection.ptp_instances = [PtpInstance.convert_with_links(p, expand)
                                    for p in rpc_ptp_instances]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpInstanceController'


class PtpInstanceController(rest.RestController):
    """REST controller for PTP instance."""

    ptp_parameters = ptp_parameter.PtpParameterController(
        parent="ptp_instance")
    "Expose PTP parameters as a sub-element of PTP instances"

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    @wsme_pecan.wsexpose(PtpInstanceCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, host_uuid=None, marker=None, limit=None,
                sort_key='name', sort_dir='asc'):
        """Retrieve a list of PTP instances."""
        LOG.debug("PtpInstanceController.get_all: from_ihosts %s host_uuid %s"
                  % (self._from_ihosts, host_uuid))
        if self._from_ihosts and not host_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ptp_instance.get_by_uuid(
                pecan.request.context, marker)

        ptp_instances = \
            pecan.request.dbapi.ptp_instances_get_list(
                host_uuid, limit, marker_obj, sort_key, sort_dir)

        return PtpInstanceCollection.convert_with_links(
            ptp_instances, limit, sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInstance, types.uuid)
    def get_one(self, ptp_instance_uuid):
        """Retrieve a single PTP instance."""
        LOG.debug("PtpInstanceController.get_one: uuid=%s" % ptp_instance_uuid)
        ptp_instance = objects.ptp_instance.get_by_uuid(
            pecan.request.context, ptp_instance_uuid)
        return PtpInstance.convert_with_links(ptp_instance)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpInstance, body=PtpInstance)
    def post(self, ptp_instance):
        """Create a new PTP instance."""
        ptp_instance_dict = ptp_instance.as_dict()
        LOG.debug("PtpInstanceController.post: %s" % ptp_instance_dict)

        # Get rid of foreign data to create the PTP instance
        try:
            ptp_instance_dict.pop('hostnames')
        except KeyError:
            LOG.debug("PtpInstanceController.post: no host data in %s" %
                      ptp_instance_dict)
        try:
            ptp_instance_dict.pop('parameters')
        except KeyError:
            LOG.debug("PtpInstanceController.post: no parameter data in %s" %
                      ptp_instance_dict)

        return PtpInstance.convert_with_links(
            pecan.request.dbapi.ptp_instance_create(ptp_instance_dict))

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PtpInstancePatchType])
    @wsme_pecan.wsexpose(PtpInstance, types.uuid,
                         body=[PtpInstancePatchType])
    def patch(self, uuid, patch):
        """Update the association between PTP instance and PTP parameters."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.debug("PtpInstanceController.patch: params %s" % patch)
        utils.validate_patch(patch)

        try:
            # Check PTP instance exists
            objects.ptp_instance.get_by_uuid(pecan.request.context, uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP instance found for %s" % uuid))

        # Currently patch is used to add/remove PTP parameters
        # (but not having both operations in same patch)
        patch_list = list(jsonpatch.JsonPatch(patch))
        for p in patch_list:
            param_adding = p.get('op') == constants.PTP_PATCH_OPERATION_ADD
            param_keypair = p['value']
            if param_keypair.find('=') < 0:
                raise wsme.exc.ClientSideError(
                    _("Bad PTP parameter keypair: %s" % param_keypair))
            (param_name, param_value) = param_keypair.split('=', 1)
            try:
                # Check PTP parameter exists
                ptp_parameter = \
                    pecan.request.dbapi.ptp_parameter_get_by_namevalue(
                        param_name, param_value)

            except exception.NotFound:
                if not param_adding:
                    raise wsme.exc.ClientSideError(
                        _("No PTP parameter object found for %s"
                          % param_keypair))

                # If PTP parameter doesn't exist yet, create it
                param_dict = dict(name=param_name, value=param_value)
                LOG.debug("PtpInstanceController.patch: creating parameter %s"
                          % param_keypair)
                ptp_parameter = pecan.request.dbapi.ptp_parameter_create(
                    param_dict)

            param_uuid = ptp_parameter.uuid
            if param_adding:
                pecan.request.dbapi.ptp_instance_parameter_add(uuid,
                                                               param_uuid)
                LOG.debug("PtpInstanceController.patch: added %s to %s" %
                          (param_keypair, uuid))
            else:
                pecan.request.dbapi.ptp_instance_parameter_remove(uuid,
                                                                  param_uuid)
                LOG.debug("PtpInstanceController.patch: removed %s from %s" %
                          (param_keypair, uuid))

                # If PTP parameter isn't owned by anyone else, remove it
                param_owners = pecan.request.dbapi.ptp_parameter_get_owners(
                    param_uuid)
                if len(param_owners) == 0:
                    LOG.debug(
                        "PtpInstanceController.patch: destroying unreferenced "
                        "parameter %s" % param_keypair)
                    pecan.request.dbapi.ptp_parameter_destroy(param_uuid)

        return PtpInstance.convert_with_links(
            objects.ptp_instance.get_by_uuid(pecan.request.context, uuid))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_instance_uuid):
        """Delete a PTP instance."""
        LOG.debug("PtpInstanceController.delete: %s" % ptp_instance_uuid)
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            ptp_instance_obj = objects.ptp_instance.get_by_uuid(
                pecan.request.context, ptp_instance_uuid)
        except exception.PtpInstanceNotFound:
            raise

        # Only allow delete if there are no associated hosts, interfaces and
        # parameters
        parameters = pecan.request.dbapi.ptp_parameters_get_list(
            ptp_instance=ptp_instance_uuid)
        if parameters:
            raise wsme.exc.ClientSideError(
                "PTP instance %s is still associated with PTP parameter(s)"
                % ptp_instance_uuid)

        ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_list(
            ptp_instance=ptp_instance_obj.id)
        if ptp_interfaces:
            raise wsme.exc.ClientSideError(
                "PTP instance %s is still associated with PTP interface(s)"
                % ptp_instance_uuid)

        hosts = pecan.request.dbapi.ptp_instance_get_assignees(
            ptp_instance_obj.id)
        if hosts:
            raise wsme.exc.ClientSideError(
                "PTP instance %s is still associated with host(s)"
                % ptp_instance_uuid)

        LOG.debug("PtpInstanceController.delete: all clear for %s" %
                  ptp_instance_uuid)
        pecan.request.dbapi.ptp_instance_destroy(ptp_instance_uuid)
