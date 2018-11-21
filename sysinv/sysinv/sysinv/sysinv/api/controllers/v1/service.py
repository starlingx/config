#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import socket
import pecan
import six
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import sm_api
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class SMService(base.APIBase):

    id = int
    status = wtypes.text
    state = wtypes.text
    desired_state = wtypes.text
    name = wtypes.text
    node_name = wtypes.text

    def __init__(self, **kwargs):
        self.fields = ['id', 'status', 'state', 'desired_state', 'name']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))
        # node_name not in response message, set to active controller
        self.node_name = socket.gethostname()


class SMServiceCollection(base.APIBase):
    """API representation of a collection of SM service."""

    services = [SMService]
    "A list containing SmService objects"

    def __init__(self, **kwargs):
        self._type = 'SmService'

    @classmethod
    def convert(cls, smservices):
        collection = SMServiceCollection()
        collection.services = [SMService(**n) for n in smservices]
        return collection


class Service(base.APIBase):
    """API representation of service.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a service.
    """

    enabled = bool
    "Is this service enabled"

    name = wtypes.text
    "Name of the service"

    region_name = wtypes.text
    "Name of region where the service resides"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text, bool,
                                                  six.integer_types)}
    "Service capabilities"

    def __init__(self, **kwargs):
        self.fields = objects.service.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_service, expand=True):

        service = Service(**rpc_service.as_dict())
        if not expand:
            service.unset_fields_except(['name',
                                         'enabled',
                                         'region_name',
                                         'capabilities'])

        service.links = [link.Link.make_link('self', pecan.request.host_url,
                                             'services', service.name),
                               link.Link.make_link('bookmark',
                                                    pecan.request.host_url,
                                                    'services', service.name,
                                                    bookmark=True)
                         ]

        return service


def _check_service_data(op, service):
    # Get data
    name = service['name']
    if name not in constants.ALL_OPTIONAL_SERVICES:
        raise wsme.exc.ClientSideError(_(
                        "Invalid service name"))

    # magnum-specific error checking
    if name == constants.SERVICE_TYPE_MAGNUM:
        # magnum clusters need to all be cleared before service can be disabled
        # this error check is commented out because get_magnum_cluster_count
        # cannot count clusters of different projects
        # it is commented instead of removed in case a --all-tenants feature is
        # added to magnum in the future
        # if service['enabled'] == False:
        #    cluster_count = pecan.request.rpcapi.get_magnum_cluster_count(
        #        pecan.request.context)
        #    if cluster_count > 0:
        #        raise wsme.exc.ClientSideError(_(
        #                "Cannot disable Magnum while clusters are active"))
        # magnum can be enabled only on AIO duplex
        if service['enabled']:
            system = pecan.request.dbapi.isystem_get_one()
            if system.system_type != constants.TIS_STD_BUILD:
                raise wsme.exc.ClientSideError(_(
                        "Magnum can be enabled on only Standard systems"))

    # ironic-specific error checking
    if name == constants.SERVICE_TYPE_IRONIC:
        if service['enabled']:
            system = pecan.request.dbapi.isystem_get_one()
            if system.system_type != constants.TIS_STD_BUILD:
                raise wsme.exc.ClientSideError(_(
                        "Ironic can be enabled on only Standard systems"))

    return service


LOCK_NAME = 'SMServiceController'


class SMServiceController(rest.RestController):

    @wsme_pecan.wsexpose(SMService, six.text_type)
    def get_one(self, uuid):
        sm_service = sm_api.service_show(uuid)
        if sm_service is None:
            raise wsme.exc.ClientSideError(_(
                    "Service %s could not be found") % uuid)
        return SMService(**sm_service)

    @wsme_pecan.wsexpose(SMServiceCollection)
    def get(self):
        sm_services = sm_api.service_list()

        # sm_api returns {'services':[list of services]}
        if isinstance(sm_services, dict):
            if 'services' in sm_services:
                sm_services = sm_services['services']
                return SMServiceCollection.convert(sm_services)
        LOG.error("Bad response from SM API")
        raise wsme.exc.ClientSideError(_(
                    "Bad response from SM API"))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Service, wtypes.text, body=[six.text_type])
    def patch(self, service_name, patch):
        """Update the service configuration."""

        rpc_service = objects.service.\
            get_by_service_name(pecan.request.context, str(service_name))

        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/id']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s" %
                                             state_rel_path))

        try:
            service = Service(**jsonpatch.apply_patch(
                    rpc_service.as_dict(), patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        service = _check_service_data(
                "modify", service.as_dict())

        try:
            # Update only the fields that have changed
            for field in objects.service.fields:
                if rpc_service[field] != service[field]:
                    rpc_service[field] = service[field]

            rpc_service.save()

            pecan.request.rpcapi.update_service_config(
                    pecan.request.context, service_name,
                    do_apply=True)

            return Service.convert_with_links(rpc_service)

        except exception.HTTPNotFound:
            msg = _("service update failed: %s : patch %s"
                    % (service_name, patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Service, body=Service)
    def post(self, service):
        """Create the service configuration."""
        try:
            result = pecan.request.dbapi.service_create(service.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))

        return Service.convert_with_links(result)
