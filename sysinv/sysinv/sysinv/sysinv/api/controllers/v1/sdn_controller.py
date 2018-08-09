# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2016 Wind River Systems, Inc.
#

import socket
import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import excutils
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

from fm_api import constants as fm_constants
from fm_api import fm_api

LOG = log.getLogger(__name__)


# UTILS
def _getIPAddressFromHostname(hostname):
    """ Dual stacked version of gethostbyname

        return: family (AF_INET | AF_INET6)
                ip address
    """

    sockaddrlist = socket.getaddrinfo(hostname, 0)
    if not sockaddrlist:
        raise wsme.exc.ClientSideError(_("Cannot resolve %s hostname "
                                         % hostname))
    ip = None
    family = None
    for sock in sockaddrlist:
        # Each sock entry is a 5-tuples with the following structure:
        # (family, socktype, proto, canonname, sockaddr)
        if not sock[4] or not sock[4][0]:  # no sockaddr
            continue
        ip = sock[4][0]
        family = sock[0]
        break

    if not ip:
        raise wsme.exc.ClientSideError(_("Cannot determine "
                                         "%s IP address" % hostname))
    return family, ip


class SDNControllerPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/uuid']


class SDNController(base.APIBase):
    """API representation of an SDN Controller

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    SDN controller.
    """

    uuid = types.uuid
    "Unique UUID for this entry"

    state = wtypes.text
    "SDN controller administrative state"

    port = int
    "The remote listening port of the SDN controller"

    ip_address = wtypes.text
    "SDN controller FQDN or ip address"

    transport = wtypes.text
    "The transport mode of the SDN controller channel"

    links = [link.Link]
    "A list containing a self link and associated SDN controller links"

    def __init__(self, **kwargs):
        self.fields = objects.sdn_controller.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_sdn_controller, expand=True):
        sdn_controller = SDNController(**rpc_sdn_controller.as_dict())

        if not expand:
            sdn_controller.unset_fields_except([
                'uuid', 'ip_address', 'port', 'transport', 'state'])

        sdn_controller.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'sdn_controllers', sdn_controller.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'sdn_controllers', sdn_controller.uuid,
                                bookmark=True)]

        return sdn_controller


class SDNControllerCollection(collection.Collection):
    """API representation of a collection of SDNController objects."""

    sdn_controllers = [SDNController]
    "A list containing SDNController objects"

    def __init__(self, **kwargs):
        self._type = 'sdn_controllers'

    @classmethod
    def convert_with_links(cls, rpc_sdn_controllers, limit, url=None,
                           expand=False, **kwargs):
        collection = SDNControllerCollection()

        collection.sdn_controllers = [SDNController.convert_with_links(p, expand)
                                      for p in rpc_sdn_controllers]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'SDNControllerController'


class SDNControllerController(rest.RestController):
    """REST controller for SDNControllers."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_sdn_controller_collection(self, uuid, marker, limit, sort_key,
                                        sort_dir, expand=False,
                                        resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.sdn_controller.get_by_uuid(
                pecan.request.context, marker)

        sdn_controllers = pecan.request.dbapi.sdn_controller_get_list(
            limit, marker_obj, sort_key, sort_dir)

        return SDNControllerCollection.convert_with_links(sdn_controllers, limit,
                                                          url=resource_url,
                                                          expand=expand,
                                                          sort_key=sort_key,
                                                          sort_dir=sort_dir)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    def _verify_sdn_controller_af(self, ip_address):
        # Ensure that IP address is same version as the OAM IP
        # address. We will attempt to resolve the OAM IP address
        # first. If the provided SDN controller ip_address is a
        # hostname or FQDN then we will resolve its IP address as well
        oam_family, NULL = _getIPAddressFromHostname(
                                constants.OAMCONTROLLER_HOSTNAME)
        sdn_family, NULL = _getIPAddressFromHostname(ip_address)

        if oam_family != sdn_family:
            raise wsme.exc.ClientSideError(
                    exception.SDNControllerMismatchedAF.message)

    def _clear_existing_sdn_controller_alarms(self, uuid):
        # Clear any existing OVSDB manager alarm, corresponding
        # to this SDN controller. We need to clear this alarm
        # for all hosts on which it is set, i.e. all unlocked
        # compute nodes.
        key = "sdn-controller=%s" % uuid
        obj = fm_api.FaultAPIs()

        alarms = obj.get_faults_by_id(fm_constants.
                                      FM_ALARM_ID_NETWORK_OVSDB_MANAGER)
        if alarms is not None:
            for alarm in alarms:
                if key in alarm.entity_instance_id:
                    obj.clear_fault(
                            fm_constants.FM_ALARM_ID_NETWORK_OVSDB_MANAGER,
                            alarm.entity_instance_id)

        # Clear any existing Openflow Controller alarm, corresponding
        # to this SDN controller. We need need to clear this alarm
        # for all hosts on which it is set, i.e. all unlocked computes.
        sdn_controller = objects.sdn_controller.get_by_uuid(
            pecan.request.context, uuid)
        uri = "%s://%s" % (sdn_controller.transport,
                           sdn_controller.ip_address)
        key = "openflow-controller=%s" % uri

        alarms = obj.get_faults_by_id(fm_constants.
                                      FM_ALARM_ID_NETWORK_OPENFLOW_CONTROLLER)
        if alarms is not None:
            for alarm in alarms:
                if key in alarm.entity_instance_id:
                    obj.clear_fault(
                            fm_constants.
                            FM_ALARM_ID_NETWORK_OPENFLOW_CONTROLLER,
                            alarm.entity_instance_id)

    # this decorator will declare the function signature of this get call
    # and take care of calling the adequate decorators of the Pecan framework
    @wsme_pecan.wsexpose(SDNControllerCollection, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of SDN controllers."""

        return self._get_sdn_controller_collection(uuid, marker, limit,
                                                    sort_key, sort_dir)

    # call the SDNController class decorator and not the Collection class
    @wsme_pecan.wsexpose(SDNController, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given SDN controller."""

        rpc_sdn_controller = objects.sdn_controller.get_by_uuid(
            pecan.request.context, uuid)
        return SDNController.convert_with_links(rpc_sdn_controller)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(SDNController, body=SDNController)
    def post(self, sdn_controller):
        """Perform semantic checks and create a new SDN Controller."""

        try:
            # Ensure that SDN is enabled before proceeding
            if not utils.get_sdn_enabled():
                raise wsme.exc.ClientSideError(
                        exception.SDNNotEnabled.message)

            # Ensure that compulsory parameters are there
            # This is merely sanity since the args parse layer
            # will also ensure that they're provided
            ip_address = sdn_controller.ip_address
            port = sdn_controller.port
            transport = sdn_controller.transport
            if not (len(ip_address) and port and len(transport)):
                raise wsme.exc.ClientSideError(
                        exception.SDNControllerRequiredParamsMissing.message)

            self._verify_sdn_controller_af(ip_address)

            new_controller = pecan.request.dbapi.sdn_controller_create(
                                                sdn_controller.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))

        try:
            pecan.request.rpcapi.update_sdn_controller_config(
                pecan.request.context)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        return sdn_controller.convert_with_links(new_controller)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [SDNControllerPatchType])
    @wsme_pecan.wsexpose(SDNController, types.uuid,
                         body=[SDNControllerPatchType])
    def patch(self, uuid, patch):
        """Update an existing SDN controller entry."""

        sdn_controller = objects.sdn_controller.get_by_uuid(
            pecan.request.context, uuid)

        sdn_controller = sdn_controller.as_dict()
        # get attributes to be updated
        updates = self._get_updates(patch)

        # before we can update we have to do a quick semantic check
        if 'uuid' in updates:
            raise wsme.exc.ClientSideError(_("uuid cannot be modified"))

        if 'ip_address' in updates:
            self._verify_sdn_controller_af(updates['ip_address'])

        # update DB record
        updated_sdn_controller = pecan.request.dbapi.sdn_controller_update(
                uuid, updates)
        # apply SDN manifest to target personalities
        pecan.request.rpcapi.update_sdn_controller_config(pecan.request.context)

        # if this SDN controller is being set in disabled state,
        # clear any existing alarms for this SDN controller if
        # it exists
        if ('state' in updates and
                updates['state'] == constants.SDN_CONTROLLER_STATE_DISABLED):
            self._clear_existing_sdn_controller_alarms(uuid)

        return SDNController.convert_with_links(updated_sdn_controller)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete an SDN controller."""
        objects.sdn_controller.get_by_uuid(pecan.request.context, uuid)

        # clear all existing alarms for this SDN controller
        self._clear_existing_sdn_controller_alarms(uuid)

        pecan.request.rpcapi.update_sdn_controller_config(pecan.request.context)
        pecan.request.dbapi.sdn_controller_destroy(uuid)
