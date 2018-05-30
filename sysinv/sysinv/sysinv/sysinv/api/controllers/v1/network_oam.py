# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#


import copy
import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from netaddr import IPNetwork, IPAddress, IPRange, AddrFormatError

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


extoam_ip_address_keys = ['oam_gateway_ip', 'oam_floating_ip',
                          'oam_c0_ip', 'oam_c1_ip']
oam_subnet_keys = ['oam_subnet']

extoam_region_address_keys = ['oam_start_ip', 'oam_end_ip']


class OAMNetworkPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class OAMNetwork(base.APIBase):
    """API representation of an OAM network.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an extoam.
    """

    _region_config = None

    def _get_region_config(self):
        return self._region_config

    def _set_region_config(self, value):
        if self._region_config is None:
            self._region_config = utils.get_region_config()

    uuid = types.uuid
    "Unique UUID for this extoam"

    oam_subnet = wtypes.text
    "Represent the oam subnet."

    oam_gateway_ip = wtypes.text
    "Represent the oam gateway IP."

    oam_floating_ip = wtypes.text
    "Represent the oam floating IP."

    oam_c0_ip = wtypes.text
    "Represent the oam controller-0 IP address."

    oam_c1_ip = wtypes.text
    "Represent the oam controller-1 IP address."

    oam_start_ip = wtypes.text
    "Represent the oam network start IP address."

    oam_end_ip = wtypes.text
    "Represent the oam network end IP address."

    # region_config = types.boolean
    region_config = wsme.wsproperty(types.boolean,
                                    _get_region_config,
                                    _set_region_config,
                                    mandatory=False)
    "Rperesents whether in region_config. True=region_config"

    action = wtypes.text
    "Represent the action on the OAM network."

    forisystemid = int
    "The isystemid that this iextoam belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this extoam belongs to"

    links = [link.Link]
    "A list containing a self link and associated extoam links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.oam_network.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.iextoam.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

        self._region_config = None
        # 'region_config' is not part of objects.iextoam.fields
        # (it's an API-only attribute)
        self.fields.append('region_config')
        setattr(self, 'region_config', kwargs.get('region_config', None))

    @classmethod
    def convert_with_links(cls, rpc_extoam, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # extoam = iextoam.from_rpc_object(rpc_extoam, fields)

        extoam = OAMNetwork(**rpc_extoam.as_dict())
        if not expand:
            extoam.unset_fields_except(['uuid',
                                        'oam_subnet',
                                        'oam_gateway_ip',
                                        'oam_floating_ip',
                                        'oam_c0_ip',
                                        'oam_c1_ip',
                                        'region_config',
                                        'oam_start_ip',
                                        'oam_end_ip',
                                        'isystem_uuid',
                                        'created_at',
                                        'updated_at'])

        # never expose the isystem_id attribute
        extoam.isystem_id = wtypes.Unset

        extoam.links = [link.Link.make_link('self', pecan.request.host_url,
                                            'iextoams', extoam.uuid),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'iextoams', extoam.uuid,
                                            bookmark=True)
                        ]

        return extoam


class OAMNetworkCollection(collection.Collection):
    """API representation of a collection of extoams."""

    iextoams = [OAMNetwork]
    "A list containing extoam objects"

    def __init__(self, **kwargs):
        self._type = 'iextoams'

    @classmethod
    def convert_with_links(cls, rpc_extoams, limit, url=None,
                           expand=False, **kwargs):
        collection = OAMNetworkCollection()
        collection.iextoams = [OAMNetwork.convert_with_links(p, expand)
                               for p in rpc_extoams]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############
# extoam is passed in as_dict


def _check_extoam_data(extoam_orig, extoam, region_config=False):

    subnetkey = 'oam_subnet'
    if subnetkey in extoam.keys():
        subnet = extoam[subnetkey]
        try:
            subnet = IPNetwork(subnet)
        except AddrFormatError:
            raise wsme.exc.ClientSideError(_(
                "Invalid subnet %s %s."
                "Please configure a valid subnet"
            ) % (subnetkey, subnet))

        try:
            utils.is_valid_subnet(subnet)
        except Exception as e:
            raise wsme.exc.ClientSideError(_(
                "Invalid subnet %s %s."
                "Please check and configure a valid OAM Subnet."
            ) % (subnetkey, subnet))

    skip_oam_gateway_ip_check = False
    gateway_ipkey = 'oam_gateway_ip'
    gateway_ip = extoam.get(gateway_ipkey) or ""
    if gateway_ipkey in extoam.keys():
        ogateway_ip = extoam_orig.get(gateway_ipkey) or ""
        osubnet = extoam_orig.get(subnetkey) or ""
        if not ogateway_ip and osubnet:
            if gateway_ip:
                raise wsme.exc.ClientSideError(_(
                    "OAM gateway IP is not allowed to be configured %s %s. "
                    "There is already a management gateway address configured."
                ) % (ogateway_ip, gateway_ip))
            else:
                skip_oam_gateway_ip_check = True

    for k, v in extoam.items():
        if k in extoam_ip_address_keys:

            if skip_oam_gateway_ip_check:
                if k == "oam_gateway_ip":
                    continue
            if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
                if k == "oam_c0_ip" or k == 'oam_c1_ip':
                    continue
            try:
                v = IPAddress(v)
            except (AddrFormatError, ValueError):
                raise wsme.exc.ClientSideError(_(
                    "Invalid address %s in %s."
                    " Please configure a valid"
                    " IPv%s address"
                ) % (v, k, str(subnet.version)))

            utils.is_valid_address_within_subnet(v, subnet)

    oam_c0_ip = extoam.get('oam_c0_ip') or ""
    oam_c1_ip = extoam.get('oam_c1_ip') or ""

    # check for unique if not empty
    if oam_c0_ip and oam_c0_ip == oam_c1_ip:
        raise wsme.exc.ClientSideError(_(
            "Invalid address: "
            "oam_c0_ip=%s and oam_c1_ip=%s must be unique. "
        ) % (oam_c0_ip, oam_c1_ip))

    if gateway_ip and (gateway_ip == oam_c0_ip) or (gateway_ip == oam_c1_ip):
        raise wsme.exc.ClientSideError(_(
            "Invalid address: "
            "oam_c0_ip=%s, oam_c1_ip=%s, oam_gateway_ip=%s must be unique."
        ) % (oam_c0_ip, oam_c1_ip, gateway_ip))

    # Region Mode, check if addresses are within start and end range
    # Gateway address is not used in region mode
    subnet = IPNetwork(extoam.get('oam_subnet'))
    floating_address = IPAddress(extoam.get('oam_floating_ip'))
    start_address = IPAddress(extoam.get('oam_start_ip'))
    end_address = IPAddress(extoam.get('oam_end_ip'))
    # check whether start and end addresses are within the oam_subnet range
    if start_address not in subnet:
        if region_config:
            raise wsme.exc.ClientSideError(_(
                "Invalid oam_start_ip=%s. Please configure a valid IP address")
                % start_address)
        LOG.info("Updating oam_start_ip=%s to %s" % (start_address, subnet[1]))
        extoam['oam_start_ip'] = subnet[1]
        start_address = IPAddress(extoam.get('oam_start_ip'))

    if end_address not in subnet:
        if region_config:
            raise wsme.exc.ClientSideError(_(
                "Invalid oam_end_ip=%s. Please configure a valid IP address") %
                end_address)
        LOG.info("Updating oam_end_ip=%s to %s" % (end_address, subnet[-2]))
        extoam['oam_end_ip'] = subnet[-2]
        end_address = IPAddress(extoam.get('oam_end_ip'))

    if floating_address not in IPRange(start_address, end_address):
        raise wsme.exc.ClientSideError(_(
            "Invalid oam_floating_ip=%s. Please configure a valid IP address "
            "in range")
            % floating_address)

    if oam_c0_ip and IPAddress(oam_c0_ip) not in IPRange(start_address, end_address):
        raise wsme.exc.ClientSideError(_(
            "Invalid oam_c0_ip=%s. Please configure a valid IP address "
            "in range")
            % oam_c0_ip)

    if oam_c1_ip and IPAddress(oam_c1_ip) not in IPRange(start_address, end_address):
        raise wsme.exc.ClientSideError(_(
            "Invalid oam_c1_ip=%s. Please configure a valid IP address "
            "in range")
            % oam_c1_ip)

    return extoam


LOCK_NAME = 'OAMNetworkController'


class OAMNetworkController(rest.RestController):
    """REST controller for iextoams."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems
        self._region_config = None

    def _get_region_config(self):
        if self._region_config is None:
            self._region_config = utils.get_region_config()
        if self._region_config == "False":
            self._region_config = False
        return self._region_config

    def _get_extoams_collection(self, isystem_uuid, marker, limit, sort_key,
                                sort_dir, expand=False, resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.oam_network.get_by_uuid(pecan.request.context,
                                                         marker)

        extoams = pecan.request.dbapi.iextoam_get_list(limit, marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)

        return OAMNetworkCollection.convert_with_links(extoams, limit,
                                                       url=resource_url,
                                                       expand=expand,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)

    @wsme_pecan.wsexpose(OAMNetworkCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of extoams. Only one per system"""

        return self._get_extoams_collection(isystem_uuid, marker, limit,
                                            sort_key, sort_dir)

    @wsme_pecan.wsexpose(OAMNetworkCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of extoams with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "iextoams":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['extoams', 'detail'])
        return self._get_extoams_collection(isystem_uuid,
                                            marker, limit,
                                            sort_key, sort_dir,
                                            expand, resource_url)

    @wsme_pecan.wsexpose(OAMNetwork, types.uuid)
    def get_one(self, extoam_uuid):
        """Retrieve information about the given extoam."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_extoam = \
            objects.oam_network.get_by_uuid(pecan.request.context, extoam_uuid)
        return OAMNetwork.convert_with_links(rpc_extoam)

    @wsme_pecan.wsexpose(OAMNetwork, body=OAMNetwork)
    def post(self, extoam):
        """Create a new extoam."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [OAMNetworkPatchType])
    @wsme_pecan.wsexpose(OAMNetwork, types.uuid,
                         body=[OAMNetworkPatchType])
    def patch(self, extoam_uuid, patch):
        """Update the current OAM configuration."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_extoam = objects.oam_network.get_by_uuid(pecan.request.context,
                                                     extoam_uuid)

        # this is required for cases where action is appended
        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        # replace isystem_uuid and iextoam_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id', '/created_at', '/updated_at',
                          '/forisystemid', '/isystem_uuid',
                          ]

        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s from this level." %
                                             state_rel_path))

        extoam_orig = copy.deepcopy(rpc_extoam)
        for p in patch_obj:
            if p['path'] == '/isystem_uuid':
                isystem = objects.system.get_by_uuid(pecan.request.context,
                                                     p['value'])
                p['path'] = '/forisystemid'
                p['value'] = isystem.id

        try:
            extoam = OAMNetwork(**jsonpatch.apply_patch(rpc_extoam.as_dict(),
                                                        patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        region_config = self._get_region_config()

        # extoam.region_config = region_config
        LOG.info("extoam %s, region_config=%s " %
                 (extoam.as_dict(), str(region_config)))

        extoam = _check_extoam_data(extoam_orig.as_dict(), extoam.as_dict(),
                                    region_config)

        try:
            # Update only the fields that have changed
            for field in objects.oam_network.fields:
                if rpc_extoam[field] != extoam[field]:
                    rpc_extoam[field] = extoam[field]

            rpc_extoam.save()

            pecan.request.rpcapi.update_oam_config(pecan.request.context)

            return OAMNetwork.convert_with_links(rpc_extoam)

        except exception.HTTPNotFound:
            msg = _("OAM IP update failed: system %s extoam %s: patch %s"
                    % (isystem['systemname'], extoam, patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, extoam_uuid):
        """Delete a extoam."""
        raise exception.OperationNotPermitted
