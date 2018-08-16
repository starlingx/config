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


import jsonpatch

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
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

from netaddr import IPAddress, AddrFormatError


LOG = log.getLogger(__name__)


class NTPPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/ntpservers']


class NTP(base.APIBase):
    """API representation of NTP configuration.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an ntp.
    """

    uuid = types.uuid
    "Unique UUID for this ntp"

    enabled = types.boolean
    "Represent the status of the intp."

    ntpservers = wtypes.text
    "Represent the ntpservers of the intp. csv list."

    action = wtypes.text
    "Represent the action on the intp."

    forisystemid = int
    "The isystemid that this intp belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this ntp belongs to"

    links = [link.Link]
    "A list containing a self link and associated ntp links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.ntp.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.intp.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_ntp, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # ntp = intp.from_rpc_object(rpc_ntp, fields)

        ntp = NTP(**rpc_ntp.as_dict())
        if not expand:
            ntp.unset_fields_except(['uuid',
                                     'enabled',
                                     'ntpservers',
                                     'isystem_uuid',
                                     'created_at',
                                     'updated_at'])

        # never expose the isystem_id attribute
        ntp.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # ntp.forisystemid = wtypes.Unset

        ntp.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'intps', ntp.uuid),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'intps', ntp.uuid,
                                         bookmark=True)
                     ]

        return ntp


class intpCollection(collection.Collection):
    """API representation of a collection of ntps."""

    intps = [NTP]
    "A list containing ntp objects"

    def __init__(self, **kwargs):
        self._type = 'intps'

    @classmethod
    def convert_with_links(cls, rpc_ntps, limit, url=None,
                           expand=False, **kwargs):
        collection = intpCollection()
        collection.intps = [NTP.convert_with_links(p, expand)
                            for p in rpc_ntps]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############
def _check_ntp_data(op, ntp):
    # Get data
    enabled = ntp['enabled']
    ntpservers = ntp['ntpservers']
    intp_ntpservers_list = []
    ntp_ntpservers = ""
    idns_nameservers_list = []

    MAX_S = 3

    dns_list = pecan.request.dbapi.idns_get_by_isystem(ntp['forisystemid'])

    if dns_list:
        if hasattr(dns_list[0], 'nameservers'):
            if dns_list[0].nameservers:
                idns_nameservers_list = dns_list[0].nameservers.split(',')

    if ntpservers:
        for ntpserver in [n.strip() for n in ntpservers.split(',')]:
            # Semantic check each server as IP
            try:
                intp_ntpservers_list.append(str(IPAddress(ntpserver)))

            except (AddrFormatError, ValueError):
                if utils.is_valid_hostname(ntpserver):
                    # If server address in FQDN, and no DNS servers, raise error
                    if len(idns_nameservers_list) == 0 and ntpserver != 'NC':
                        raise wsme.exc.ClientSideError(_(
                            "A DNS server must be configured prior to "
                            "configuring any NTP server address as FQDN. "
                            "Alternatively, specify the NTP server as an IP"
                            " address"))
                    else:
                        if ntpserver == 'NC':
                            intp_ntpservers_list.append(str(""))
                        else:
                            intp_ntpservers_list.append(str(ntpserver))
                else:
                    raise wsme.exc.ClientSideError(_(
                        "Invalid NTP server %s "
                        "Please configure a valid NTP "
                        "IP address or hostname.") % (ntpserver))

    if len(intp_ntpservers_list) == 0 and enabled is None:
        raise wsme.exc.ClientSideError(_("No NTP parameters provided."))

    if len(intp_ntpservers_list) > MAX_S:
        raise wsme.exc.ClientSideError(_(
                   "Maximum NTP servers supported: %s but provided: %s. "
                   "Please configure a valid list of NTP servers."
                   % (MAX_S, len(intp_ntpservers_list))))

    ntp_ntpservers = ",".join(intp_ntpservers_list)

    ntp['ntpservers'] = ntp_ntpservers

    return ntp


LOCK_NAME = 'NTPController'


class NTPController(rest.RestController):
    """REST controller for intps."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_ntps_collection(self, isystem_uuid, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                  "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ntp.get_by_uuid(pecan.request.context,
                                                 marker)

        if isystem_uuid:
            ntps = pecan.request.dbapi.intp_get_by_isystem(
                                                    isystem_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            ntps = pecan.request.dbapi.intp_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return intpCollection.convert_with_links(ntps, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(intpCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of ntps. Only one per system"""

        return self._get_ntps_collection(isystem_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(intpCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of ntps with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "intps":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['ntps', 'detail'])
        return self._get_ntps_collection(isystem_uuid,
                                         marker, limit,
                                         sort_key, sort_dir,
                                         expand, resource_url)

    @wsme_pecan.wsexpose(NTP, types.uuid)
    def get_one(self, ntp_uuid):
        """Retrieve information about the given ntp."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_ntp = objects.ntp.get_by_uuid(pecan.request.context, ntp_uuid)
        return NTP.convert_with_links(rpc_ntp)

    @wsme_pecan.wsexpose(NTP, body=NTP)
    def post(self, ntp):
        """Create a new ntp."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [NTPPatchType])
    @wsme_pecan.wsexpose(NTP, types.uuid,
                         body=[NTPPatchType])
    def patch(self, ntp_uuid, patch):
        """Update the current NTP configuration."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_ntp = objects.ntp.get_by_uuid(pecan.request.context, ntp_uuid)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        # replace isystem_uuid and intp_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id', 'forisystemid', 'isystem_uuid']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s" %
                                             state_rel_path))

        for p in patch_obj:
            if p['path'] == '/isystem_uuid':
                isystem = objects.system.get_by_uuid(pecan.request.context,
                                                     p['value'])
                p['path'] = '/forisystemid'
                p['value'] = isystem.id

        try:
            # Keep an original copy of the ntp data
            ntp_orig = rpc_ntp.as_dict()

            ntp = NTP(**jsonpatch.apply_patch(rpc_ntp.as_dict(),
                                              patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        LOG.warn("ntp %s" % ntp.as_dict())
        ntp = _check_ntp_data("modify", ntp.as_dict())

        try:
            # Update only the fields that have changed
            for field in objects.ntp.fields:
                if rpc_ntp[field] != ntp[field]:
                    rpc_ntp[field] = ntp[field]

            delta = rpc_ntp.obj_what_changed()
            delta_handle = list(delta)
            if delta:
                rpc_ntp.save()

                if 'enabled' in delta_handle:
                    service_change = True
                else:
                    service_change = False
                if action == constants.APPLY_ACTION:
                    # perform rpc to conductor to perform config apply
                    pecan.request.rpcapi.update_ntp_config(pecan.request.context,
                                                           service_change)
            else:
                LOG.info("No NTP config changes")

            return NTP.convert_with_links(rpc_ntp)

        except Exception as e:
            # rollback database changes
            for field in ntp_orig:
                if rpc_ntp[field] != ntp_orig[field]:
                    rpc_ntp[field] = ntp_orig[field]
            rpc_ntp.save()

            msg = _("Failed to update the NTP configuration")
            if e == exception.HTTPNotFound:
                msg = _("NTP update failed: system %s if %s : patch %s"
                        % (isystem['systemname'], ntp['ifname'], patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ntp_uuid):
        """Delete a ntp."""
        raise exception.OperationNotPermitted
