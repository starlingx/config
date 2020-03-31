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

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

from netaddr import IPAddress
from netaddr import AddrFormatError


LOG = log.getLogger(__name__)


class DNSPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class DNS(base.APIBase):
    """API representation of DNS configuration.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an dns.
    """

    uuid = types.uuid
    "Unique UUID for this dns"

    nameservers = wtypes.text
    "Represent the nameservers of the idns. csv list."

    action = wtypes.text
    "Represent the action on the idns."

    forisystemid = int
    "The isystemid that this idns belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this dns belongs to"

    links = [link.Link]
    "A list containing a self link and associated dns links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = list(objects.dns.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.idns.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_dns, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # dns = idns.from_rpc_object(rpc_dns, fields)

        dns = DNS(**rpc_dns.as_dict())
        if not expand:
            dns.unset_fields_except(['uuid',
                                     'nameservers',
                                     'isystem_uuid',
                                     'created_at',
                                     'updated_at'])

        # never expose the isystem_id attribute
        dns.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # dns.forisystemid = wtypes.Unset

        dns.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'idnss', dns.uuid),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'idnss', dns.uuid,
                                         bookmark=True)
                     ]

        return dns


class DNSCollection(collection.Collection):
    """API representation of a collection of dnss."""

    idnss = [DNS]
    "A list containing dns objects"

    def __init__(self, **kwargs):
        self._type = 'idnss'

    @classmethod
    def convert_with_links(cls, rpc_dnss, limit, url=None,
                           expand=False, **kwargs):
        collection = DNSCollection()
        collection.idnss = [DNS.convert_with_links(p, expand)
                            for p in rpc_dnss]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############
def _check_dns_data(dns, ip_family):
    # Get data
    nameservers = dns['nameservers']
    idns_nameservers_list = []
    dns_nameservers = ""

    MAX_S = 3

    if 'forisystemid' in dns.keys():
        ntp_list = pecan.request.dbapi.intp_get_by_isystem(dns['forisystemid'])
    else:
        ntp_list = pecan.request.dbapi.intp_get_by_isystem(dns['isystem_uuid'])

    if nameservers:
        for nameserver in [n.strip() for n in nameservers.split(',')]:
            # Semantic check each server as IP
            try:
                idns_nameservers_list.append(str(IPAddress(nameserver)))
                if ip_family and IPAddress(nameserver).version != ip_family:
                    raise wsme.exc.ClientSideError(_(
                        "IP version mismatch: was expecting "
                        "IPv%d, IPv%d received") % (ip_family,
                            IPAddress(nameserver).version))
            except (AddrFormatError, ValueError):

                if nameserver == 'NC':
                    idns_nameservers_list.append(str(""))
                    break

                raise wsme.exc.ClientSideError(_(
                           "Invalid DNS nameserver target address %s "
                           "Please configure a valid DNS "
                           "address.") % (nameserver))

    if len(idns_nameservers_list) == 0 or idns_nameservers_list == [""]:
        if ntp_list:
            if hasattr(ntp_list[0], 'ntpservers'):
                if ntp_list[0].ntpservers:
                    for ntpserver in [n.strip() for n in
                                      ntp_list[0].ntpservers.split(',')]:
                        try:
                            str(IPAddress(ntpserver))

                        except (AddrFormatError, ValueError):
                            if utils.is_valid_hostname(ntpserver):
                                raise wsme.exc.ClientSideError(_(
                                    "At least  one DNS server must be used "
                                    "when any NTP server address is using "
                                    "FQDN. Alternatively, use IPv4 or IPv6 for"
                                    "NTP server address and then delete DNS "
                                    "servers."))

    if len(idns_nameservers_list) > MAX_S:
        raise wsme.exc.ClientSideError(_(
                   "Maximum DNS nameservers supported: %s but provided: %s. "
                   "Please configure a valid list of DNS nameservers."
                   % (MAX_S, len(idns_nameservers_list))))

    dns_nameservers = ",".join(idns_nameservers_list)

    dns['nameservers'] = dns_nameservers

    return dns


LOCK_NAME = 'DNSController'


class DNSController(rest.RestController):
    """REST controller for idnss."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_dnss_collection(self, isystem_uuid, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                  "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.dns.get_by_uuid(pecan.request.context,
                                                 marker)

        if isystem_uuid:
            dnss = pecan.request.dbapi.idns_get_by_isystem(
                                                    isystem_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            dnss = pecan.request.dbapi.idns_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return DNSCollection.convert_with_links(dnss, limit,
                                                url=resource_url,
                                                expand=expand,
                                                sort_key=sort_key,
                                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DNSCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of dnss. Only one per system"""

        return self._get_dnss_collection(isystem_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(DNSCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of dnss with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "idnss":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['dnss', 'detail'])
        return self._get_dnss_collection(isystem_uuid,
                                         marker, limit,
                                         sort_key, sort_dir,
                                         expand, resource_url)

    @wsme_pecan.wsexpose(DNS, types.uuid)
    def get_one(self, dns_uuid):
        """Retrieve information about the given dns."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_dns = objects.dns.get_by_uuid(pecan.request.context, dns_uuid)
        return DNS.convert_with_links(rpc_dns)

    @wsme_pecan.wsexpose(DNS, body=DNS)
    def post(self, dns):
        """Create a new dns."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [DNSPatchType])
    @wsme_pecan.wsexpose(DNS, types.uuid,
                         body=[DNSPatchType])
    def patch(self, dns_uuid, patch):
        """Update the current DNS configuration."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_dns = objects.dns.get_by_uuid(pecan.request.context, dns_uuid)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        # replace isystem_uuid and idns_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id', '/forisystemid',
                          '/isystem_uuid']
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

            # Keep an original copy of the dns data
            dns_orig = rpc_dns.as_dict()

            dns = DNS(**jsonpatch.apply_patch(rpc_dns.as_dict(),
                                              patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Since dns requests on the controller go over the oam network,
        # check the ip version of the oam address pool in the database
        oam_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_OAM)
        oam_address_pool = pecan.request.dbapi.address_pool_get(
            oam_network.pool_uuid)
        ip_family = oam_address_pool.family

        LOG.info("dns %s; ip_family: ipv%d" % (dns.as_dict(), ip_family))
        dns = _check_dns_data(dns.as_dict(), ip_family)

        try:
            # Update only the fields that have changed
            for field in objects.dns.fields:
                if rpc_dns[field] != dns[field]:
                    rpc_dns[field] = dns[field]

            delta = rpc_dns.obj_what_changed()
            if delta:
                rpc_dns.save()

                if action == constants.APPLY_ACTION:
                    # perform rpc to conductor to perform config apply
                    pecan.request.rpcapi.update_dns_config(
                        pecan.request.context)
            else:
                LOG.info("No DNS config changes")

            return DNS.convert_with_links(rpc_dns)

        except Exception as e:
            # rollback database changes
            for field in dns_orig:
                if rpc_dns[field] != dns_orig[field]:
                    rpc_dns[field] = dns_orig[field]
            rpc_dns.save()

            msg = _("Failed to update the DNS configuration")
            if e == exception.HTTPNotFound:
                msg = _("DNS update failed: system %s dns %s : patch %s"
                        % (isystem['systemname'], dns, patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, dns_uuid):
        """Delete a dns."""
        raise exception.OperationNotPermitted
