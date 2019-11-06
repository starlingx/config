#!/usr/bin/env python
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from oslo_utils import excutils
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class TrapDestPatchType(types.JsonPatchType):
    pass


class TrapDest(base.APIBase):
    """API representation of a trap destination.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a itrapdest.
    """

    uuid = types.uuid
    "The UUID of the itrapdest"

    ip_address = wsme.wsattr(wtypes.text, mandatory=True)
    "The ip address of the trap destination"

    community = wsme.wsattr(wtypes.text, mandatory=True)
    "The community of which the trap destination is a member"

    port = int
    "The port number of which the SNMP manager is listening for trap"

    type = wtypes.text
    "The SNMP version of the trap message"

    transport = wtypes.text
    "The SNMP version of the trap message"

    links = [link.Link]
    "A list containing a self link and associated trap destination links"

    def __init__(self, **kwargs):
        self.fields = objects.trapdest.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_itrapdest, expand=True):
        minimum_fields = ['id', 'uuid', 'ip_address',
                          'community', 'port',
                          'type', 'transport']

        fields = minimum_fields if not expand else None

        itrap = TrapDest.from_rpc_object(rpc_itrapdest, fields)

        itrap.links = [link.Link.make_link('self', pecan.request.host_url,
                                           'itrapdest', itrap.uuid),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'itrapdest', itrap.uuid,
                                           bookmark=True)
                       ]
        return itrap


class TrapDestCollection(collection.Collection):
    """API representation of a collection of itrapdest."""

    itrapdest = [TrapDest]
    "A list containing itrapdest objects"

    def __init__(self, **kwargs):
        self._type = 'itrapdest'

    @classmethod
    def convert_with_links(cls, itrapdest, limit, url=None,
                           expand=False, **kwargs):
        collection = TrapDestCollection()
        collection.itrapdest = [TrapDest.convert_with_links(ch, expand)
                                for ch in itrapdest]
        # url = url or None
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'TrapDestController'


class TrapDestController(rest.RestController):
    """REST controller for itrapdest."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_itrapdest_collection(self, marker, limit, sort_key, sort_dir,
                                expand=False, resource_url=None):
        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.trapdest.get_by_uuid(pecan.request.context,
                                                      marker)
        itrap = pecan.request.dbapi.itrapdest_get_list(limit, marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)
        return TrapDestCollection.convert_with_links(itrap, limit,
                                                     url=resource_url,
                                                     expand=expand,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

    @wsme_pecan.wsexpose(TrapDestCollection, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of itrapdests.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        return self._get_itrapdest_collection(marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(TrapDestCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of itrapdest with detail.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        # /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "itrapdest":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['itrapdest', 'detail'])
        return self._get_itrapdest_collection(marker, limit, sort_key, sort_dir,
                                              expand, resource_url)

    @wsme_pecan.wsexpose(TrapDest, wtypes.text)
    def get_one(self, ip):
        """Retrieve information about the given itrapdest.

        :param itrapdest_uuid: UUID of a itrapdest.
        """
        rpc_itrapdest = objects.trapdest.get_by_ip(
            pecan.request.context, ip)
        return TrapDest.convert_with_links(rpc_itrapdest)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(TrapDest, body=TrapDest)
    def post(self, itrapdest):
        """Create a new itrapdest.

        :param itrapdest: a itrapdest within the request body.
        """
        try:
            new_itrapdest = pecan.request.dbapi.itrapdest_create(itrapdest.as_dict())
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        # update snmpd.conf
        pecan.request.rpcapi.update_snmp_config(pecan.request.context)
        return itrapdest.convert_with_links(new_itrapdest)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [TrapDestPatchType])
    @wsme_pecan.wsexpose(TrapDest, types.uuid, body=[TrapDestPatchType])
    def patch(self, itrapdest_uuid, patch):
        """Update an existing itrapdest.

        :param itrapdest_uuid: UUID of a itrapdest.
        :param patch: a json PATCH document to apply to this itrapdest.
        """
        rpc_itrapdest = objects.trapdest.get_by_uuid(pecan.request.context,
                                                     itrapdest_uuid)
        try:
            itrap = TrapDest(**jsonpatch.apply_patch(rpc_itrapdest.as_dict(),
                                                     jsonpatch.JsonPatch(patch)))
        except api_utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        ip = ""
        for field in objects.trapdest.fields:
            if rpc_itrapdest[field] != getattr(itrap, field):
                rpc_itrapdest[field] = getattr(itrap, field)
                if field == 'ip_address':
                    ip = rpc_itrapdest[field]

        rpc_itrapdest.save()

        if ip:
            LOG.debug("Modify destination IP: uuid (%s), ip (%s",
                      itrapdest_uuid, ip)

        return TrapDest.convert_with_links(rpc_itrapdest)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, ip):
        """Delete a itrapdest.

        :param ip: ip address of a itrapdest.
        """
        pecan.request.dbapi.itrapdest_destroy(ip)
        # update snmpd.conf
        pecan.request.rpcapi.update_snmp_config(pecan.request.context)
