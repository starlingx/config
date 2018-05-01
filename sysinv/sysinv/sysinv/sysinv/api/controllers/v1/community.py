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

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.db import exception as Exception
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class CommunityPatchType(types.JsonPatchType):
    pass


class Community(base.APIBase):
    """API representation of a Community.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a icommunity.
    """

    uuid = types.uuid
    "The UUID of the icommunity"

    community = wsme.wsattr(wtypes.text, mandatory=True)
    "The community string of which the SNMP client is a member"

    view = wtypes.text
    "The SNMP MIB View"

    access = wtypes.text
    "The SNMP GET/SET access control"

    links = [link.Link]
    "A list containing a self link and associated community string links"

    def __init__(self, **kwargs):
        self.fields = objects.community.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_icommunity, expand=True):
        minimum_fields = ['id', 'uuid', 'community',
                          'view', 'access']

        fields = minimum_fields if not expand else None

        icomm = Community.from_rpc_object(rpc_icommunity, fields)

        return icomm


class CommunityCollection(collection.Collection):
    """API representation of a collection of icommunity."""

    icommunity = [Community]
    "A list containing icommunity objects"

    def __init__(self, **kwargs):
        self._type = 'icommunity'

    @classmethod
    def convert_with_links(cls, icommunity, limit, url=None,
                           expand=False, **kwargs):
        collection = CommunityCollection()
        collection.icommunity = [Community.convert_with_links(ch, expand)
                                 for ch in icommunity]
        # url = url or None
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'CommunityController'


class CommunityController(rest.RestController):
    """REST controller for icommunity."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_icommunity_collection(self, marker, limit, sort_key, sort_dir,
                                   expand=False, resource_url=None):
        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.community.get_by_uuid(pecan.request.context,
                                                       marker)
        icomm = pecan.request.dbapi.icommunity_get_list(limit, marker_obj,
                                                        sort_key=sort_key,
                                                        sort_dir=sort_dir)
        return CommunityCollection.convert_with_links(icomm, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    @wsme_pecan.wsexpose(CommunityCollection, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of icommunity.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        return self._get_icommunity_collection(marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(CommunityCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of icommunity with detail.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        # /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "icommunity":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['icommunity', 'detail'])
        return self._get_icommunity_collection(marker, limit, sort_key, sort_dir,
                                            expand, resource_url)

    @wsme_pecan.wsexpose(Community, wtypes.text)
    def get_one(self, name):
        """Retrieve information about the given icommunity.

        :param icommunity_uuid: UUID of a icommunity.
        """
        rpc_icommunity = objects.community.get_by_name(
            pecan.request.context, name)
        return Community.convert_with_links(rpc_icommunity)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Community, body=Community)
    def post(self, icommunity):
        """Create a new icommunity.

        :param icommunity: a icommunity within the request body.
        """
        try:
            new_icommunity = \
                pecan.request.dbapi.icommunity_create(icommunity.as_dict())
        except Exception.DBDuplicateEntry as e:
            LOG.error(e)
            raise wsme.exc.ClientSideError(_(
                "Rejected: Cannot add %s, it is an existing community.") % icommunity.as_dict().get('community'))
        except Exception.DBError as e:
            LOG.error(e)
            raise wsme.exc.ClientSideError(_(
                "Database check error on community %s create.") % icommunity.as_dict().get('community'))
        except Exception as e:
            LOG.error(e)
            raise wsme.exc.ClientSideError(_(
                "Database error on community %s create. See log for details.") % icommunity.as_dict().get('community'))

        # update snmpd.conf
        pecan.request.rpcapi.update_snmp_config(pecan.request.context)
        return icommunity.convert_with_links(new_icommunity)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [CommunityPatchType])
    @wsme_pecan.wsexpose(Community, types.uuid, body=[CommunityPatchType])
    def patch(self, icommunity_uuid, patch):
        """Update an existing icommunity.

        :param icommunity_uuid: UUID of a icommunity.
        :param patch: a json PATCH document to apply to this icommunity.
        """
        rpc_icommunity = objects.community.get_by_uuid(pecan.request.context,
                                                       icommunity_uuid)
        try:
            icomm = Community(**jsonpatch.apply_patch(rpc_icommunity.as_dict(),
                                                      jsonpatch.JsonPatch(patch)))
        except api_utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        comm = ""
        for field in objects.community.fields:
            if rpc_icommunity[field] != getattr(icomm, field):
                rpc_icommunity[field] = getattr(icomm, field)
                if field == 'community':
                    comm = rpc_icommunity[field]

        rpc_icommunity.save()

        if comm:
            LOG.debug("Modify community: uuid (%s) community (%s) ",
                      icommunity_uuid, comm)

        return Community.convert_with_links(rpc_icommunity)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, name):
        """Delete a icommunity.

        :param name: community name of a icommunity.
        """
        pecan.request.dbapi.icommunity_destroy(name)
        # update snmpd.conf
        pecan.request.rpcapi.update_snmp_config(pecan.request.context)
