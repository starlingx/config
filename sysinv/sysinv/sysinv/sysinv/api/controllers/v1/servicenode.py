#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import sm_api
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class SMServiceNode(base.APIBase):

    id = int
    name = wtypes.text
    administrative_state = wtypes.text
    ready_state = wtypes.text
    operational_state = wtypes.text
    availability_status = wtypes.text

    def __init__(self, **kwargs):
        self.fields = ['id', 'name', 'administrative_state', 'ready_state',
                       'operational_state', 'availability_status']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))


class SMServiceNodeCollection(base.APIBase):
    """API representation of a collection of SM service node."""

    nodes = [SMServiceNode]
    "A list containing SmService objects"

    def __init__(self, **kwargs):
        self._type = 'SmService'

    @classmethod
    def convert(cls, smservicenodes):
        collection = SMServiceNodeCollection()
        collection.nodes = [SMServiceNode(**n) for n in smservicenodes]
        return collection


class SMServiceNodeController(rest.RestController):

    @wsme_pecan.wsexpose(SMServiceNode, unicode)
    def get_one(self, uuid):
        sm_servicenode = sm_api.servicenode_show(uuid)
        if sm_servicenode is None:
            raise wsme.exc.ClientSideError(_(
                    "Service node %s could not be found") % uuid)
        return SMServiceNode(**sm_servicenode)

    @wsme_pecan.wsexpose(SMServiceNodeCollection)
    def get(self):
        sm_servicenodes = sm_api.servicenode_list()

        # sm_api returns {'nodes':[list of nodes]}
        if isinstance(sm_servicenodes, dict):
            if 'nodes' in sm_servicenodes:
                sm_servicenodes = sm_servicenodes['nodes']
                return SMServiceNodeCollection.convert(sm_servicenodes)
        LOG.error("Bad response from SM API")
        raise wsme.exc.ClientSideError(_(
                    "Bad response from SM API"))
