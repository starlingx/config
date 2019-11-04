#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# this file is used for service group requests. Keeping naming consistent with sm client

from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import sm_api

LOG = log.getLogger(__name__)


class SMServiceGroup(base.APIBase):

    status = wtypes.text
    state = wtypes.text
    desired_state = wtypes.text
    name = wtypes.text
    service_group_name = wtypes.text
    node_name = wtypes.text
    condition = wtypes.text
    uuid = wtypes.text

    def __init__(self, **kwargs):
        self.fields = ['status', 'state', 'desired_state', 'name',
                       'service_group_name', 'node_name', 'condition', 'uuid']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))


class SMServiceGroupCollection(base.APIBase):
    """API representation of a collection of SM service group."""

    sm_servicegroup = [SMServiceGroup]
    "A list containing SmServiceGroup objects"

    def __init__(self, **kwargs):
        self._type = 'SmService'

    @classmethod
    def convert(cls, smservicegroups):
        collection = SMServiceGroupCollection()
        collection.sm_servicegroup = [SMServiceGroup(**n) for n in smservicegroups]
        return collection


class SMServiceGroupController(rest.RestController):

    @wsme_pecan.wsexpose(SMServiceGroup, six.text_type)
    def get_one(self, uuid):
        sm_servicegroup = sm_api.sm_servicegroup_show(uuid)
        if sm_servicegroup is None:
            raise wsme.exc.ClientSideError(_(
                    "Service group %s could not be found") % uuid)
        return SMServiceGroup(**sm_servicegroup)

    @wsme_pecan.wsexpose(SMServiceGroupCollection)
    def get(self):
        sm_servicegroups = sm_api.sm_servicegroup_list()

        # sm_api returns {'sm_servicegroup':[list of sm_servicegroups]}
        if isinstance(sm_servicegroups, dict):
            if 'sm_servicegroup' in sm_servicegroups:
                sm_servicegroups = sm_servicegroups['sm_servicegroup']
                return SMServiceGroupCollection.convert(sm_servicegroups)
        LOG.error("Bad response from SM API")
        raise wsme.exc.ClientSideError(_(
                    "Bad response from SM API"))
