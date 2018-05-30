#
# Copyright (c) 2016-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


def get_peer_values(field, db_object):
    """Retrieves the list of peers associated with the cluster."""
    peers = []
    for entry in getattr(db_object, 'peers', []):
        hosts = []
        for ientry in getattr(entry, 'hosts', []):
            hosts.append(ientry.hostname)

        val = {'name': entry.name,
               'status': entry.status,
               'hosts': hosts,
               'uuid': entry.uuid}

        peers.append(val)

    return peers


def get_tier_values(field, db_object):
    """Retrieves the list of storage tiers associated with the cluster."""
    tiers = []
    for entry in getattr(db_object, 'tiers', []):
        val = {'name': entry.name,
               'status': entry.status,
               'uuid': entry.uuid}

        tiers.append(val)

    return tiers


class Cluster(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'cluster_uuid': utils.str_or_none,
        'system_id': utils.int_or_none,
        'type': utils.str_or_none,
        'name': utils.str_or_none,
        'capabilities': utils.dict_or_none,
        'peers': list,
        'tiers': list,
    }

    _foreign_fields = {
        'peers': get_peer_values,
        'tiers': get_tier_values
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.cluster_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.cluster_update(self.uuid, updates)
