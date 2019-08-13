#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
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


def get_host_values(field, db_object):
    """Retrieves the list of hosts associated with peer."""
    result = []
    for entry in getattr(db_object, 'hosts', []):
        result.append(entry.hostname)
    return result


class Peer(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'cluster_id': int,
            'name': utils.str_or_none,
            'status': utils.str_or_none,
            'info': utils.dict_or_none,
            'capabilities': utils.dict_or_none,
            'hosts': list,
             }

    _foreign_fields = {'hosts': get_host_values}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.peer_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.peer_update(self.uuid,  # pylint: disable=no-member
                               updates)
