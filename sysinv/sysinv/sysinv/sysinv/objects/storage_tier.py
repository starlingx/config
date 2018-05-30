#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sqlalchemy.orm import exc

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


def get_backend_uuid(field, db_object):
    """Retrieves backend uuid."""

    if hasattr(db_object, 'backend_uuid'):
        return db_object['backend_uuid']

    backend_uuid = None
    try:
        backend = getattr(db_object, 'stor_backend')
        if backend:
            backend_uuid = backend.uuid
    except exc.DetachedInstanceError:
        # No backend associated with the tier
        pass

    return backend_uuid


def get_cluster_uuid(field, db_object):
    """Retrieves cluster uuid."""

    if hasattr(db_object, 'cluster_uuid'):
        return db_object['cluster_uuid']

    cluster_uuid = None
    try:
        cluster = getattr(db_object, 'cluster')
        if cluster:
            cluster_uuid = cluster.uuid
    except exc.DetachedInstanceError:
        # No cluster associated with the tier
        pass

    return cluster_uuid


def get_stor_ids(field, db_object):
    """Retrieves the list of stors associated with the tier."""
    stors = []
    try:
        for entry in getattr(db_object, 'stors', []):
            # Exclude profile OSDs as they don't have and ID and are not active
            # on the tier
            if entry.osdid is not None:
                stors.append(entry.osdid)
    except exc.DetachedInstanceError:
        # No istor assigned to the tier
        pass

    return stors


class StorageTier(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'name': utils.str_or_none,
        'type': utils.str_or_none,
        'status': utils.str_or_none,
        'capabilities': utils.dict_or_none,

        'forbackendid': utils.int_or_none,
        'backend_uuid': utils.str_or_none,

        'forclusterid': utils.int_or_none,
        'cluster_uuid': utils.str_or_none,
        'stors': list,
    }

    _foreign_fields = {
        'backend_uuid': get_backend_uuid,
        'cluster_uuid': get_cluster_uuid,
        'stors': get_stor_ids
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.storage_tier_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.storage_tier_update(self.uuid, updates)
