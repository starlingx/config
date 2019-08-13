#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

from sqlalchemy.orm import exc

from sysinv.openstack.common import log

LOG = log.getLogger(__name__)

dbapi = db_api.get_instance()


def get_journal_location(field, db_server):
    """Retrieves the uuid of the istor on which the OSD journal resides"""
    journal_location = None

    # When creating an istor journal_location is passed in db_server, return
    # this value as journal entries are not yet created
    if hasattr(db_server, 'journal_location'):
        return db_server['journal_location']

    try:
        for entry in getattr(db_server, 'journal', []):
            journal_location = entry.onistor_uuid
    except exc.DetachedInstanceError:
        # Not an issue, just return None
        pass

    return journal_location


def get_journal_size(field, db_server):
    """Retrieves the size of the stor's journal."""

    if hasattr(db_server, 'journal_size_mib'):
        return db_server['journal_size_mib']

    functions = ['journal', 'osd']
    if db_server['function'] not in functions:
        return None

    journal_size = 0
    try:
        for entry in getattr(db_server, 'journal', []):
            journal_size += entry.size_mib
    except exc.DetachedInstanceError:
        # Not an issue, just return 0
        pass

    return journal_size if journal_size else None


def get_journal_path(field, db_server):
    """Retrieve the node on which a stor's journal resides."""

    if hasattr(db_server, 'journal_path'):
        return db_server['journal_path']

    journal_path = None

    try:
        for entry in getattr(db_server, 'journal', []):
            journal_path = entry.device_path
    except exc.DetachedInstanceError:
        # Not an issue, just return None
        pass

    return journal_path


class Storage(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
              'id': int,
              'uuid': utils.str_or_none,
              'forihostid': int,
              'ihost_uuid': utils.str_or_none,
              'fortierid': utils.int_or_none,
              'tier_uuid': utils.str_or_none,
              'tier_name': utils.str_or_none,
              'osdid': utils.int_or_none,
              'idisk_uuid': utils.str_or_none,
              'state': utils.str_or_none,
              'function': utils.str_or_none,
              'capabilities': utils.dict_or_none,
              'journal_location': utils.uuid_or_none,
              'journal_size_mib': utils.int_or_none,
              'journal_path': utils.str_or_none
             }

    _foreign_fields = {
                       'ihost_uuid': 'host:uuid',
                       'tier_uuid': 'tier:uuid',
                       'tier_name': 'tier:name',
                       'journal_location': get_journal_location,
                       'journal_size_mib': get_journal_size,
                       'journal_path': get_journal_path
                      }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.istor_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.istor_update(self.uuid,  # pylint: disable=no-member
                                updates)
