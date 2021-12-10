########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def get_owners(field, db_object):
    owners = db_object['ptp_parameter_owners']
    uuids = []
    if owners is not None:
        for o in owners:
            uuids.append(o.uuid)
    return uuids


class PtpParameter(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'name': utils.str_or_none,
            'value': utils.str_or_none,
            'owners': utils.list_of_strings_or_none
             }

    _foreign_fields = {
        'owners': get_owners
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_parameter_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ptp_parameter_update(self.uuid,  # pylint: disable=no-member
                                        updates)
