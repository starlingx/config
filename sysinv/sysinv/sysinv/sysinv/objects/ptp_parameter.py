########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.common import constants
from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def get_owners(field, db_object):
    ptp_parameter_owners = db_object['ptp_parameter_owners']
    if not ptp_parameter_owners:
        return []

    owners = []
    for owner in ptp_parameter_owners:
        details = {}
        details['uuid'] = owner.uuid
        if owner.type == constants.PTP_PARAMETER_OWNER_INSTANCE:
            details['owner'] = owner.name
            details['type'] = owner.service
        owners.append(details)

    return owners


class PtpParameter(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'name': utils.str_or_none,
            'value': utils.str_or_none,

            'owners': list
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
