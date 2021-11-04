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


def get_owner(field, db_object):
    owner = {}
    """Retrieves the owner details based on type and uuid."""
    if db_object['type'] == constants.PTP_PARAMETER_OWNER_INSTANCE:
        ptp_instances = getattr(db_object, 'ptp_instance')
        if ptp_instances:
            owner['name'] = ptp_instances[0].name
            owner['type'] = ptp_instances[0].service
            host = getattr(ptp_instances[0], 'host')
            if host:
                owner['hostname'] = host.hostname

    elif db_object['type'] == constants.PTP_PARAMETER_OWNER_INTERFACE:
        ptp_interfaces = getattr(db_object, 'ptp_interface')
        if ptp_interfaces:
            interface = getattr(ptp_interfaces[0], 'interface')
            if interface:
                owner['name'] = interface.ifname
                owner['type'] = interface.iftype
                host = getattr(interface, 'host')
                if host:
                    owner['hostname'] = host.hostname

    return owner


class PtpParameter(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'name': utils.str_or_none,
            'value': utils.str_or_none,

            'type': utils.str_or_none,
            'foreign_uuid': utils.str_or_none,

            'owner': dict
             }

    _foreign_fields = {
        'owner': get_owner
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_parameter_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ptp_parameter_update(self.uuid,  # pylint: disable=no-member
                                        updates)
