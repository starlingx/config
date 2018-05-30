#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.common import constants
from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


def get_lldp_tlvs(field, db_object):
    if hasattr(db_object, field):
        return db_object[field]
    if hasattr(db_object, 'lldptlvs'):
        tlv_object = db_object['lldptlvs']
        if tlv_object:
            for tlv in tlv_object:
                if tlv['type'] == field:
                    return tlv['value']
    return None


class LLDPAgent(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.str_or_none,
              'status': utils.str_or_none,
              'host_id': utils.int_or_none,
              'host_uuid': utils.str_or_none,
              'port_id': utils.int_or_none,
              'port_uuid': utils.str_or_none,
              'port_name': utils.str_or_none,
              'port_namedisplay': utils.str_or_none}

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'port_uuid': 'port:uuid',
        'port_name': 'port:name',
        'port_namedisplay': 'port:namedisplay',
    }

    for tlv in constants.LLDP_TLV_VALID_LIST:
        fields.update({tlv: utils.str_or_none})
        _foreign_fields.update({tlv: get_lldp_tlvs})

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.lldp_agent_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.lldp_agent_update(self.uuid, updates)
