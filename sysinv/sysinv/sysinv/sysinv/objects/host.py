#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def _get_software_load(field, db_object):
    if db_object.host_upgrade:
        return db_object.host_upgrade.load_software.software_version


def _get_target_load(field, db_object):
    if db_object.host_upgrade:
        return db_object.host_upgrade.load_target.software_version


class Host(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'forisystemid': utils.int_or_none,
            'isystem_uuid': utils.str_or_none,
            'peer_id': utils.int_or_none,
            'recordtype': utils.str_or_none,

            # 'created_at': utils.datetime_str_or_none,
            # 'updated_at': utils.datetime_str_or_none,
            'hostname': utils.str_or_none,
            'personality': utils.str_or_none,
            'subfunctions': utils.str_or_none,
            'subfunction_oper': utils.str_or_none,
            'subfunction_avail': utils.str_or_none,
            # Host is working on a blocking process
            'reserved': utils.str_or_none,
            # NOTE: instance_uuid must be read-only when server is provisioned
            'uuid': utils.str_or_none,

            # NOTE: driver should be read-only after server is created
            'invprovision': utils.str_or_none,
            'mgmt_mac': utils.str_or_none,
            'mgmt_ip': utils.str_or_none,

            # Board management members
            'bm_ip': utils.str_or_none,
            'bm_mac': utils.str_or_none,
            'bm_type': utils.str_or_none,
            'bm_username': utils.str_or_none,

            'location': utils.dict_or_none,
            # 'reservation': utils.str_or_none,
            'serialid': utils.str_or_none,
            'administrative': utils.str_or_none,
            'operational': utils.str_or_none,
            'availability': utils.str_or_none,
            'ihost_action': utils.str_or_none,
            'action_state': utils.str_or_none,
            'inv_state': utils.str_or_none,
            'mtce_info': utils.str_or_none,
            'vim_progress_status': utils.str_or_none,
            'action': utils.str_or_none,
            'task': utils.str_or_none,
            'uptime': utils.int_or_none,
            'config_status': utils.str_or_none,
            'config_applied': utils.str_or_none,
            'config_target': utils.str_or_none,
            'capabilities': utils.dict_or_none,
            'clock_synchronization': utils.str_or_none,

            'boot_device': utils.str_or_none,
            'rootfs_device': utils.str_or_none,
            'install_output': utils.str_or_none,
            'console': utils.str_or_none,
            'tboot': utils.str_or_none,
            'vsc_controllers': utils.str_or_none,
            'ttys_dcd': utils.str_or_none,
            'software_load': utils.str_or_none,
            'target_load': utils.str_or_none,
            'install_state': utils.str_or_none,
            'install_state_info': utils.str_or_none,
            'iscsi_initiator_name': utils.str_or_none,
            'device_image_update': utils.str_or_none,
            'reboot_needed': utils.bool_or_none,
             }

    _foreign_fields = {
        'isystem_uuid': 'system:uuid',
        'software_load': _get_software_load,
        'target_load': _get_target_load
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ihost_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ihost_update(self.uuid,  # pylint: disable=no-member
                                updates)


class ihost(Host):
    """Alias object for RPC compatibility with older versions based on the
    old naming convention.  Object compatibility based on object version."""
    pass
