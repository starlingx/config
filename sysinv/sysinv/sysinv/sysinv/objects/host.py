#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def _get_ptp_instance_names(field, db_object):
    instances = db_object['ptp_instances']
    names = []
    if instances is not None:
        for i in instances:
            names.append(str(i.name))
    return names


class Host(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = \
        {
            'id': int,
            'forisystemid': utils.int_or_none,
            'isystem_uuid': utils.str_or_none,
            'peer_id': utils.int_or_none,
            'recordtype': utils.str_or_none,

            # 'created_at': utils.datetime_str_or_none,
            # 'updated_at': utils.datetime_str_or_none,
            'hostname': utils.str_or_none,
            'personality': utils.str_or_none,
            'kernel_running': utils.str_or_none,
            'kernel_config_status': utils.str_or_none,
            'subfunctions': utils.str_or_none,
            'subfunction_oper': utils.str_or_none,
            'subfunction_avail': utils.str_or_none,
            'apparmor': utils.str_or_none,
            'apparmor_config_status': utils.str_or_none,

            # Host is working on a blocking process
            'reserved': utils.bool_or_none,
            # NOTE: instance_uuid must be read-only when server is provisioned
            'uuid': utils.str_or_none,

            # NOTE: driver should be read-only after server is created
            'invprovision': utils.str_or_none,
            'mgmt_mac': utils.str_or_none,
            'mgmt_ip': utils.str_or_none,

            # Software version
            'sw_version': utils.str_or_none,

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
            'hw_settle': utils.str_or_none,
            'install_output': utils.str_or_none,
            'console': utils.str_or_none,
            'tboot': utils.str_or_none,
            'vsc_controllers': utils.str_or_none,
            'ttys_dcd': utils.bool_or_none,
            'install_state': utils.str_or_none,
            'install_state_info': utils.str_or_none,
            'iscsi_initiator_name': utils.str_or_none,
            'device_image_update': utils.str_or_none,
            'reboot_needed': utils.bool_or_none,
            'max_cpu_mhz_configured': utils.str_or_none,
            'min_cpu_mhz_allowed': utils.str_or_none,
            'max_cpu_mhz_allowed': utils.str_or_none,
            'cstates_available': utils.str_or_none,
            'nvme_host_id': utils.str_or_none,
            'nvme_host_nqn': utils.str_or_none
             }

    _foreign_fields = {
        'isystem_uuid': 'system:uuid'
    }

    _optional_fields = {
        'mgmt_ip': utils.str_or_none
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
