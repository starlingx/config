#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Puppet common top level code."""

import subprocess

import os

from sysinv.common import exception
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log as logging
from tsconfig import tsconfig


LOG = logging.getLogger(__name__)

PUPPET_HIERADATA_PATH = os.path.join(tsconfig.PUPPET_PATH, 'hieradata')

# runtime applied manifest constants
REPORT_STATUS_CFG = 'report_status'
REPORT_SUCCESS = 'report_success'
REPORT_FAILURE = 'report_failure'

# name of manifest config operations to report back to sysinv conductor
REPORT_AIO_CINDER_CONFIG = 'aio_cinder_config'
REPORT_DISK_PARTITON_CONFIG = 'manage_disk_partitions'
REPORT_LVM_BACKEND_CONFIG = 'lvm_config'
REPORT_EXTERNAL_BACKEND_CONFIG = 'external_config'
REPORT_CEPH_BACKEND_CONFIG = 'ceph_config'
REPORT_CEPH_SERVICES_CONFIG = 'ceph_services'


def puppet_apply_manifest(ip_address, personality,
                          manifest=None, runtime=None, do_reboot=False,
                          hieradata_path=PUPPET_HIERADATA_PATH):
    """ Apply configuration for the specified manifest."""
    if not manifest:
        manifest = personality

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        hieradata_path,
        str(ip_address),
        personality,
        manifest
    ]

    if runtime:
        cmd.append(runtime)

    try:
        if do_reboot:
            LOG.warn("Sysinv will be rebooting the node post "
                     "manifest application")

            with open("/dev/console", "w") as fconsole:
                cmdstr = " ".join(cmd) + ' && reboot'
                subprocess.Popen(cmdstr,
                                 stdout=fconsole,
                                 stderr=fconsole,
                                 shell=True)
        else:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(cmd, stdout=fnull, stderr=fnull)
    except subprocess.CalledProcessError:
        msg = "Failed to execute %s manifest for host %s" % \
              (manifest, ip_address)
        LOG.exception(msg)
        raise exception.SysinvException(_(msg))
