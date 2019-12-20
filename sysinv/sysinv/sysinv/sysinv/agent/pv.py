#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory ipv Utilities and helper functions."""

from eventlet.green import subprocess
import json
import sys

from oslo_log import log as logging

from sysinv.common import disk_utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils

LOG = logging.getLogger(__name__)


class PVOperator(object):
    '''Class to encapsulate Physical Volume operations for System Inventory'''

    def __init__(self):
        pass

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename,
                                  traceback.tb_lineno))

    def ipv_get(self, cinder_device=None):
        '''Enumerate physical volume topology based on:

        :param self
        :param cinder_device: by-path of cinder device
        :returns list of physical volumes and attributes
        '''
        ipv = []

        # keys: matching the field order of pvdisplay command
        string_keys = ['lvm_pv_name', 'lvm_vg_name', 'lvm_pv_uuid',
                       'lvm_pv_size', 'lvm_pe_total', 'lvm_pe_alloced']

        # keys that need to be translated into ints
        int_keys = ['lvm_pv_size', 'lvm_pe_total', 'lvm_pe_alloced']

        # pvdisplay command to retrieve the pv data of all pvs present
        pvdisplay_command = 'pvdisplay -C --separator=";" -o pv_name,vg_name,pv_uuid'\
                            ',pv_size,pv_pe_count,pv_pe_alloc_count'\
                            ' --units B --nosuffix --noheadings'

        # Execute the command
        try:
            pvdisplay_process = subprocess.Popen(pvdisplay_command,
                                             stdout=subprocess.PIPE,
                                             shell=True)
            pvdisplay_output = pvdisplay_process.stdout.read()
        except Exception as e:
            self.handle_exception("Could not retrieve pvdisplay "
                                  "information: %s" % e)
            pvdisplay_output = ""

        # Cinder devices are hidden by global_filter on standby controller,
        # list them separately.
        if cinder_device:
            new_global_filer = ' --config \'devices/global_filter=["a|' + \
                               cinder_device + '|","r|.*|"]\''
            pvdisplay_process = pvdisplay_command + new_global_filer

            try:
                pvdisplay_process = subprocess.Popen(pvdisplay_process,
                                                     stdout=subprocess.PIPE,
                                                     shell=True)
                pvdisplay_output = pvdisplay_output + pvdisplay_process.stdout.read()
            except Exception as e:
                self.handle_exception("Could not retrieve vgdisplay "
                                      "information: %s" % e)

        # parse the output 1 pv/row
        rows = [row for row in pvdisplay_output.split('\n') if row.strip()]
        for row in rows:
            if "unknown device" in row:
                # Found a previously known pv that is now missing
                # This happens when a disk is physically removed without
                # being removed from the volume group first
                # Since the disk is gone we need to forcefully cleanup
                # the volume group
                try:
                    values = row.split(';')
                    values = [v.strip() for v in values]

                    vgreduce_command = 'vgreduce --removemissing %s' % values[2]
                    subprocess.Popen(vgreduce_command,
                                     stdout=subprocess.PIPE,
                                     shell=True)
                except Exception as e:
                    self.handle_exception("Could not execute vgreduce: %s" % e)
                continue

            # get the values of fields as strings
            values = row.split(';')
            values = [v.strip() for v in values]

            # create the dict of attributes
            attr = dict(zip(string_keys, values))

            # convert required values from strings to ints
            for k in int_keys:
                if k in attr.keys():
                    attr[k] = int(attr[k])

            # Make sure we have attributes and ignore orphaned PVs
            if attr and attr['lvm_vg_name']:
                # the lvm_pv_name for cinder volumes is always /dev/drbd4
                if attr['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
                    attr['lvm_pv_name'] = constants.CINDER_DRBD_DEVICE
                for pv in ipv:
                    # ignore duplicates
                    if pv['lvm_pv_name'] == attr.get('lvm_pv_name'):
                        break
                else:
                    ipv.append(attr)

        LOG.debug("ipv= %s" % ipv)

        return ipv

    def ipv_delete(self, ipv_dict):
        """Delete LVM physical volume

         Also delete Logical volume Group if PV is last in group

        :param ipv_dict: values for physical volume object
        :returns: pass or fail
        """
        LOG.info("Deleting PV: %s" % (ipv_dict))

        if ipv_dict['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES:
            # disable LIO targets before cleaning up volumes
            # as they may keep the volumes busy
            LOG.info("Clearing LIO configuration")
            cutils.execute('targetctl', 'clear',
                           run_as_root=True)
            # Note: targets are restored from config file by Cinder
            # on restart. Restarts should done after 'cinder-volumes'
            # re-configuration

        # Check if LVG exists
        stdout, __ = cutils.execute('vgs', '--reportformat', 'json',
                                    run_as_root=True)
        data = json.loads(stdout)['report']
        LOG.debug("ipv_delete vgs data: %s" % data)
        vgs = []
        for vgs_entry in data:
            if type(vgs_entry) == dict and 'vg' in vgs_entry.keys():
                vgs = vgs_entry['vg']
                break
        for vg in vgs:
            if vg['vg_name'] == ipv_dict['lvm_vg_name']:
                break
        else:
            LOG.info("VG %s not found, "
                     "skipping removal" % ipv_dict['lvm_vg_name'])
            vg = None

        # Remove all volumes from volume group before deleting any PV from it
        # (without proper pvmove the data will get corrupted anyway, so better
        # we remove the data while the group is still clean)
        if vg:
            LOG.info("Removing all volumes "
                     "from LVG %s" % ipv_dict['lvm_vg_name'])
            # VG exists, should not give any errors
            # (make sure no FD is open when running this)
            # TODO(oponcea): Run pvmove if multiple PVs are
            # associated with the same LVG to avoid data loss
            cutils.execute('lvremove',
                           ipv_dict['lvm_vg_name'],
                           '-f',
                           run_as_root=True)

        # Check if PV exists
        stdout, __ = cutils.execute('pvs', '--reportformat', 'json',
                                    run_as_root=True)
        data = json.loads(stdout)['report']
        LOG.debug("ipv_delete pvs data: %s" % data)
        pvs = []
        for pvs_entry in data:
            if type(pvs_entry) == dict and 'pv' in pvs_entry.keys():
                for pv in pvs:
                    pvs = vgs_entry['pv']
                    break
        for pv in pvs:
            if (pv['vg_name'] == ipv_dict['lvm_vg_name'] and
                    pv['pv_name'] == ipv_dict['lvm_pv_name']):
                break
        else:
            pv = None

        # Removing PV. VG goes down with it if last PV is removed from it
        if pv:
            parm = {'dev': ipv_dict['lvm_pv_name'],
                    'vg': ipv_dict['lvm_vg_name']}
            if (pv['vg_name'] == ipv_dict['lvm_vg_name'] and
                    pv['pv_name'] == ipv_dict['lvm_pv_name']):
                LOG.info("Removing PV %(dev)s "
                         "from LVG %(vg)s" % parm)
                cutils.execute('pvremove',
                               ipv_dict['lvm_pv_name'],
                               '--force',
                               '--force',
                               '-y',
                               run_as_root=True)
            else:
                LOG.warn("PV %(dev)s from LVG %(vg)s not found, "
                         "nothing to remove!" % parm)

        try:
            disk_utils.disk_wipe(ipv_dict['idisk_device_node'])
            # Clean up the directory used by the volume group otherwise VG
            # creation will fail without a reboot
            vgs, __ = cutils.execute('vgs', '--noheadings',
                                     '-o', 'vg_name',
                                     run_as_root=True)
            vgs = [v.strip() for v in vgs.split("\n")]
            if ipv_dict['lvm_vg_name'] not in vgs:
                cutils.execute('rm', '-rf',
                               '/dev/%s' % ipv_dict['lvm_vg_name'])
        except exception.ProcessExecutionError as e:
            LOG.warning("Continuing after wipe command returned exit code: "
                        "%(exit_code)s stdout: %(stdout)s err: %(stderr)s" %
                        {'exit_code': e.exit_code,
                         'stdout': e.stdout,
                         'stderr': e.stderr})

        LOG.info("Deleting PV: %s completed" % (ipv_dict))
