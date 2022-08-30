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
import sys

from oslo_log import log as logging

from sysinv.common import constants

LOG = logging.getLogger(__name__)


class PVOperator(object):
    '''Class to encapsulate Physical Volume operations for System Inventory'''

    def __init__(self):
        pass

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename,
                                  traceback.tb_lineno))

    def ipv_get(self, cinder_device=None, get_rook_device=False):
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

        if get_rook_device:
            disable_filter = ' --config \'devices/global_filter=["a|.*|"]\''
            pvdisplay_command = pvdisplay_command + disable_filter

        # Execute the command
        try:
            pvdisplay_process = subprocess.Popen(pvdisplay_command,
                                             stdout=subprocess.PIPE,
                                             shell=True,
                                             universal_newlines=True)
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
                                                     shell=True,
                                                     universal_newlines=True)
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

            if (get_rook_device and ("ceph-" not in row)):
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

        if not get_rook_device:
            rook_pv = self.ipv_get(get_rook_device=True)

            for i in rook_pv:
                if i not in ipv:
                    ipv.append(i)

        LOG.debug("ipv= %s" % ipv)

        return ipv
