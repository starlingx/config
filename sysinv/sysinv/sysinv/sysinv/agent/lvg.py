#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory ipy Utilities and helper functions."""

import subprocess
import sys

from sysinv.common import constants
from sysinv.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class LVGOperator(object):
    '''Class to encapsulate Physical Volume operations for System Inventory'''

    def __init__(self):
        pass

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename,
                                  traceback.tb_lineno))

    def thinpools_in_vg(self, vg, cinder_device=None):
        """Return number of thinpools in the specified vg. """
        try:
            command = ['vgs', '--noheadings', '-o', 'lv_name', vg]
            if cinder_device:
                if vg == constants.LVG_CINDER_VOLUMES:
                    global_filer = 'devices/global_filter=["a|' + \
                                   cinder_device + '|","r|.*|"]'
                    command = command + ['--config', global_filer]
            output = subprocess.check_output(command)
        except Exception as e:
            self.handle_exception("Could not retrieve vgdisplay "
                                  "information: %s" % e)
            output = ""
        thinpools = 0
        for line in output.splitlines():
            # This makes some assumptions, the suffix is defined in nova.
            if constants.LVM_POOL_SUFFIX in line:
                thinpools += 1

        return thinpools

    def ilvg_get(self, cinder_device=None):
        '''Enumerate physical volume topology based on:

        :param self
        :param cinder_device: by-path of cinder device
        :returns list of disk and attributes
        '''
        ilvg = []

        # keys: matching the field order of pvdisplay command
        string_keys = ['lvm_vg_name', 'lvm_vg_uuid', 'lvm_vg_access',
                       'lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv',
                       'lvm_cur_pv', 'lvm_vg_size', 'lvm_vg_total_pe',
                       'lvm_vg_free_pe']

        # keys that need to be translated into ints
        int_keys = ['lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv',
                    'lvm_cur_pv', 'lvm_vg_size', 'lvm_vg_total_pe',
                    'lvm_vg_free_pe']

        # pvdisplay command to retrieve the pv data of all pvs present
        vgdisplay_command = 'vgdisplay -C --aligned -o vg_name,vg_uuid,vg_attr'\
                            ',max_lv,lv_count,max_pv,pv_count,vg_size,'\
                            'vg_extent_count,vg_free_count'\
                            ' --units B --nosuffix --noheadings'

        # Execute the command
        try:
            vgdisplay_process = subprocess.Popen(vgdisplay_command,
                                                 stdout=subprocess.PIPE,
                                                 shell=True)
            vgdisplay_output = vgdisplay_process.stdout.read()
        except Exception as e:
            self.handle_exception("Could not retrieve vgdisplay "
                                  "information: %s" % e)
            vgdisplay_output = ""

        # Cinder devices are hidden by global_filter, list them separately.
        if cinder_device:
            new_global_filer = ' --config \'devices/global_filter=["a|' + \
                               cinder_device + '|","r|.*|"]\''
            vgdisplay_command = vgdisplay_command + new_global_filer

            try:
                vgdisplay_process = subprocess.Popen(vgdisplay_command,
                                                     stdout=subprocess.PIPE,
                                                     shell=True)
                vgdisplay_output = vgdisplay_output + vgdisplay_process.stdout.read()
            except Exception as e:
                self.handle_exception("Could not retrieve vgdisplay "
                                      "information: %s" % e)

        # parse the output 1 vg/row
        for row in vgdisplay_output.split('\n'):
            # get the values of fields as strings
            values = row.split()

            # create the dict of attributes
            attr = dict(zip(string_keys, values))

            # convert required values from strings to ints
            for k in int_keys:
                if k in attr.keys():
                    attr[k] = int(attr[k])

            # subtract any thinpools from the lv count
            if 'lvm_cur_lv' in attr:
                attr['lvm_cur_lv'] -= self.thinpools_in_vg(attr['lvm_vg_name'],
                                                           cinder_device)

            # Make sure we have attributes
            if attr:
                ilvg.append(attr)

        LOG.debug("ilvg= %s" % ilvg)

        return ilvg
