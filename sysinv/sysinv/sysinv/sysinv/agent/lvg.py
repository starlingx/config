#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory ipy Utilities and helper functions."""

from eventlet.green import subprocess
import sys

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import utils

LOG = logging.getLogger(__name__)


class LVGOperator(object):
    '''Class to encapsulate Physical Volume operations for System Inventory'''

    def __init__(self):
        pass

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename,
                                  traceback.tb_lineno))

    def count_lvs_in_thinpool(self, vg, thin_pool):
        """Return number lvs in thinpools in the specified vg. """
        try:
            selection = f"pool_lv={thin_pool} && vg_name={vg}"
            command = ['lvs', '--noheadings', '-o', 'lv_name',
                       '--select', selection]
            output = subprocess.check_output(command, universal_newlines=True)  # pylint: disable=not-callable
        except Exception as e:
            self.handle_exception("Could not retrieve LV information: %s" % e)
            output = ""

        thinpools = len(output.strip().splitlines())

        return thinpools

    def thinpools_in_vg(self, vg, cinder_device=None):
        """Return number of thinpools in the specified vg. """
        try:
            command = ['vgs', '--noheadings', '-o', 'lv_name', vg]
            if cinder_device:
                if vg == constants.LVG_CINDER_VOLUMES:
                    global_filer = 'devices/global_filter=["a|' + \
                                   cinder_device + '|","r|.*|"]'
                    command = command + ['--config', global_filer]
            output = subprocess.check_output(command, universal_newlines=True)  # pylint: disable=not-callable
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

    def ilvg_rook_get(self):
        # rook-ceph are hidden by global_filter, list them separately.
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

        disable_filter = ' --config \'devices/global_filter=["a|.*|"]\''
        vgdisplay_command = vgdisplay_command + disable_filter
        vgdisplay_stdout, vgdisplay_stderr = utils.subprocess_open(command=vgdisplay_command,
                                                                   timeout=5)
        vgdisplay_output = vgdisplay_stdout

        # parse the output 1 vg/row
        rook_vgs = []
        for row in vgdisplay_output.split('\n'):
            if row.strip().startswith("ceph"):

                # get the values of fields as strings
                values = row.split()

                # create the dict of attributes
                attr = dict(zip(string_keys, values))

                # convert required values from strings to ints
                for k in int_keys:
                    if k in attr.keys():
                        attr[k] = int(attr[k])

                rook_vgs.append(attr)

        return rook_vgs

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

        vgdisplay_stdout, vgdisplay_stderr = utils.subprocess_open(command=vgdisplay_command,
                                                                   timeout=5)
        vgdisplay_output = vgdisplay_stdout

        if cinder_device:
            new_global_filer = ' --config \'devices/global_filter=["a|' + \
                               cinder_device + '|","r|.*|"]\''
            vgdisplay_command = vgdisplay_command + new_global_filer
            vgdisplay_stdout, vgdisplay_stderr = utils.subprocess_open(command=vgdisplay_command,
                                                                       timeout=5)

            vgdisplay_output = vgdisplay_output + vgdisplay_stdout

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

            # Search for lvm-csi thin LVs in CGTS-VG
            vg_name = attr.get('lvm_vg_name', None)
            if vg_name and vg_name == constants.LVG_CGTS_VG:
                thin_cur_lv = self.count_lvs_in_thinpool(
                    constants.LVG_CGTS_VG,
                    constants.LVM_CSI_POOL_NAME)
                attr['capabilities'] = {'thin_cur_lv': thin_cur_lv}

            # Make sure we have attributes
            if attr:
                ilvg.append(attr)

        rook_vgs = self.ilvg_rook_get()
        for vg in rook_vgs:
            if vg and vg not in ilvg:
                ilvg.append(vg)

        LOG.debug("ilvg= %s" % ilvg)

        return ilvg
