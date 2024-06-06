#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" Inventory logical volume utilities and helper functions."""

from eventlet.green import subprocess

from oslo_log import log as logging
from sysinv.common import constants

LOG = logging.getLogger(__name__)


class LVOperator(object):
    """Class to encapsulate logical volume operations for System Inventory."""

    def __init__(self):

        self.supported_hostfs_lvs = [constants.FILESYSTEM_LV_DICT[fs] for fs in
                                        constants.HOSTFS_SUPPORTED_LIST]

    def ilv_get_supported_hostfs(self):
        """
        Retrieve and return a list of all supported host filesystem LVs present in
        the system.
        Each LV is represented as a dictionary containing 'name', 'size' and 'lv_name'.
        """

        ilv = []

        string_keys = ['name', 'size', 'logical_volume']

        int_keys = ['size']

        # Command to retrieve LV data with their full names and sizes
        lvdisplay_command = 'lvdisplay -C --separator=";" -o lv_full_name,lv_size'\
            ' --units B --nosuffix --noheadings'

        try:
            # Execute the lvdisplay command
            lvdisplay_process = subprocess.Popen(lvdisplay_command,
                                                 stdout=subprocess.PIPE,
                                                 shell=True,
                                                 universal_newlines=True)
            lvdisplay_output = lvdisplay_process.stdout.read()
        except Exception as e:
            LOG.error("Could not retrieve lvdisplay information: %s" % e)
            return ilv

        rows = [row for row in lvdisplay_output.split('\n') if row.strip()]

        for row in rows:
            values = row.split(';')
            values = [v.strip() for v in values]
            names = values[0].split('/')
            if names[0] != constants.LVG_CGTS_VG:
                continue
            if not names[1] in self.supported_hostfs_lvs:
                continue
            values.append(names[1])

            # Get the filesystem name
            matching_lv = next((key for key, value in constants.FILESYSTEM_LV_DICT.items()
                                                             if value == values[2]), None)
            if not matching_lv:
                continue
            values[0] = matching_lv
            attr = dict(zip(string_keys, values))
            for k in int_keys:
                if k in attr.keys():
                    attr[k] = int(attr[k])
            if attr and attr['name']:
                ilv.append(attr)

        return ilv
