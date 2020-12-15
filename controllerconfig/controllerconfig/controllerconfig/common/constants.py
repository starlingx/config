#
# Copyright (c) 2016-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from tsconfig import tsconfig


CONFIG_WORKDIR = '/tmp/config'
CGCS_CONFIG_FILE = CONFIG_WORKDIR + '/cgcs_config'
CONFIG_PERMDIR = tsconfig.CONFIG_PATH

HIERADATA_WORKDIR = '/tmp/hieradata'
HIERADATA_PERMDIR = tsconfig.PUPPET_PATH + 'hieradata'

KEYRING_WORKDIR = '/tmp/python_keyring'
KEYRING_PERMDIR = tsconfig.KEYRING_PATH

INITIAL_CONFIG_COMPLETE_FILE = '/etc/platform/.initial_config_complete'
LOG_LOCAL1 = 'local1'
