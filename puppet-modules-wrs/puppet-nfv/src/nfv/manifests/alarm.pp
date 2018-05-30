#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::alarm (
  $enabled             = false,
  $storage_file        = '/var/log/nfv-vim-alarms.log',
) {

  include nfv::params

  nfv_plugin_alarm_config {
    /* File-Storage Information */
    'File-Storage/file': value => $storage_file;
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }
}
