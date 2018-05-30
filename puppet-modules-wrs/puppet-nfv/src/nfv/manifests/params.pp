#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::params {

  $nfv_conf_dir = '/etc/nfv'
  $nfv_plugin_conf_dir = '/etc/nfv/nfv_plugins'
  $nfv_vim_conf = '/etc/nfv/vim/config.ini'
  $nfv_plugin_alarm_conf = '/etc/nfv/nfv_plugins/alarm_handlers/config.ini'
  $nfv_plugin_event_log_conf = '/etc/nfv/nfv_plugins/event_log_handlers/config.ini'
  $nfv_plugin_nfvi_conf = '/etc/nfv/nfv_plugins/nfvi_plugins/config.ini'

  if $::osfamily == 'Debian' {
    $package_name            = 'nfv-vim'
    $nfv_plugin_package_name = 'nfv-plugins'
    $nfv_common_package_name = 'nfv-common'

  } elsif($::osfamily == 'RedHat') {

    $package_name            = 'nfv-vim'
    $nfv_plugin_package_name = 'nfv-plugins'
    $nfv_common_package_name = 'nfv-common'

  } elsif($::osfamily == 'WRLinux') {

    $package_name            = 'nfv-vim'
    $nfv_plugin_package_name = 'nfv-plugins'
    $nfv_common_package_name = 'nfv-common'

  } else {
    fail("unsuported osfamily ${::osfamily}, currently WindRiver, Debian, Redhat are the only supported platforms")
  }
}
