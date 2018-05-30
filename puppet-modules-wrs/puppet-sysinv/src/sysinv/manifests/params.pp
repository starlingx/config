#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Aug 2016: rebase mitaka
#  Jun 2016: rebase centos
#  Jun 2015: uprev kilo
#  Dec 2014: uprev juno
#  Jul 2014: rename ironic
#  Dec 2013: uprev grizzly, havana
#  Nov 2013: integrate source from https://github.com/stackforge/puppet-sysinv
#

class sysinv::params {

  $sysinv_dir = '/etc/sysinv'
  $sysinv_conf = '/etc/sysinv/sysinv.conf'
  $sysinv_paste_api_ini = '/etc/sysinv/api-paste.ini'

  if $::osfamily == 'Debian' {
    $package_name       = 'sysinv'
    $client_package     = 'cgtsclient'
    $api_package        = 'sysinv'
    $api_service        = 'sysinv-api'
    $conductor_package  = 'sysinv'
    $conductor_service  = 'sysinv-conductor'
    $agent_package      = 'sysinv'
    $agent_service      = 'sysinv-agent'
    $db_sync_command    = 'sysinv-dbsync'

  } elsif($::osfamily == 'RedHat') {

    $package_name       = 'sysinv'
    $client_package     = 'cgtscli'
    $api_package        = false
    $api_service        = 'sysinv-api'
    $conductor_package  = false
    $conductor_service  = 'sysinv-conductor'
    $agent_package      = false
    $agent_service      = 'sysinv-agent'
    $db_sync_command    = 'sysinv-dbsync'

  } elsif($::osfamily == 'WRLinux') {

    $package_name       = 'sysinv'
    $client_package     = 'cgtscli'
    $api_package        = false
    $api_service        = 'sysinv-api'
    $conductor_package  = false
    $conductor_service  = 'sysinv-conductor'
    $agent_package      = false
    $agent_service      = 'sysinv-agent'
    $db_sync_command    = 'sysinv-dbsync'

  } else {
    fail("unsuported osfamily ${::osfamily}, currently WindRiver, Debian, Redhat are the only supported platforms")
  }
}
