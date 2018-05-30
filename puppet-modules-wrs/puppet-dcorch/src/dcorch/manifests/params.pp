#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

class dcorch::params {

  $dcorch_dir = '/etc/dcorch'
  $dcorch_conf = '/etc/dcorch/dcorch.conf'
  $dcorch_paste_api_ini = '/etc/dcorch/api-paste.ini'

  if $::osfamily == 'Debian' {
    $package_name          = 'distributedcloud-dcorch'
    $client_package        = 'distributedcloud-client-dcorchclient'
    $api_package           = 'distributedcloud-dcorch'
    $api_service           = 'dcorch-api'
    $engine_package        = 'distributedcloud-dcorch'
    $engine_service        = 'dcorch-engine'
    $snmp_package          = 'distributedcloud-dcorch'
    $snmp_service          = 'dcorch-snmp'
    $api_proxy_package      = 'distributedcloud-dcorch'
    $api_proxy_service      = 'dcorch-api-proxy'

    $db_sync_command       = 'dcorch-manage db_sync'

  } elsif($::osfamily == 'RedHat') {

    $package_name          = 'distributedcloud-dcorch'
    $client_package        = 'distributedcloud-client-dcorchclient'
    $api_package           = false
    $api_service           = 'dcorch-api'
    $engine_package        = false
    $engine_service        = 'dcorch-engine'
    $snmp_package          = false
    $snmp_service          = 'dcorch-snmp'
    $api_proxy_package      = false
    $api_proxy_service      = 'dcorch-api-proxy'
    
    $db_sync_command       = 'dcorch-manage db_sync'

  } elsif($::osfamily == 'WRLinux') {

    $package_name          = 'dcorch'
    $client_package        = 'distributedcloud-client-dcorchclient'
    $api_package           = false
    $api_service           = 'dcorch-api'
    $snmp_package          = false
    $snmp_service          = 'dcorch-snmp'
    $engine_package        = false
    $engine_service        = 'dcorch-engine'
    $api_proxy_package      = false
    $api_proxy_service      = 'dcorch-api-proxy'
    $db_sync_command       = 'dcorch-manage db_sync'

  } else {
    fail("unsuported osfamily ${::osfamily}, currently WindRiver, Debian, Redhat are the only supported platforms")
  }
}
