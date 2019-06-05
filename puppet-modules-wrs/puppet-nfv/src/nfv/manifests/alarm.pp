#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::alarm (
  $enabled             = false,
  $storage_file        = '/var/log/nfv-vim-alarms.log',
  $openstack_username            = 'admin',
  $openstack_tenant              = 'admin',
  $openstack_user_domain         = 'Default',
  $openstack_project_domain      = 'Default',
  $openstack_auth_protocol       = 'http',
  $openstack_auth_host           = '127.0.0.1',
  $openstack_auth_port           = 5000,
  $openstack_keyring_service     = undef,
  $fault_mgmt_region_name        = 'RegionOne',
  $fault_mgmt_service_name       = 'fm',
  $fault_mgmt_service_type       = 'faultmanagement',
  $fault_mgmt_endpoint_type      = 'admin',
  $fault_mgmt_endpoint_disabled  = false,
  $fault_management_pod_disabled      = true,
) {

  include nfv::params

  nfv_plugin_alarm_config {
    # File-Storage Information
    'File-Storage/file': value => $storage_file;
    # This flag is used to disable raising alarm to containerized fm
    # and will be removed in future.
    'openstack/fault_management_pod_disabled': value => $fault_management_pod_disabled;

    # OpenStack Authentication Information
    'openstack/username': value => $openstack_username;
    'openstack/tenant': value => $openstack_tenant;
    'openstack/user_domain_name': value => $openstack_user_domain;
    'openstack/project_domain_name': value => $openstack_project_domain;
    'openstack/authorization_protocol': value => $openstack_auth_protocol;
    'openstack/authorization_ip': value => $openstack_auth_host;
    'openstack/authorization_port': value => $openstack_auth_port;
    'openstack/keyring_service': value => $openstack_keyring_service;

    # Fault Management Information
    'fm/region_name': value => $fault_mgmt_region_name;
    'fm/service_name': value => $fault_mgmt_service_name;
    'fm/service_type': value => $fault_mgmt_service_type;
    'fm/endpoint_type': value => $fault_mgmt_endpoint_type;
    'fm/endpoint_disabled': value => $fault_mgmt_endpoint_disabled;
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }
}
