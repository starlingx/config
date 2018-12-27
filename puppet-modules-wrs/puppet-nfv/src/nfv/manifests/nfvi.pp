#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::nfvi (
  $enabled                       = false,
  $platform_username             = 'admin',
  $platform_tenant               = 'admin',
  $platform_user_domain          = 'Default',
  $platform_project_domain       = 'Default',
  $platform_auth_protocol        = 'http',
  $platform_auth_host            = '127.0.0.1',
  $platform_auth_port            = 5000,
  $platform_keyring_service      = undef,
  $openstack_username            = 'admin',
  $openstack_tenant              = 'admin',
  $openstack_user_domain         = 'Default',
  $openstack_project_domain      = 'Default',
  $openstack_auth_protocol       = 'http',
  $openstack_auth_host           = '127.0.0.1',
  $openstack_auth_port           = 5000,
  $openstack_keyring_service     = undef,
  $keystone_region_name          = 'RegionOne',
  $keystone_service_name         = 'keystone',
  $keystone_service_type         = 'identity',
  $keystone_endpoint_type        = 'internal',
  $ceilometer_region_name        = 'RegionOne',
  $ceilometer_service_name       = 'ceilometer',
  $ceilometer_service_type       = 'metering',
  $ceilometer_endpoint_type      = 'admin',
  $cinder_region_name            = 'RegionOne',
  $cinder_service_name           = 'cinderv2',
  $cinder_service_type           = 'volumev2',
  $cinder_endpoint_type          = 'admin',
  $cinder_endpoint_disabled      = false,
  $glance_region_name            = 'RegionOne',
  $glance_service_name           = 'glance',
  $glance_service_type           = 'image',
  $glance_endpoint_type          = 'admin',
  $neutron_region_name           = 'RegionOne',
  $neutron_service_name          = 'neutron',
  $neutron_service_type          = 'network',
  $neutron_endpoint_type         = 'admin',
  $neutron_endpoint_disabled     = false,
  $nova_region_name              = 'RegionOne',
  $nova_service_name             = 'nova',
  $nova_service_type             = 'compute',
  $nova_endpoint_type            = 'admin',
  $nova_endpoint_override        = 'http://localhost:18774',
  $nova_endpoint_disabled        = false,
  $sysinv_region_name            = 'RegionOne',
  $sysinv_service_name           = 'sysinv',
  $sysinv_service_type           = 'platform',
  $sysinv_endpoint_type          = 'admin',
  $heat_region_name              = 'RegionOne',
  $mtc_endpoint_override         = 'http://localhost:2112',
  $guest_endpoint_override       = 'http://localhost:2410',
  $patching_region_name          = 'RegionOne',
  $patching_service_name         = 'patching',
  $patching_service_type         = 'patching',
  $patching_endpoint_type        = 'admin',
  $fm_region_name                = 'RegionOne',
  $fm_service_name               = 'fm',
  $fm_service_type               = 'faultmanagement',
  $fm_endpoint_type              = 'admin',
  $rabbit_host                   = '127.0.0.1',
  $rabbit_port                   =  5672,
  $rabbit_userid                 = 'guest',
  $rabbit_password               = 'guest',
  $rabbit_virtual_host           = '/',
  $infrastructure_rest_api_host  = '127.0.0.1',
  $infrastructure_rest_api_port  = 30001,
  $infrastructure_rest_api_data_port_fault_handling_enabled = true,
  $guest_rest_api_host           = '127.0.0.1',
  $guest_rest_api_port           = 30002,
  $compute_rest_api_host         = '127.0.0.1',
  $compute_rest_api_port         = 30003,
  $compute_rest_api_max_concurrent_requests  = 128,
  $compute_rest_api_max_request_wait_in_secs = 120,
  $host_listener_host            = '127.0.0.1',
  $host_listener_port            = 30004,
  $identity_uri                  = undef,
) {

  include nfv::params

  nfv_plugin_nfvi_config {

    # Platform Authentication Information
    'platform/username': value => $platform_username;
    'platform/tenant': value => $platform_tenant;
    'platform/user_domain_name': value => $platform_user_domain;
    'platform/project_domain_name': value => $platform_project_domain;
    'platform/authorization_protocol': value => $platform_auth_protocol;
    'platform/authorization_ip': value => $platform_auth_host;
    'platform/authorization_port': value => $platform_auth_port;
    'platform/keyring_service': value => $platform_keyring_service;

    # OpenStack Authentication Information
    'openstack/username': value => $openstack_username;
    'openstack/tenant': value => $openstack_tenant;
    'openstack/user_domain_name': value => $openstack_user_domain;
    'openstack/project_domain_name': value => $openstack_project_domain;
    'openstack/authorization_protocol': value => $openstack_auth_protocol;
    'openstack/authorization_ip': value => $openstack_auth_host;
    'openstack/authorization_port': value => $openstack_auth_port;
    'openstack/keyring_service': value => $openstack_keyring_service;

    'keystone/region_name': value => $keystone_region_name;
    'keystone/service_name': value => $keystone_service_name;
    'keystone/service_type': value => $keystone_service_type;
    'keystone/endpoint_type': value => $keystone_endpoint_type;

    'ceilometer/region_name': value => $ceilometer_region_name;
    'ceilometer/service_name': value => $ceilometer_service_name;
    'ceilometer/service_type': value => $ceilometer_service_type;
    'ceilometer/endpoint_type': value => $ceilometer_endpoint_type;

    'cinder/region_name': value => $cinder_region_name;
    'cinder/service_name': value => $cinder_service_name;
    'cinder/service_type': value => $cinder_service_type;
    'cinder/endpoint_type': value => $cinder_endpoint_type;
    'cinder/endpoint_disabled': value => $cinder_endpoint_disabled;

    'glance/region_name': value => $glance_region_name;
    'glance/service_name': value => $glance_service_name;
    'glance/service_type': value => $glance_service_type;
    'glance/endpoint_type': value => $glance_endpoint_type;

    'neutron/region_name': value => $neutron_region_name;
    'neutron/service_name': value => $neutron_service_name;
    'neutron/service_type': value => $neutron_service_type;
    'neutron/endpoint_type': value => $neutron_endpoint_type;
    'neutron/endpoint_disabled': value => $neutron_endpoint_disabled;

    'nova/region_name': value => $nova_region_name;
    'nova/service_name': value => $nova_service_name;
    'nova/service_type': value => $nova_service_type;
    'nova/endpoint_type': value => $nova_endpoint_type;
    'nova/endpoint_override': value => $nova_endpoint_override;
    'nova/endpoint_disabled': value => $nova_endpoint_disabled;

    'sysinv/region_name': value => $sysinv_region_name;
    'sysinv/service_name': value => $sysinv_service_name;
    'sysinv/service_type': value => $sysinv_service_type;
    'sysinv/endpoint_type': value => $sysinv_endpoint_type;

    'heat/region_name': value => $heat_region_name;

    'mtc/endpoint_override': value => $mtc_endpoint_override;

    'guest/endpoint_override': value => $guest_endpoint_override;

    'patching/region_name': value => $patching_region_name;
    'patching/service_name': value => $patching_service_name;
    'patching/service_type': value => $patching_service_type;
    'patching/endpoint_type': value => $patching_endpoint_type;

    'fm/region_name': value => $fm_region_name;
    'fm/service_name': value => $fm_service_name;
    'fm/service_type': value => $fm_service_type;
    'fm/endpoint_type': value => $fm_endpoint_type;

    # AMQP
    'amqp/host': value => $rabbit_host;
    'amqp/port': value => $rabbit_port;
    'amqp/user_id': value => $rabbit_userid;
    'amqp/password': value => $rabbit_password, secret => true;
    'amqp/virt_host': value => $rabbit_virtual_host;

    # Infrastructure Rest-API
    'infrastructure-rest-api/host': value => $infrastructure_rest_api_host;
    'infrastructure-rest-api/port': value => $infrastructure_rest_api_port;
    'infrastructure-rest-api/data_port_fault_handling_enabled': value => $infrastructure_rest_api_data_port_fault_handling_enabled;

    # Guest-Services Rest-API
    'guest-rest-api/host': value => $guest_rest_api_host;
    'guest-rest-api/port': value => $guest_rest_api_port;

    # Compute Rest-API
    'compute-rest-api/host': value => $compute_rest_api_host;
    'compute-rest-api/port': value => $compute_rest_api_port;
    'compute-rest-api/max_concurrent_requests': value => $compute_rest_api_max_concurrent_requests;
    'compute-rest-api/max_request_wait_in_secs': value => $compute_rest_api_max_request_wait_in_secs;

    # Host Listener
    'host-listener/host': value => $host_listener_host;
    'host-listener/port': value => $host_listener_port;
  }

  if $identity_uri {
    nfv_plugin_nfvi_config { 'openstack/authorization_uri': value => $identity_uri; }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }
}
