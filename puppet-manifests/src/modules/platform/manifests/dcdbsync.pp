class platform::dcdbsync::params (
  $api_port = 8219,
  $region_name = undef,
  $service_create = false,
  $service_enabled = false,
  $default_endpoint_type = 'internalURL',
) {
  include ::platform::params
}

class platform::dcdbsync
  inherits ::platform::dcdbsync::params {
  if ($::platform::params::distributed_cloud_role == 'systemcontroller' or
      $::platform::params::distributed_cloud_role == 'subcloud') {
    if $service_create {
      if $::platform::params::init_keystone {
        include ::dcdbsync::keystone::auth
      }

      class { '::dcdbsync': }
    }
  }
}

class platform::dcdbsync::api
  inherits ::platform::dcdbsync::params {
  if ($::platform::params::distributed_cloud_role == 'systemcontroller' or
      $::platform::params::distributed_cloud_role == 'subcloud') {
    if $service_create {
      include ::platform::network::mgmt::params

      $api_host = $::platform::network::mgmt::params::controller_address
      $api_fqdn = $::platform::params::controller_hostname
      $url_host = "http://${api_fqdn}:${api_port}"

      class { '::dcdbsync::api':
        bind_host => $api_host,
        bind_port => $api_port,
        enabled   => $service_enabled,
      }
    }
  }
}

