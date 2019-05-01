# Installs & configure the fm api service
#
# == Parameters
#
# [*enabled*]
#   (optional) Should the service be enabled.
#   Defaults to true
#
# [*manage_service*]
#   (optional) Whether the service should be managed by Puppet.
#   Defaults to true.
#
# [*host*]
#   (optional) The fm api bind address.
#   Defaults to 0.0.0.0
#
# [*port*]
#   (optional) The fm api port.
#   Defaults to 18002
#
# [*package_ensure*]
#   (optional) ensure state for package.
#   Defaults to 'present'
#
# [*service_name*]
#   (optional) Name of the service that will be providing the
#   server functionality of fm-api.
#
# [*sync_db*]
#   (optional) Run fm-dbsync on api nodes after installing the package.
#   Defaults to false
#
# [*auth_strategy*]
#   (optional) Type of authentication to be used.
#   Defaults to 'keystone'
#
# [*enable_proxy_headers_parsing*]
#   (Optional) Enable paste middleware to handle SSL requests through
#   HTTPProxyToWSGI middleware.
#   Defaults to $::os_service_default.
#
# [*paste_config*]
#   (Optional) Configuration file for WSGI definition of API
#   Defaults to $::os_service_default.
#
class fm::api (
  $manage_service                 = true,
  $enabled                        = true,
  $package_ensure                 = 'present',
  $host                           = '0.0.0.0',
  $port                           = '18002',
  $workers                        = 1,
  $service_name                   = $::fm::params::api_service,
  $sync_db                        = false,
  $auth_strategy                  = 'keystone',
  $enable_proxy_headers_parsing   = $::os_service_default,
  $paste_config                   = '/etc/fm/api-paste.ini',
) inherits fm::params {


  include ::fm::deps
  include ::fm::params

  if $auth_strategy == 'keystone' {
    include ::fm::keystone::authtoken
  }

  package { 'fm-api':
    ensure => $package_ensure,
    name   => $::fm::params::api_package,
    tag    => 'fm-package',
  }

  if $manage_service {
    if $enabled {
      $service_ensure = 'running'
    } else {
      $service_ensure = 'stopped'
    }
  }

  if $sync_db {
    include ::fm::db::sync
  }

  if $service_name == $::fm::params::api_service {
    service { 'fm-api':
      ensure     => $service_ensure,
      name       => $::fm::params::api_service,
      enable     => $enabled,
      hasstatus  => true,
      hasrestart => true,
      tag        => 'fm-service',
    }
  } else {
    fail('Invalid service_name. fm-api for running as a standalone service')
  }

  fm_config {
    'api/bind_host':                  value => $host;
    'api/bind_port':                  value => $port;
    'api/api_workers':                value => $workers;
    'api/api_paste_config':           value => $paste_config;
  }

  oslo::middleware { 'fm_config':
    enable_proxy_headers_parsing => $enable_proxy_headers_parsing,
  }
}
