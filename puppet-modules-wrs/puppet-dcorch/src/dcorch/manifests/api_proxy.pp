#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# == Class: dcorch::api_proxy
#
# Setup and configure the dcorch API endpoint
#
# === Parameters
#
# [*keystone_password*]
#   The password to use for authentication (keystone)
#
# [*keystone_enabled*]
#   (optional) Use keystone for authentification
#   Defaults to true
#
# [*keystone_tenant*]
#   (optional) The tenant of the auth user
#   Defaults to services
#
# [*keystone_user*]
#   (optional) The name of the auth user
#   Defaults to dcorch
#
# [*keystone_auth_host*]
#   (optional) The keystone host
#   Defaults to localhost
#
# [*keystone_auth_port*]
#   (optional) The keystone auth port
#   Defaults to 5000
#
# [*keystone_auth_protocol*]
#   (optional) The protocol used to access the auth host
#   Defaults to http.
#
# [*keystone_auth_admin_prefix*]
#   (optional) The admin_prefix used to admin endpoint of the auth host
#   This allow admin auth URIs like http://auth_host:5000/keystone.
#   (where '/keystone' is the admin prefix)
#   Defaults to false for empty. If defined, should be a string with a
#   leading '/' and no trailing '/'.
#
# [*keystone_user_domain*]
#   (Optional) domain name for auth user.
#   Defaults to 'Default'.
#
# [*keystone_project_domain*]
#   (Optional) domain name for auth project.
#   Defaults to 'Default'.
#
# [*auth_type*]
#   (Optional) Authentication type to load.
#   Defaults to 'password'.
#
# [*service_port*]
#   (optional) The dcorch api port
#   Defaults to 5000
#
# [*package_ensure*]
#   (optional) The state of the package
#   Defaults to present
#
# [*bind_host*]
#   (optional) The dcorch api bind address
#   Defaults to 0.0.0.0
#
# [*pxeboot_host*]
#   (optional) The dcorch api pxeboot address
#   Defaults to undef
#
# [*enabled*]
#   (optional) The state of the service
#   Defaults to true
#
class dcorch::api_proxy (
  $keystone_password,
  $keystone_admin_password,
  $keystone_admin_user        = 'admin',
  $keystone_admin_tenant      = 'admin',
  $keystone_enabled           = true,
  $keystone_tenant            = 'services',
  $keystone_user              = 'dcorch',
  $keystone_auth_host         = 'localhost',
  $keystone_auth_port         = '5000',
  $keystone_auth_protocol     = 'http',
  $keystone_auth_admin_prefix = false,
  $keystone_auth_uri          = false,
  $keystone_auth_version      = false,
  $keystone_identity_uri      = false,
  $keystone_user_domain       = 'Default',
  $keystone_project_domain    = 'Default',
  $auth_type                  = 'password',
  $service_port               = '5000',
  $package_ensure             = 'latest',
  $bind_host                  = '0.0.0.0',
  $enabled                    = false
) {

  include dcorch::params

  Dcorch_config<||> ~> Service['dcorch-api-proxy']
  Dcorch_config<||> ~> Exec['dcorch-dbsync']
  Dcorch_api_paste_ini<||> ~> Service['dcorch-api-proxy']

  if $::dcorch::params::api_package {
    Package['dcorch'] -> Dcorch_config<||>
    Package['dcorch'] -> Dcorch_api_paste_ini<||>
    Package['dcorch'] -> Service['dcorch-api-proxy']
    package { 'dcorch':
      ensure  => $package_ensure,
      name    => $::dcorch::params::api_proxy_package,
    }
  }

  dcorch_config {
    "DEFAULT/bind_host": value => $bind_host;
  }


  if $keystone_identity_uri {
    dcorch_config { 'keystone_authtoken/auth_url': value => $keystone_identity_uri; }
    dcorch_config { 'cache/auth_uri': value => "${keystone_identity_uri}/v3"; }
  } else {
    dcorch_config { 'keystone_authtoken/auth_url': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/"; }
  }

  if $keystone_auth_uri {
    dcorch_config { 'keystone_authtoken/auth_uri': value => $keystone_auth_uri; }
  } else {
    dcorch_config {
      'keystone_authtoken/auth_uri': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/";
    }
  }

  if $keystone_auth_version {
    dcorch_config { 'keystone_authtoken/auth_version': value => $keystone_auth_version; }
  } else {
    dcorch_config { 'keystone_authtoken/auth_version': ensure => absent; }
  }

  if $keystone_enabled {
    dcorch_config {
      'DEFAULT/auth_strategy':     value => 'keystone' ;
    }
    dcorch_config {
      'keystone_authtoken/auth_type':    value => $auth_type;
      'keystone_authtoken/project_name': value => $keystone_tenant;
      'keystone_authtoken/username':     value => $keystone_user;
      'keystone_authtoken/password':     value => $keystone_password, secret=> true;
      'keystone_authtoken/user_domain_name':  value => $keystone_user_domain;
      'keystone_authtoken/project_domain_name':  value => $keystone_project_domain;
    }
     dcorch_config {
      'cache/admin_tenant': value => $keystone_admin_tenant;
      'cache/admin_username':     value => $keystone_admin_user;
      'cache/admin_password':     value => $keystone_admin_password, secret=> true;
    }

    if $keystone_auth_admin_prefix {
      validate_re($keystone_auth_admin_prefix, '^(/.+[^/])?$')
      dcorch_config {
        'keystone_authtoken/auth_admin_prefix': value => $keystone_auth_admin_prefix;
      }
    } else {
      dcorch_config {
        'keystone_authtoken/auth_admin_prefix': ensure => absent;
      }
    }
  }
  else
  {
    dcorch_config {
      'DEFAULT/auth_strategy':     value => 'noauth' ;
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcorch-api-proxy':
    ensure     => $ensure,
    name       => $::dcorch::params::api_proxy_service,
    enable     => $enabled,
    hasstatus  => true,
    hasrestart => true,
    tag        => 'dcorch-service',
  }
  Keystone_endpoint<||> -> Service['dcorch-api-proxy']

  exec { 'dcorch-dbsync':
    command     => $::dcorch::params::db_sync_command,
    path        => '/usr/bin',
    refreshonly => true,
    logoutput   => 'on_failure',
    require     => Package['dcorch'],
    # Only do the db sync if both controllers are running the same software
    # version. Avoids impacting mate controller during an upgrade.
    onlyif      => "test $::controller_sw_versions_match = true",
  }

}
