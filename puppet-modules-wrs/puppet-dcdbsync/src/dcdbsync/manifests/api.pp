#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# == Class: dcdbsync::api
#
# Setup and configure the dcdbsync API endpoint
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
#   Defaults to dcdbsync
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
# [*bind_port*]
#   (optional) The dcorch dbsync api port
#   Defaults to 8219
#
# [*package_ensure*]
#   (optional) The state of the package
#   Defaults to present
#
# [*bind_host*]
#   (optional) The dcorch dbsync api bind address
#   Defaults to 0.0.0.0
#
# [*enabled*]
#   (optional) The state of the service
#   Defaults to true
#
class dcdbsync::api (
  $keystone_password,
  $keystone_enabled           = true,
  $keystone_tenant            = 'services',
  $keystone_user              = 'dcdbsync',
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
  $package_ensure             = 'latest',
  $bind_host                  = '0.0.0.0',
  $bind_port                  = 8219,
  $enabled                    = false
) {

  include dcdbsync::params

  Dcdbsync_config<||> ~> Service['dcdbsync-api']

  if $::dcdbsync::params::api_package {
    Package['dcdbsync-api'] -> Dcdbsync_config<||>
    Package['dcdbsync-api'] -> Service['dcdbsync-api']
    package { 'dcdbsync-api':
      ensure => $package_ensure,
      name   => $::dcdbsync::params::api_package,
    }
  }

  dcdbsync_config {
    'DEFAULT/bind_host': value => $bind_host;
    'DEFAULT/bind_port': value => $bind_port;
  }

  if $keystone_identity_uri {
    dcdbsync_config { 'keystone_authtoken/auth_url': value => $keystone_identity_uri; }
    dcdbsync_config { 'cache/auth_uri': value => "${keystone_identity_uri}/v3"; }
  } else {
    dcdbsync_config { 'keystone_authtoken/auth_url': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/v3"; }
  }

  if $keystone_auth_uri {
    dcdbsync_config { 'keystone_authtoken/auth_uri': value => $keystone_auth_uri; }
  } else {
    dcdbsync_config {
      'keystone_authtoken/auth_uri': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/v3";
    }
  }

  if $keystone_auth_version {
    dcdbsync_config { 'keystone_authtoken/auth_version': value => $keystone_auth_version; }
  } else {
    dcdbsync_config { 'keystone_authtoken/auth_version': ensure => absent; }
  }

  if $keystone_enabled {
    dcdbsync_config {
      'DEFAULT/auth_strategy':     value => 'keystone' ;
    }
    dcdbsync_config {
      'keystone_authtoken/auth_type':    value => $auth_type;
      'keystone_authtoken/project_name': value => $keystone_tenant;
      'keystone_authtoken/username':     value => $keystone_user;
      'keystone_authtoken/password':     value => $keystone_password, secret=> true;
      'keystone_authtoken/user_domain_name':  value => $keystone_user_domain;
      'keystone_authtoken/project_domain_name':  value => $keystone_project_domain;
    }

    if $keystone_auth_admin_prefix {
      validate_re($keystone_auth_admin_prefix, '^(/.+[^/])?$')
      dcdbsync_config {
        'keystone_authtoken/auth_admin_prefix': value => $keystone_auth_admin_prefix;
      }
    } else {
      dcdbsync_config {
        'keystone_authtoken/auth_admin_prefix': ensure => absent;
      }
    }
  }
  else
  {
    dcdbsync_config {
      'DEFAULT/auth_strategy':     value => 'noauth' ;
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcdbsync-api':
    ensure     => $ensure,
    name       => $::dcdbsync::params::api_service,
    enable     => $enabled,
    hasstatus  => true,
    hasrestart => true,
    tag        => 'dcdbsync-api',
  }
  Keystone_endpoint<||> -> Service['dcdbsync-api']
}
