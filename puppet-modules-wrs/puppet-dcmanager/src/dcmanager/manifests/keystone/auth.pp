#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  DEC 2017: creation
#

# == Class: dcmanager::keystone::auth
#
# Configures dcmanager user, service and endpoint in Keystone.
#
class dcmanager::keystone::auth (
  $password,
  $auth_name            = 'dcmanager',
  $auth_domain,
  $email                = 'dcmanager@localhost',
  $tenant               = 'admin',
  $region               = 'SystemController',
  $service_description  = 'DCManagerService',
  $service_name         = undef,
  $service_type         = 'dcmanager',
  $configure_endpoint   = true,
  $configure_user       = true,
  $configure_user_role  = true,
  $public_url           = 'http://127.0.0.1:8119/v1',
  $admin_url            = 'http://127.0.0.1:8119/v1',
  $internal_url         = 'http://127.0.0.1:8119/v1',
  $admin_project_name,
  $admin_project_domain,
) {

  $real_service_name = pick($service_name, $auth_name)

  keystone::resource::service_identity { 'dcmanager':
    configure_user      => $configure_user,
    configure_user_role => $configure_user_role,
    configure_endpoint  => $configure_endpoint,
    service_type        => $service_type,
    service_description => $service_description,
    service_name        => $real_service_name,
    region              => $region,
    auth_name           => $auth_name,
    password            => $password,
    email               => $email,
    tenant              => $tenant,
    public_url          => $public_url,
    admin_url           => $admin_url,
    internal_url        => $internal_url,
  }

  -> keystone_user_role { "${auth_name}@${admin_project_name}":
    ensure         => present,
    user_domain    => $auth_domain,
    project_domain => $admin_project_domain,
    roles          => ['admin'],
  }

}
