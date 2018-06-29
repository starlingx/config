#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# == Class: smapi::keystone::auth
#
# Configures smapi user, service and endpoint in Keystone.
#

class smapi::keystone::auth (
  $configure_endpoint   = true,
  $configure_user       = true,
  $configure_user_role  = true,
  $password             = 'passwd',
  $auth_name            = 'smapi',
  $public_url           = 'http://127.0.0.1:7777',
  $admin_url            = 'http://127.0.0.1:7777',
  $internal_url         = 'http://127.0.0.1:7777',
  $tenant               = 'services',
  $region               = 'RegionOne',
  $service_description  = 'sm-api service',
  $service_name         = 'smapi',
  $service_type         = 'smapi',
) {

  $real_service_name = pick($service_name, $auth_name)

  keystone::resource::service_identity { $auth_name:
    configure_endpoint  => $configure_endpoint,
    configure_user      => $configure_user,
    configure_user_role => $configure_user_role,
    password            => $password,
    auth_name           => $auth_name,
    public_url          => $public_url,
    admin_url           => $admin_url,
    internal_url        => $internal_url,
    tenant              => $tenant,
    region              => $region,
    service_description => $service_description,
    service_name        => $real_service_name,
    service_type        => $service_type,
  }
}
