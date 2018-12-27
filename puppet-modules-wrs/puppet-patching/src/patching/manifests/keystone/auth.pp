#
# Copyright (c) 2014-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class patching::keystone::auth (
  $password,
  $auth_name            = 'patching',
  $tenant               = 'services',
  $email                = 'patching@localhost',
  $region               = 'RegionOne',
  $service_description  = 'Patching Service',
  $service_name         = undef,
  $service_type         = 'patching',
  $configure_endpoint   = true,
  $configure_user       = true,
  $configure_user_role  = true,
  $public_url           = 'http://127.0.0.1:15491/v1',
  $admin_url            = 'http://127.0.0.1:5491/v1',
  $internal_url         = 'http://127.0.0.1:5491/v1',
) {
  $real_service_name = pick($service_name, $auth_name)

  keystone::resource::service_identity { 'patching':
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

  # Assume we dont need backwards compatability
  # if $configure_endpoint {
  #   Keystone_endpoint["${region}/${real_service_name}::${service_type}"]  ~> Service <| title == 'patch-server' |>
  # }

}
