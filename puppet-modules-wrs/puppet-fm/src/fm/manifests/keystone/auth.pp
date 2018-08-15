# == Class: fm::keystone::auth
#
# Configures fault management user, service and endpoint in Keystone.
#
# === Parameters
#
# [*password*]
#   (required) Password for fm user.
#
# [*auth_name*]
#   Username for fm service. Defaults to 'fm'.
#
# [*email*]
#   Email for fm user. Defaults to 'fm@localhost'.
#
# [*tenant*]
#   Tenant for fm user. Defaults to 'services'.
#
# [*configure_endpoint*]
#   Should fm endpoint be configured? Defaults to 'true'.
#
# [*configure_user*]
#   (Optional) Should the service user be configured?
#   Defaults to 'true'.
#
# [*configure_user_role*]
#   (Optional) Should the admin role be configured for the service user?
#   Defaults to 'true'.
#
# [*service_type*]
#   Type of service. Defaults to 'faultmanagement'.
#
# [*region*]
#   Region for endpoint. Defaults to 'RegionOne'.
#
# [*service_name*]
#   (optional) Name of the service.
#   Defaults to 'fm'.
#
# [*public_url*]
#   (optional) The endpoint's public url. (Defaults to 'http://127.0.0.1:18002')
#   This url should *not* contain any trailing '/'.
#
# [*admin_url*]
#   (optional) The endpoint's admin url. (Defaults to 'http://127.0.0.1:18002')
#   This url should *not* contain any trailing '/'.
#
# [*internal_url*]
#   (optional) The endpoint's internal url. (Defaults to 'http://127.0.0.1:18002')
#   This url should *not* contain any trailing '/'.
#
class fm::keystone::auth (
  $password,
  $auth_name           = 'fm',
  $email               = 'fm@localhost',
  $tenant              = 'services',
  $configure_endpoint  = true,
  $configure_user      = true,
  $configure_user_role = true,
  $service_name        = 'fm',
  $service_type        = 'faultmanagement',
  $region              = 'RegionOne',
  $public_url          = 'http://127.0.0.1:18002',
  $internal_url        = 'http://127.0.0.1:18002',
  $admin_url           = 'http://127.0.0.1:18002',
) {

  include ::fm::deps

  keystone::resource::service_identity { 'fm':
    configure_user      => $configure_user,
    configure_user_role => $configure_user_role,
    configure_endpoint  => $configure_endpoint,
    service_name        => $service_name,
    service_type        => $service_type,
    service_description => 'Fault Management Service',
    region              => $region,
    auth_name           => $auth_name,
    password            => $password,
    email               => $email,
    tenant              => $tenant,
    public_url          => $public_url,
    internal_url        => $internal_url,
    admin_url           => $admin_url,
  }

}
