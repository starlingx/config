# == Class: fm
#
# Full description of class fm here.
#
# === Parameters
#
# [*package_ensure*]
#   (optional) The state of fm packages
#   Defaults to 'present'
#
# [*log_dir*]
#   (optional) Directory where logs should be stored.
#   If set to boolean false or the $::os_service_default, it will not log to
#   any directory.
#   Defaults to undef.
#
# [*debug*]
#   (optional) Set log output to debug output.
#   Defaults to undef
#
# [*use_syslog*]
#   (optional) Use syslog for logging
#   Defaults to undef
#
# [*use_stderr*]
#   (optional) Use stderr for logging
#   Defaults to undef
#
# [*log_facility*]
#   (optional) Syslog facility to receive log lines.
#   Defaults to undef
#
# [*database_connection*]
#   (optional) Connection url for the fm database.
#   Defaults to undef.
#
# [*database_max_retries*]
#   (optional) Maximum database connection retries during startup.
#   Defaults to undef.
#
# [*database_idle_timeout*]
#   (optional) Timeout before idle database connections are reaped.
#   Defaults to undef.
#
# [*database_retry_interval*]
#   (optional) Interval between retries of opening a database connection.
#   Defaults to undef.
#
# [*database_min_pool_size*]
#   (optional) Minimum number of SQL connections to keep open in a pool.
#   Defaults to undef.
#
# [*database_max_pool_size*]
#   (optional) Maximum number of SQL connections to keep open in a pool.
#   Defaults to undef.
#
# [*database_max_overflow*]
#   (optional) If set, use this value for max_overflow with sqlalchemy.
#   Defaults to: undef.
#
class fm (
  $package_ensure                     = 'present',
  $debug                              = undef,
  $use_syslog                         = undef,
  $use_stderr                         = undef,
  $log_facility                       = undef,
  $log_dir                            = undef,
  $database_connection                = undef,
  $database_idle_timeout              = undef,
  $database_min_pool_size             = undef,
  $database_max_pool_size             = undef,
  $database_max_retries               = undef,
  $database_retry_interval            = undef,
  $database_max_overflow              = undef,
  $event_log_max_size                 = 4000,
  $system_name                        = undef,
  $region_name                        = undef,
  $trap_destinations                  = undef,
  $sysinv_catalog_info                = undef,
) inherits fm::params {

  include ::fm::deps
  include ::fm::logging

  # set up the connection string for FM Manager, remove psycopg2 if it exists
  $sql_connection = regsubst($database_connection,'^postgresql+psycopg2:','postgresql:')
  fm_config {
    'DEFAULT/sql_connection':       value => $sql_connection, secret => true;
    'DEFAULT/event_log_max_size':   value => $event_log_max_size;
    'DEFAULT/system_name':          value => $system_name;
    'DEFAULT/region_name':          value => $region_name;
    'DEFAULT/trap_destinations':    value => $trap_destinations;
  }

  # Automatically add psycopg2 driver to postgresql (only does this if it is missing)
  $real_connection = regsubst($database_connection,'^postgresql:','postgresql+psycopg2:')
  fm_config {
    'database/connection':    value => $real_connection, secret => true;
    'database/idle_timeout':  value => $database_idle_timeout;
    'database/max_pool_size': value => $database_max_pool_size;
    'database/max_overflow':  value => $database_max_overflow;
  }

  fm_config {
    'sysinv/catalog_info':    value => $sysinv_catalog_info;
    'sysinv/os_region_name':  value => $region_name;
  }

  fm_api_paste_ini {
    'pipeline:fm-api/pipeline': value => 'request_id authtoken api_v1';
    'filter:request_id/paste.filter_factory': value => 'oslo_middleware:RequestId.factory';
    'filter:authtoken/acl_public_routes': value => '/, /v1';
    'filter:authtoken/paste.filter_factory': value => 'fm.api.middleware.auth_token:AuthTokenMiddleware.factory';
    'app:api_v1/paste.app_factory': value => 'fm.api.app:app_factory';
  }
}
