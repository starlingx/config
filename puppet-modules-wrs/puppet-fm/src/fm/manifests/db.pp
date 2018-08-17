# == Class: fm::db
#
#  Configure the fm database
#
# === Parameters
#
# [*database_db_max_retries*]
#   (optional) Maximum retries in case of connection error or deadlock error
#   before error is raised. Set to -1 to specify an infinite retry count.
#   Defaults to $::os_service_default
#
# [*database_connection*]
#   Url used to connect to database.
#   (Optional) Defaults to "sqlite:////var/lib/fm/fm.sqlite".
#
# [*database_idle_timeout*]
#   Timeout when db connections should be reaped.
#   (Optional) Defaults to $::os_service_default.
#
# [*database_min_pool_size*]
#   Minimum number of SQL connections to keep open in a pool.
#   (Optional) Defaults to $::os_service_default.
#
# [*database_max_pool_size*]
#   Maximum number of SQL connections to keep open in a pool.
#   (Optional) Defaults to $::os_service_default.
#
# [*database_max_retries*]
#   Maximum number of database connection retries during startup.
#   Setting -1 implies an infinite retry count.
#   (Optional) Defaults to $::os_service_default.
#
# [*database_retry_interval*]
#   Interval between retries of opening a database connection.
#   (Optional) Defaults to $::os_service_default.
#
# [*database_max_overflow*]
#   If set, use this value for max_overflow with sqlalchemy.
#   (Optional) Defaults to $::os_service_default.
#
class fm::db (
  $database_db_max_retries = $::os_service_default,
  $database_connection     = 'sqlite:////var/lib/fm/fm.sqlite',
  $database_idle_timeout   = $::os_service_default,
  $database_min_pool_size  = $::os_service_default,
  $database_max_pool_size  = $::os_service_default,
  $database_max_retries    = $::os_service_default,
  $database_retry_interval = $::os_service_default,
  $database_max_overflow   = $::os_service_default,
) {

  include ::fm::deps

  $database_connection_real = pick($::fm::database_connection, $database_connection)
  $database_idle_timeout_real = pick($::fm::database_idle_timeout, $database_idle_timeout)
  $database_min_pool_size_real = pick($::fm::database_min_pool_size, $database_min_pool_size)
  $database_max_pool_size_real = pick($::fm::database_max_pool_size, $database_max_pool_size)
  $database_max_retries_real = pick($::fm::database_max_retries, $database_max_retries)
  $database_retry_interval_real = pick($::fm::database_retry_interval, $database_retry_interval)
  $database_max_overflow_real = pick($::fm::database_max_overflow, $database_max_overflow)

  oslo::db { 'fm_config':
    db_max_retries => $database_db_max_retries,
    connection     => $database_connection_real,
    idle_timeout   => $database_idle_timeout_real,
    min_pool_size  => $database_min_pool_size_real,
    max_pool_size  => $database_max_pool_size_real,
    max_retries    => $database_max_retries_real,
    retry_interval => $database_retry_interval_real,
    max_overflow   => $database_max_overflow_real,
  }

  # set up the connection string for FM Manager
  $sql_connection = regsubst($database_connection_real,'^postgresql+psycopg2:','postgresql:')
  fm_config {
    'DEFAULT/sql_connection':    value => $sql_connection;
  }
}
