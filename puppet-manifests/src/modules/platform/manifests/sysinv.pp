class platform::sysinv::params (
  $api_port = 6385,
  $region_name = undef,
  $service_create = false,
) { }

class platform::sysinv
  inherits ::platform::sysinv::params {

  Anchor['platform::services'] -> Class[$name]

  include ::platform::params
  include ::platform::amqp::params

  # sysinv-agent is started on all hosts
  include ::sysinv::agent

  group { 'sysinv':
    ensure => 'present',
    gid    => '168',
  } ->

  user { 'sysinv':
    ensure           => 'present',
    comment          => 'sysinv Daemons',
    gid              => '168',
    groups           => ['nobody', 'sysinv', 'wrs_protected'],
    home             => '/var/lib/sysinv',
    password         => '!!',
    password_max_age => '-1',
    password_min_age => '-1',
    shell            => '/sbin/nologin',
    uid              => '168',
  } ->

  file { "/etc/sysinv":
    ensure  => "directory",
    owner   => 'sysinv',
    group   => 'sysinv',
    mode    => '0750',
  } ->

  class { '::sysinv':
    rabbit_host => $::platform::amqp::params::host_url,
    rabbit_port => $::platform::amqp::params::port,
    rabbit_userid => $::platform::amqp::params::auth_user,
    rabbit_password => $::platform::amqp::params::auth_password,
  }

  # Note: The log format strings are prefixed with "sysinv" because it is
  # interpreted as the program by syslog-ng, which allows the sysinv logs to be
  # filtered and directed to their own file.

  # TODO(mpeters): update puppet-sysinv to permit configuration of log formats
  # once the log configuration has been moved to oslo::log
  sysinv_config {
    "DEFAULT/logging_context_format_string": value =>
      'sysinv %(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [%(request_id)s %(user)s %(tenant)s] %(instance)s%(message)s';
    "DEFAULT/logging_default_format_string": value =>
      'sysinv %(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [-] %(instance)s%(message)s';
  }

  $sysinv_db_connection = $::sysinv::database_connection
  file { "/etc/fm.conf":
    ensure => 'present',
    content => template('platform/fm.conf.erb'),
  }

  if str2bool($::is_initial_config_primary) {
    $software_version = $::platform::params::software_version

    Class['::sysinv'] ->

      file { '/opt/platform/sysinv':
        ensure => directory,
        owner  => 'sysinv',
        mode   => '0755',
      } ->

      file { "/opt/platform/sysinv/${software_version}":
        ensure => directory,
        owner  => 'sysinv',
        mode   => '0755',
      } ->

      file { "/opt/platform/sysinv/${software_version}/sysinv.conf.default":
        source => '/etc/sysinv/sysinv.conf',
      }
  }
}


class platform::sysinv::conductor {

  Class['::platform::drbd::platform'] -> Class[$name]

  include ::sysinv::conductor
}


class platform::sysinv::firewall
  inherits ::platform::sysinv::params {

  platform::firewall::rule { 'sysinv-api':
    service_name => 'sysinv',
    ports        => $api_port,
  }
}


class platform::sysinv::haproxy
  inherits ::platform::sysinv::params {

  platform::haproxy::proxy { 'sysinv-restapi':
    server_name => 's-sysinv',
    public_port => $api_port,
    private_port => $api_port,
  }
}


class platform::sysinv::api
  inherits ::platform::sysinv::params {

  include ::platform::params
  include ::sysinv::api

  if ($::platform::sysinv::params::service_create and
      $::platform::params::init_keystone) {
    include ::sysinv::keystone::auth
  }

  # TODO(mpeters): move to sysinv puppet module parameters
  sysinv_config {
    "DEFAULT/sysinv_api_workers": value => $::platform::params::eng_workers_by_5;
  }

  include ::platform::sysinv::firewall
  include ::platform::sysinv::haproxy
}


class platform::sysinv::bootstrap {
  include ::sysinv::db::postgresql
  include ::sysinv::keystone::auth

  include ::platform::sysinv

  class { '::sysinv::api':
    enabled => true
  }

  class { '::sysinv::conductor':
    enabled => true
  }
}
