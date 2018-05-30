class platform::patching::params (
  $private_port = 5491,
  $public_port = 15491,
  $server_timeout = '300s',
  $region_name = undef,
  $service_create = false,
) { }


class platform::patching
  inherits ::platform::patching::params {

  include ::platform::params

  group { 'patching':
    ensure => 'present',
  } ->
  user { 'patching':
    ensure           => 'present',
    comment          => 'patching Daemons',
    groups           => ['nobody', 'patching', $::platform::params::protected_group_name],
    home             => '/var/lib/patching',
    password         => '!!',
    password_max_age => '-1',
    password_min_age => '-1',
    shell            => '/sbin/nologin',
  } ->
  file { "/etc/patching":
    ensure  => "directory",
    owner   => 'patching',
    group   => 'patching',
    mode    => '0755',
  } ->
  class { '::patching': }
}


class platform::patching::firewall
  inherits ::platform::patching::params {

  platform::firewall::rule { 'patching-api':
    service_name => 'patching',
    ports => $public_port,
  }
}


class platform::patching::haproxy
  inherits ::platform::patching::params {

  platform::haproxy::proxy { 'patching-restapi':
    server_name => 's-patching',
    public_port => $public_port,
    private_port => $private_port,
    server_timeout => $server_timeout,
  }
}


class platform::patching::api (
) inherits ::platform::patching::params {

  include ::patching::api

  if ($::platform::patching::params::service_create and
      $::platform::params::init_keystone) {
    include ::patching::keystone::auth
  }

  include ::platform::patching::firewall
  include ::platform::patching::haproxy
}
