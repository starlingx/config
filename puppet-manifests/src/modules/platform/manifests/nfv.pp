class platform::nfv::params (
  $api_port = 4545,
  $region_name = undef,
  $service_create = false,
) { }


class platform::nfv {
  include ::platform::params
  include ::platform::amqp::params

  group { 'nfv':
    ensure => 'present',
    gid    => '172',
  }

  user { 'nfv':
    ensure           => 'present',
    comment          => 'nfv',
    gid              => '172',
    groups           => ['nobody', 'nfv', $::platform::params::protected_group_name],
    home             => '/var/lib/nfv',
    password         => '!!',
    password_max_age => '-1',
    password_min_age => '-1',
    shell            => '/sbin/nologin',
    uid              => '172',
  }

  file {'/opt/platform/nfv':
    ensure => directory,
    mode   => '0755',
  }

  include ::nfv
  include ::nfv::vim

  class { '::nfv::nfvi':
    rabbit_host => $::platform::amqp::params::host,
    rabbit_port => $::platform::amqp::params::port,
    rabbit_userid => $::platform::amqp::params::auth_user,
    rabbit_password => $::platform::amqp::params::auth_password,
  }
}


class platform::nfv::reload {
  platform::sm::restart {'vim': }
}


class platform::nfv::runtime {
  include ::platform::nfv

  class {'::platform::nfv::reload':
    stage => post
  }
}


class platform::nfv::firewall
  inherits ::platform::nfv::params {

  platform::firewall::rule { 'nfv-vim-api':
    service_name => 'nfv-vim',
    ports        => $api_port,
  }
}


class platform::nfv::haproxy
  inherits ::platform::nfv::params {

  platform::haproxy::proxy { 'vim-restapi':
    server_name => 's-vim-restapi',
    public_port => $api_port,
    private_port => $api_port,
  }
}


class platform::nfv::api
  inherits ::platform::nfv::params {

  if ($::platform::nfv::params::service_create and
      $::platform::params::init_keystone) {
    include ::nfv::keystone::auth
  }

  include ::platform::nfv::firewall
  include ::platform::nfv::haproxy
}

