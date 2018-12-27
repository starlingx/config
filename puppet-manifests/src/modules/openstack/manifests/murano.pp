class openstack::murano::params (
  $tcp_listen_options,
  $rabbit_tcp_listen_options,
  $rabbit_cipher_list,
  $api_port = 8082,
  $auth_password = 'guest',
  $auth_user = 'guest',
  $service_enabled = false,
  $disable_murano_agent = true,
  $service_name = 'openstack-murano',
  $database_idle_timeout = 60,
  $database_max_pool_size = 1,
  $database_max_overflow  = 10,
  $rabbit_normal_port = '5672',
  $rabbit_ssl_port = '5671',
  $rabbit_certs_dir = '/etc/ssl/private/murano-rabbit',
  $tlsv2 = 'tlsv1.2',
  $tlsv1 = 'tlsv1.1',
  $ssl_fail_if_no_peer_cert = true,
  $disk_free_limit = '10000000',
  $heartbeat = '30',
  $ssl = false,
) {}

class openstack::murano::firewall
  inherits ::openstack::murano::params {

  if $service_enabled {
    platform::firewall::rule { 'murano-api':
      service_name => 'murano',
      ports        => $api_port,
    }

    if $disable_murano_agent != true {
      if $ssl == true {
        platform::firewall::rule { 'murano-rabbit-ssl':
        service_name => 'murano-rabbit-ssl',
        ports        => 5671,
        }
        platform::firewall::rule { 'murano-rabbit-regular':
        ensure       => absent,
        ports        => 5672,
        service_name => 'murano-rabbit-regular',
        }
      } else {
        platform::firewall::rule { 'murano-rabbit-regular':
        service_name => 'murano-rabbit-regular',
        ports        => 5672,
        }
        platform::firewall::rule { 'murano-rabbit-ssl':
        ensure       => absent,
        ports        => 5671,
        service_name => 'murano-rabbit-ssl',
        }
      }
    } else {
    platform::firewall::rule { 'murano-rabbit-regular':
      ensure       => absent,
      ports        => 5672,
      service_name => 'murano-rabbit-regular',
      }
      platform::firewall::rule { 'murano-rabbit-ssl':
      ensure       => absent,
      ports        => 5671,
      service_name => 'murano-rabbit-ssl',
      }
    }
  }
}

class openstack::murano::haproxy
  inherits ::openstack::murano::params {

  if $service_enabled {
    platform::haproxy::proxy { 'murano-restapi':
      server_name  => 's-murano-restapi',
      public_port  => $api_port,
      private_port => $api_port,
    }
  }
}

class openstack::murano
  inherits ::openstack::murano::params {

  if $::platform::params::init_database {
    include ::murano::db::postgresql
  }

  if str2bool($::is_initial_config_primary) {
    class { '::murano::db::sync': }
  }

  include ::platform::params
  include ::platform::amqp::params

  include ::murano::client

  class { '::murano::dashboard':
    sync_db                      => false,
  }

  class { '::murano::engine':
    workers                      => $::platform::params::eng_workers_by_4,
  }

  if $ssl {
    $murano_rabbit_port = $rabbit_ssl_port
    $murano_cacert = "${rabbit_certs_dir}/ca-cert.pem"
  } else {
    $murano_rabbit_port = $rabbit_normal_port
    $murano_cacert = undef
  }

  include ::murano::params

  class {'::murano':
    use_syslog             => true,
    log_facility           => 'local2',
    service_host           => $::platform::network::mgmt::params::controller_address,
    service_port           => '8082',
    database_idle_timeout  => $database_idle_timeout,
    database_max_pool_size => $database_max_pool_size,
    database_max_overflow  => $database_max_overflow,
    sync_db                => false,
    rabbit_own_user        => $::openstack::murano::params::auth_user,
    rabbit_own_password    => $::openstack::murano::params::auth_password,
    rabbit_own_host        => $::platform::network::oam::params::controller_address,
    rabbit_own_port        => $murano_rabbit_port,
    rabbit_own_vhost       => '/',
    rabbit_own_use_ssl     => $ssl,
    rabbit_own_ca_certs    => $murano_cacert,
    disable_murano_agent   => $disable_murano_agent,
    api_workers            => $::platform::params::eng_workers_by_4,
    default_transport_url  => $::platform::amqp::params::transport_url,
  }

  # this rabbitmq is separate from the main one and used only for murano
  case $::platform::amqp::params::backend  {
    'rabbitmq': {
      enable_murano_agent_rabbitmq { 'rabbitmq': }
    }
    default: {}
  }
}

class openstack::murano::api
  inherits ::openstack::murano::params {
  include ::platform::params

  class { '::murano::api':
    enabled => false,
    host    => $::platform::network::mgmt::params::controller_address,
  }

  $upgrade = $::platform::params::controller_upgrade
  if $service_enabled and (str2bool($::is_controller_active) or $upgrade) {
    include ::murano::keystone::auth
  }

  include ::openstack::murano::haproxy
  include ::openstack::murano::firewall

}

define enable_murano_agent_rabbitmq {
  include ::openstack::murano::params
  include ::platform::params

  # Rabbit configuration parameters
  $amqp_platform_sw_version = $::platform::params::software_version
  $kombu_ssl_ca_certs = "${::openstack::murano::params::rabbit_certs_dir}/ca-cert.pem"
  $kombu_ssl_keyfile = "${::openstack::murano::params::rabbit_certs_dir}/key.pem"
  $kombu_ssl_certfile = "${::openstack::murano::params::rabbit_certs_dir}/cert.pem"

  $murano_rabbit_dir = '/var/lib/rabbitmq/murano'
  $rabbit_home = "${murano_rabbit_dir}/${amqp_platform_sw_version}"
  $mnesia_base = "${rabbit_home}/mnesia"
  $rabbit_node  = $::platform::amqp::params::node
  $murano_rabbit_node  = "murano-${rabbit_node}"
  $default_user = $::openstack::murano::params::auth_user
  $default_pass = $::openstack::murano::params::auth_password
  $disk_free_limit = $::openstack::murano::params::disk_free_limit
  $heartbeat = $::openstack::murano::params::heartbeat
  $port = $::openstack::murano::params::rabbit_normal_port

  $rabbit_cipher_list = $::openstack::murano::params::rabbit_cipher_list

  $ssl_interface = $::platform::network::oam::params::controller_address
  $ssl_port = $::openstack::murano::params::rabbit_ssl_port
  $tlsv2 = $::openstack::murano::params::tlsv2
  $tlsv1 = $::openstack::murano::params::tlsv1
  $fail_if_no_peer_cert = $::openstack::murano::params::ssl_fail_if_no_peer_cert

  $tcp_listen_options  = $::openstack::murano::params::tcp_listen_options
  $rabbit_tcp_listen_options = $::openstack::murano::params::rabbit_tcp_listen_options

  # murano rabbit ssl certificates are placed here
  file { $::openstack::murano::params::rabbit_certs_dir:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  if $::platform::params::init_database {
    file { $murano_rabbit_dir:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }

    -> file { $rabbit_home:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }

    -> file { $mnesia_base:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } -> Class['::rabbitmq']
  }

  if $::openstack::murano::params::ssl {
    $files_to_set_owner = [ $kombu_ssl_keyfile, $kombu_ssl_certfile ]
    file { $files_to_set_owner:
      owner   => 'rabbitmq',
      group   => 'rabbitmq',
      require => Package['rabbitmq-server'],
      notify  => Service['rabbitmq-server'],
    }
    $rabbitmq_conf_template= 'openstack/murano-rabbitmq.config.ssl.erb'

  } else {
    $rabbitmq_conf_template= 'openstack/murano-rabbitmq.config.erb'
  }

  file { '/etc/rabbitmq/murano-rabbitmq.config':
    ensure  => present,
    owner   => 'rabbitmq',
    group   => 'rabbitmq',
    mode    => '0640',
    content => template($rabbitmq_conf_template),
  }

  file { '/etc/rabbitmq/murano-rabbitmq-env.conf':
    ensure  => present,
    owner   => 'rabbitmq',
    group   => 'rabbitmq',
    mode    => '0640',
    content => template('openstack/murano-rabbitmq-env.conf.erb'),
  }
}

class openstack::murano::upgrade {
  include ::platform::params

  $amqp_platform_sw_version = $::platform::params::software_version
  $murano_rabbit_dir = '/var/lib/rabbitmq/murano'
  $rabbit_home = "${murano_rabbit_dir}/${amqp_platform_sw_version}"
  $mnesia_base = "${rabbit_home}/mnesia"

  file { $murano_rabbit_dir:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  -> file { $rabbit_home:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  -> file { $mnesia_base:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }
}
