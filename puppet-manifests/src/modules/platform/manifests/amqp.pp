class platform::amqp::params (
  $auth_password = 'guest',
  $auth_user = 'guest',
  $backend = 'rabbitmq',
  $node = 'rabbit@localhost',
  $host = 'localhost',
  $host_url = 'localhost',
  $port = 5672,
  $protocol = 'tcp',
  $ssl_enabled = false,
) {
  $transport_url = "rabbit://${auth_user}:${auth_password}@${host_url}:${port}"
}


class platform::amqp::rabbitmq (
  $service_enabled = false,
) inherits ::platform::amqp::params {

  include ::platform::params

  File <| path == '/etc/rabbitmq/rabbitmq.config' |> {
    ensure => present,
    owner  => 'rabbitmq',
    group  => 'rabbitmq',
    mode   => '0640',
  }

  file { '/var/log/rabbitmq':
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  if $service_enabled {
    $service_ensure = 'running'
  }
  elsif str2bool($::is_initial_config_primary) {
    $service_ensure = 'running'

    # ensure service is stopped after initial configuration
    class { '::platform::amqp::post':
      stage => post
    }
  } else {
    $service_ensure = 'stopped'
  }

  $rabbit_dbdir = "/var/lib/rabbitmq/${::platform::params::software_version}"

  class { '::rabbitmq':
    port             => $port,
    ssl              => $ssl_enabled,
    default_user     => $auth_user,
    default_pass     => $auth_password,
    service_ensure   => $service_ensure,
    rabbitmq_home    => $rabbit_dbdir,
    environment_variables => {
      'RABBITMQ_NODENAME' => $node,
      'RABBITMQ_MNESIA_BASE' => "${rabbit_dbdir}/mnesia",
      'HOME' => $rabbit_dbdir,
    },
    config_variables => {
      'disk_free_limit' => '100000000',
      'heartbeat' => '30',
      'tcp_listen_options' => '[binary,
                               {packet,raw},
                               {reuseaddr,true},
                               {backlog,128},
                               {nodelay,true},
                               {linger,{true,0}},
                               {exit_on_close,false},
                               {keepalive,true}]',
    }
  }
}


class platform::amqp::post {
  # rabbitmq-server needs to be running in order to apply the initial manifest,
  # however, it needs to be stopped/disabled to allow SM to manage the service.
  # To allow for the transition it must be explicitely stopped. Once puppet
  # can directly handle SM managed services, then this can be removed.
  exec { 'stop rabbitmq-server service':
    command => "systemctl stop rabbitmq-server; systemctl disable rabbitmq-server",
  }
}


class platform::amqp::bootstrap {
  include ::platform::params

  Class['::platform::drbd::rabbit'] -> Class[$name]

  class { '::platform::amqp::rabbitmq':
    service_enabled => true,
  }

  # Ensure the rabbit data directory is created in the rabbit filesystem.
  $rabbit_dbdir = "/var/lib/rabbitmq/${::platform::params::software_version}"
  file { "${rabbit_dbdir}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } -> Class['::rabbitmq']

  rabbitmq_policy {'notifications_queues_maxlen@/':
    require => Class['::rabbitmq'],
    pattern => '.*notifications.*',
    priority => 0,
    applyto => 'queues',
    definition => {
      'max-length' => '10000',
    },
  }

  rabbitmq_policy {'sample_queues_maxlen@/':
    require => Class['::rabbitmq'],
    pattern => '.*sample$',
    priority => 0,
    applyto => 'queues',
    definition => {
      'max-length' => '100000',
    },
  }

  rabbitmq_policy {'all_queues_ttl@/':
    require => Class['::rabbitmq'],
    pattern => '.*',
    priority => 0,
    applyto => 'queues',
    definition => {
      'expires' => '14400000',
    }
  }
}

class platform::amqp::upgrade {
  include ::platform::params

  class { '::platform::amqp::rabbitmq':
    service_enabled => true,
  }

  # Ensure the rabbit data directory is created in the rabbit filesystem.
  $rabbit_dbdir = "/var/lib/rabbitmq/${::platform::params::software_version}"
  file { "${rabbit_dbdir}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } -> Class['::rabbitmq']

}
