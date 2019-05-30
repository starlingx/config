class platform::memcached::params(
  $package_ensure = 'present',
  $logfile = '/var/log/memcached.log',
  # set CACHESIZE in /etc/sysconfig/memcached
  $max_memory = false,
  $tcp_port = 11211,
  $udp_port = 11211,
  # set MAXCONN in /etc/sysconfig/memcached
  $max_connections = 8192,
  $service_restart = true,
) {
  include ::platform::params
  $controller_0_hostname = $::platform::params::controller_0_hostname
  $controller_1_hostname = $::platform::params::controller_1_hostname
  $system_mode           = $::platform::params::system_mode

  if $system_mode == 'simplex' {
    $listen_ip = $::platform::network::mgmt::params::controller0_address
  } else {
    case $::hostname {
      $controller_0_hostname: {
        $listen_ip = $::platform::network::mgmt::params::controller0_address
      }
      $controller_1_hostname: {
        $listen_ip = $::platform::network::mgmt::params::controller1_address
      }
      default: {
        fail("Hostname must be either ${controller_0_hostname} or ${controller_1_hostname}")
      }
    }
  }

  $listen_ip_version = $::platform::network::mgmt::params::subnet_version
}


class platform::memcached
  inherits ::platform::memcached::params {

  Anchor['platform::networking']

  -> class { '::memcached':
    package_ensure  => $package_ensure,
    logfile         => $logfile,
    listen_ip       => $listen_ip,
    tcp_port        => $tcp_port,
    udp_port        => $udp_port,
    max_connections => $max_connections,
    max_memory      => $max_memory,
    service_restart => $service_restart,
  }

  -> exec { 'systemctl enable memcached.service':
    command => '/usr/bin/systemctl enable memcached.service',
  }
}
