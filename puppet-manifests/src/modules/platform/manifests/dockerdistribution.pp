class platform::dockerdistribution::params (
) {}

class platform::dockerdistribution::config
  inherits ::platform::dockerdistribution::params {
  $enabled = $::platform::kubernetes::params::enabled

  if $enabled {
    include ::platform::network::mgmt::params
#    This stuff will be needed for SM integration in the future.
#    I wrote it as part of trying to get it to work, but it's not useable right now
#    $controller_0_hostname         = $::platform::params::controller_0_hostname
#    $controller_1_hostname         = $::platform::params::controller_1_hostname
#    $system_mode                   = $::platform::params::system_mode
#    if $system_mode == 'simplex' {
#      $docker_registry_ip   = $::platform::network::mgmt::params::controller0_address
#    } else {
#      case $::hostname {
#        $controller_0_hostname: {
#          $docker_registry_ip   = $::platform::network::mgmt::params::controller0_address
#        }
#        $controller_1_hostname: {
#          $docker_registry_ip   = $::platform::network::mgmt::params::controller1_address
#        }
#      }
#    }

    # insecure workaround will be removed along with the template when proper authentication is implemented
    $insecure_docker_registry_workaround = $::platform::network::mgmt::params::controller_address
    # proper docker registry ip will be set with SM integration
    $docker_registry_ip = '0.0.0.0'

    # currently docker registry is running insecure mode
    # when proper authentication is implemented, this would go away
    file { "/etc/docker":
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    } ->
    file { "/etc/docker/daemon.json":
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/insecuredockerregistry.conf.erb'),
    } ->

    file { "/etc/docker-distribution/registry/config.yml":
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/dockerdistribution.conf.erb'),
    } ->

    # for now, start with systemd and not sm
    service { 'docker-distribution':
      ensure  => 'running',
      name    => 'docker-distribution',
      enable  => true,
    } ->
    exec { 'systemctl enable docker-distribution':
      command => "/usr/bin/systemctl enable docker-distribution.service",
    }
  }
}

class platform::dockerdistribution
  inherits ::platform::dockerdistribution::params {

  $enabled = $::platform::kubernetes::params::enabled
  if $enabled {
    include platform::dockerdistribution::config

    Class['::platform::docker::config'] -> Class[$name]
  }
}
