class platform::dockerdistribution::params (
) {}

class platform::dockerdistribution::config
  inherits ::platform::dockerdistribution::params {
  $enabled = $::platform::kubernetes::params::enabled

  if $enabled {
    include ::platform::network::mgmt::params
    include ::platform::docker::params

    $docker_registry_ip = $::platform::network::mgmt::params::controller_address

    # check insecure registries
    if $::platform::docker::params::insecure_registry {
      # insecure registry is true means unified registry was set
      $insecure_registries = "\"${::platform::docker::params::k8s_registry}\", \"${docker_registry_ip}:9001\""
    } else {
      $insecure_registries = "\"${docker_registry_ip}:9001\""
    }

    # currently docker registry is running insecure mode
    # when proper authentication is implemented, this would go away
    file { '/etc/docker':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }
    -> file { '/etc/docker/daemon.json':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/insecuredockerregistry.conf.erb'),
    }

    -> file { '/etc/docker-distribution/registry/config.yml':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/dockerdistribution.conf.erb'),
    }

    # copy the startup script to where it is supposed to be
    file {'docker_distribution_initd_script':
      ensure => 'present',
      path   => '/etc/init.d/docker-distribution',
      mode   => '0755',
      source => "puppet:///modules/${module_name}/docker-distribution"
    }
  }
}

# compute also needs the "insecure" flag in order to deploy images from
# the registry. This will go away when proper authentication is implemented
class platform::dockerdistribution::compute
  inherits ::platform::dockerdistribution::params {
  include ::platform::kubernetes::params
  $enabled = $::platform::kubernetes::params::enabled
  if $enabled {
    include ::platform::network::mgmt::params
    include ::platform::docker::params

    $docker_registry_ip = $::platform::network::mgmt::params::controller_address

    # check insecure registries
    if $::platform::docker::params::insecure_registry {
      # insecure registry is true means unified registry was set
      $insecure_registries = "\"${::platform::docker::params::k8s_registry}\", \"${docker_registry_ip}:9001\""
    } else {
      $insecure_registries = "\"${docker_registry_ip}:9001\""
    }

    # currently docker registry is running insecure mode
    # when proper authentication is implemented, this would go away
    file { '/etc/docker':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }
    -> file { '/etc/docker/daemon.json':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/insecuredockerregistry.conf.erb'),
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
