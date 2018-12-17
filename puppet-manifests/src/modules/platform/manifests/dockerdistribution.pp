class platform::dockerdistribution::params (
) {}

class platform::dockerdistribution::config
  inherits ::platform::dockerdistribution::params {
  $enabled = $::platform::kubernetes::params::enabled

  if $enabled {
    include ::platform::network::mgmt::params

    $docker_registry_ip = $::platform::network::mgmt::params::controller_address

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
    }

    # copy the startup script to where it is supposed to be
    file {'docker_distribution_initd_script':
      path    => '/etc/init.d/docker-distribution',
      ensure  => 'present',
      mode    => '0755',
      source  => "puppet:///modules/${module_name}/docker-distribution"
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

    $docker_registry_ip = $::platform::network::mgmt::params::controller_address

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
