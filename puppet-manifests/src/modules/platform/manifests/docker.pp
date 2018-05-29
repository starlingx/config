class platform::docker::params (
  $package_name    = 'docker-ce',
) { }

class platform::docker::config 
  inherits ::platform::docker::params {

  include ::platform::kubernetes::params

  if $::platform::kubernetes::params::enabled {

    Class['::platform::filesystem::docker'] ~> Class[$name]

    service { 'docker':
      ensure    => 'running',
      name      => 'docker',
      enable    => true,
      require   => Package['docker']
    } ->
    exec { 'enable-docker':
      command => '/usr/bin/systemctl enable docker.service',
    }
  }
}

class platform::docker::install 
  inherits ::platform::docker::params {

  package { 'docker':
    ensure  => 'installed',
    name    => $package_name,
  }
}

class platform::docker
{
  include ::platform::docker::install
  include ::platform::docker::config
}
