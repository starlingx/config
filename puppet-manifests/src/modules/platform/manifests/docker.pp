class platform::docker::params (
  $package_name = 'docker-ce',
  $http_proxy   = undef,
  $https_proxy  = undef,
  $no_proxy     = undef,
  $k8s_registry    = undef,
  $gcr_registry    = undef,
  $quay_registry   = undef,
  $docker_registry = undef,
  $insecure_registry    = undef,
) { }

class platform::docker::config
  inherits ::platform::docker::params {

  if $http_proxy or $https_proxy {
    file { '/etc/systemd/system/docker.service.d':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
    -> file { '/etc/systemd/system/docker.service.d/http-proxy.conf':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/dockerproxy.conf.erb'),
    }
  }

  Class['::platform::filesystem::docker'] ~> Class[$name]

  service { 'docker':
    ensure  => 'running',
    name    => 'docker',
    enable  => true,
    require => Package['docker']
  }
  -> exec { 'enable-docker':
    command => '/usr/bin/systemctl enable docker.service',
  }
}

class platform::docker::install
  inherits ::platform::docker::params {

  package { 'docker':
    ensure => 'installed',
    name   => $package_name,
  }
}

class platform::docker
{
  include ::platform::docker::install
  include ::platform::docker::config
}
