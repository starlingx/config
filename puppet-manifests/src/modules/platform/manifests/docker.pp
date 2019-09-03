class platform::docker::params (
  $package_name = 'docker-ce',
  $http_proxy   = undef,
  $https_proxy  = undef,
  $no_proxy     = undef,
  $k8s_registry    = undef,
  $gcr_registry    = undef,
  $quay_registry   = undef,
  $docker_registry = undef,
  $k8s_registry_secret    = undef,
  $gcr_registry_secret    = undef,
  $quay_registry_secret   = undef,
  $docker_registry_secret = undef,
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
    ~> exec { 'perform systemctl daemon reload for docker proxy':
      command     => 'systemctl daemon-reload',
      logoutput   => true,
      refreshonly => true,
    } ~> Service['docker']
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

class platform::docker::config::bootstrap
  inherits ::platform::docker::params {

  require ::platform::filesystem::docker::bootstrap

  Class['::platform::filesystem::docker::bootstrap'] ~> Class[$name]

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

class platform::docker::bootstrap
{
  include ::platform::docker::install
  include ::platform::docker::config::bootstrap
}

define platform::docker::login_registry (
  $registry_url,
  $registry_secret,
) {
  include ::platform::client::params

  $auth_url = $::platform::client::params::identity_auth_url
  $username = $::platform::client::params::admin_username
  $user_domain = $::platform::client::params::admin_user_domain
  $project_name = $::platform::client::params::admin_project_name
  $project_domain = $::platform::client::params::admin_project_domain
  $region_name = $::platform::client::params::keystone_identity_region
  $password = $::platform::client::params::admin_password
  $interface = 'internal'

  # Registry credentials have been stored in Barbican secret at Ansible
  # bootstrap time, retrieve Barbican secret to get the payload
  notice("Get payload of Barbican secret ${registry_secret}")
  $secret_payload = generate(
    '/bin/sh', '-c', template('platform/get-secret-payload.erb'))

  if $secret_payload {
    # Parse Barbican secret payload to get the registry username and password
    $secret_payload_array = split($secret_payload, ' ')
    $registry_username = split($secret_payload_array[0], 'username:')[1]
    $registry_password = split($secret_payload_array[1], 'password:')[1]

    # Login to authenticated registry
    if $registry_username and $registry_password {
      exec { 'Login registry':
        command   => "docker login ${registry_url} -u ${registry_username} -p ${registry_password}",
        logoutput => true,
      }
    } else {
      notice('Registry username or/and password NOT FOUND')
    }
  }
}
