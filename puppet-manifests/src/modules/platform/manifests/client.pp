class platform::client::params (
  $admin_username,
  $identity_auth_url,
  $identity_region = 'RegionOne',
  $identity_api_version = 3,
  $admin_user_domain = 'Default',
  $admin_project_domain = 'Default',
  $admin_project_name = 'admin',
  $admin_password = undef,
  $keystone_identity_region = 'RegionOne',
) { }

class platform::client
  inherits ::platform::client::params {

  include ::platform::client::credentials::params
  $keyring_file = $::platform::client::credentials::params::keyring_file

  file {'/etc/platform/openrc':
    ensure  => 'present',
    mode    => '0640',
    owner   => 'root',
    group   => 'root',
    content => template('platform/openrc.admin.erb'),
  }
  -> file {'/etc/bash_completion.d/openstack':
    ensure  => 'present',
    mode    => '0644',
    content => generate('/usr/bin/openstack', 'complete'),
  }

  if $::personality == 'controller' {
    file {'/etc/ssl/private/openstack':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
  }
}

class platform::client::credentials::params (
  $keyring_base,
  $keyring_directory,
  $keyring_file,
) { }

class platform::client::credentials
  inherits ::platform::client::credentials::params {

  Class['::platform::drbd::platform']
  -> file { $keyring_base:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }
  -> file { $keyring_directory:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }
  -> file { $keyring_file:
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    content => 'keyring get CGCS admin'
  }
}

class platform::client::bootstrap {
  include ::platform::client
  include ::platform::client::credentials
}

class platform::client::upgrade {
  include ::platform::client
}
