class openstack::client::params (
  $admin_username,
  $identity_auth_url,
  $identity_region = 'RegionOne',
  $identity_api_version = 3,
  $admin_user_domain = 'Default',
  $admin_project_domain = 'Default',
  $admin_project_name = 'admin',
  $keystone_identity_region = 'RegionOne',
) { }

class openstack::client
  inherits ::openstack::client::params {

  include ::openstack::client::credentials::params
  $keyring_file = $::openstack::client::credentials::params::keyring_file

  file {"/etc/nova/openrc":
    ensure  => "present",
    mode    => '0640',
    owner   => 'nova',
    group   => 'root',
    content => template('openstack/openrc.admin.erb'),
  }

  file {"/etc/nova/ldap_openrc_template":
    ensure  => "present",
    mode    => '0644',
    content => template('openstack/openrc.ldap.erb'),
  }

  file {"/etc/bash_completion.d/openstack":
    ensure  => "present",
    mode    => '0644',
    content => generate('/usr/bin/openstack', 'complete'),
  }
}


class openstack::client::credentials::params (
  $keyring_base,
  $keyring_directory,
  $keyring_file,
) { }

class openstack::client::credentials
  inherits ::openstack::client::credentials::params {

  Class['::platform::drbd::platform'] ->
  file { "${keyring_base}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } ->
  file { "${keyring_directory}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } ->
  file { "${keyring_file}":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    content => "keyring get CGCS admin"
  }
}

class openstack::client::bootstrap {
  include ::openstack::client
  include ::openstack::client::credentials
}

class openstack::client::upgrade {
  include ::openstack::client
}
