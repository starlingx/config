class openstack::client {

  include ::platform::client::params
  $admin_username = $::platform::client::params::admin_username
  $identity_auth_url = $::platform::client::params::identity_auth_url
  $identity_region = $::platform::client::params::identity_region
  $identity_api_version = $::platform::client::params::identity_api_version
  $admin_user_domain = $::platform::client::params::admin_user_domain
  $admin_project_domain = $::platform::client::params::admin_project_domain
  $admin_project_name = $::platform::client::params::admin_project_name
  $keystone_identity_region = $::platform::client::params::keystone_identity_region

  include ::platform::client::credentials::params
  $keyring_file = $::platform::client::credentials::params::keyring_file

  file {'/etc/nova/openrc':
    ensure  => 'present',
    mode    => '0640',
    owner   => 'nova',
    group   => 'root',
    content => template('openstack/openrc.admin.erb'),
  }

  file {'/etc/nova/ldap_openrc_template':
    ensure  => 'present',
    mode    => '0644',
    content => template('openstack/openrc.ldap.erb'),
  }

  file {'/etc/bash_completion.d/openstack':
    ensure  => 'present',
    mode    => '0644',
    content => generate('/usr/bin/openstack', 'complete'),
  }
}

class openstack::client::bootstrap {
  include ::openstack::client
}

class openstack::client::upgrade {
  include ::openstack::client
}
