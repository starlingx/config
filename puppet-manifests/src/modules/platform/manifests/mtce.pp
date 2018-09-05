class platform::mtce::params (
  $auth_host = undef,
  $auth_port = undef,
  $auth_uri = undef,
  $auth_username = undef,
  $auth_pw = undef,
  $auth_project = undef,
  $auth_user_domain = undef,
  $auth_project_domain = undef,
  $auth_region = undef,
  $compute_boot_timeout = undef,
  $controller_boot_timeout = undef,
  $heartbeat_degrade_threshold = undef,
  $heartbeat_failure_threshold = undef,
  $heartbeat_failure_action = undef,
  $heartbeat_period = undef,
  $mtce_multicast = undef,
  $mnfa_threshold = undef,
  $mnfa_timeout = undef,
) { }


class platform::mtce
  inherits ::platform::mtce::params {

  include ::openstack::ceilometer::params
  $ceilometer_port = $::openstack::ceilometer::params::api_port

  include ::openstack::client::credentials::params
  $keyring_directory = $::openstack::client::credentials::params::keyring_directory

  file { "/etc/mtc.ini":
    ensure  => present,
    mode    => '0755',
    content => template('mtce/mtc_ini.erb'),
  }

  $boot_device = $::boot_disk_device_path

  file { "/etc/rmonfiles.d/static.conf":
      ensure   => present,
      mode     => '0644',
      content  => template('mtce/static_conf.erb'),
  }
}


class platform::mtce::agent
  inherits ::platform::mtce::params {

  if $::platform::params::init_keystone {
    # configure a mtce keystone user
    keystone_user { $auth_username:
      password => $auth_pw,
      ensure   => present,
      enabled  => true,
    }

    # assign an admin role for this mtce user on the services tenant
    keystone_user_role { "${auth_username}@${auth_project}":
      ensure          => present,
      user_domain     => $auth_user_domain,
      project_domain  => $auth_project_domain,
      roles           => ['admin'],
    }
  }
}


class platform::mtce::reload {
  exec {'signal-mtc-agent':
    command => "pkill -HUP mtcAgent",
  }
  exec {'signal-hbs-agent':
    command => "pkill -HUP hbsAgent",
  }

  # mtcClient and hbsClient don't currently reload all configuration,
  # therefore they must be restarted.  Move to HUP if daemon updated.
  exec {'pmon-restart-hbs-client':
    command => "pmon-restart hbsClient",
  }
  exec {'pmon-restart-mtc-client':
    command => "pmon-restart mtcClient",
  }
}

class platform::mtce::runtime {
  include ::platform::mtce

  class {'::platform::mtce::reload':
    stage => post
  }
}
