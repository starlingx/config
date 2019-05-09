class platform::users::params (
  $sysadmin_password = undef,
  $sysadmin_password_max_age = undef,
) {}


class platform::users
  inherits ::platform::users::params {

  include ::platform::params

  # Create a 'sys_protected' group for sysadmin and all openstack services
  # (including StarlingX services: sysinv, etc.).
  group { $::platform::params::protected_group_name:
    ensure => 'present',
    gid    => $::platform::params::protected_group_id,
  }

  -> user { 'sysadmin':
    ensure           => 'present',
    groups           => ['root', $::platform::params::protected_group_name],
    home             => '/home/sysadmin',
    password         => $sysadmin_password,
    password_max_age => $sysadmin_password_max_age,
    shell            => '/bin/sh',
  }

  # Keyring should only be executable by 'sys_protected'.
  -> file { '/usr/bin/keyring':
    owner => 'root',
    group =>  $::platform::params::protected_group_name,
    mode  => '0750',
  }
}


class platform::users::bootstrap
  inherits ::platform::users::params {

  include ::platform::params

  group { $::platform::params::protected_group_name:
    ensure => 'present',
    gid    => $::platform::params::protected_group_id,
  }

  -> user { 'sysadmin':
    ensure           => 'present',
    groups           => ['root', $::platform::params::protected_group_name],
    home             => '/home/sysadmin',
    password_max_age => $sysadmin_password_max_age,
    shell            => '/bin/sh',
  }
}


class platform::users::runtime {
  include ::platform::users
}

class platform::users::upgrade {
  include ::platform::users
}

