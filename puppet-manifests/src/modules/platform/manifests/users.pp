class platform::users::params (
  $wrsroot_password = undef,
  $wrsroot_password_max_age = undef,
) {}


class platform::users
  inherits ::platform::users::params {

  include ::platform::params

  group { 'wrs':
    ensure => 'present',
  } ->

  # WRS: Create a 'wrs_protected' group for wrsroot and all openstack services
  # (including TiS services: sysinv, etc.).
  group { $::platform::params::protected_group_name:
    ensure => 'present',
    gid    =>  $::platform::params::protected_group_id,
  } ->

  user { 'wrsroot':
    ensure   => 'present',
    groups   => ['wrs', 'root', $::platform::params::protected_group_name],
    home     => '/home/wrsroot',
    password => $wrsroot_password,
    password_max_age => $wrsroot_password_max_age,
    shell    => '/bin/sh',
  } ->

  # WRS: Keyring should only be executable by 'wrs_protected'.
  file { '/usr/bin/keyring':
    owner => 'root',
    group =>  $::platform::params::protected_group_name,
    mode  => '0750',
  }
}


class platform::users::bootstrap
  inherits ::platform::users::params {

  include ::platform::params

  group { 'wrs':
    ensure => 'present',
  } ->

  group { $::platform::params::protected_group_name:
    ensure => 'present',
    gid    => $::platform::params::protected_group_id,
  } ->

  user { 'wrsroot':
    ensure   => 'present',
    groups   => ['wrs', 'root', $::platform::params::protected_group_name],
    home     => '/home/wrsroot',
    password_max_age => $wrsroot_password_max_age,
    shell    => '/bin/sh',
  }
}


class platform::users::runtime {
  include ::platform::users
}

class platform::users::upgrade {
  include ::platform::users
}

