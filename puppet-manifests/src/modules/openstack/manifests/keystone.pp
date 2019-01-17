class openstack::keystone::params(
  $api_version,
  $identity_uri,
  $auth_uri,
  $host_url,
  $api_port = 5000,
  $admin_port = 5000,
  $region_name = undef,
  $system_controller_region = undef,
  $service_name = 'openstack-keystone',
  $token_expiration = 3600,
  $service_create = false,
  $fernet_keys_rotation_minute = '25',
  $fernet_keys_rotation_hour = '0',
  $fernet_keys_rotation_month = '*/1',
  $fernet_keys_rotation_monthday = '1',
  $fernet_keys_rotation_weekday = '*',
) {}

class openstack::keystone (
) inherits ::openstack::keystone::params {

  include ::platform::params

  # In the case of a classical Multi-Region deployment, apply the Keystone
  # controller configuration for Primary Region ONLY
  # (i.e. on which region_config is False), since Keystone is a Shared service
  #
  # In the case of a Distributed Cloud deployment, apply the Keystone
  # controller configuration for each SubCloud, since Keystone is also
  # a localized service.
  if (!$::platform::params::region_config or
      $::platform::params::distributed_cloud_role == 'subcloud')  {
    include ::platform::amqp::params
    include ::platform::network::mgmt::params
    include ::platform::drbd::cgcs::params

    $keystone_key_repo_path = "${::platform::drbd::cgcs::params::mountpoint}/keystone"
    $eng_workers = $::platform::params::eng_workers

    # FIXME(mpeters): binding to wildcard address to allow bootstrap transition
    # Not sure if there is a better way to transition from the localhost address
    # to the management address while still being able to authenticate the client
    if str2bool($::is_initial_config_primary) {
      $enabled = true
      $bind_host = $::platform::network::mgmt::params::subnet_version ? {
        6       => '[::]',
        default => '0.0.0.0',
      }
    } else {
      $enabled = false
      $bind_host = $::platform::network::mgmt::params::controller_address_url
    }

    Class[$name] -> Class['::platform::client'] -> Class['::openstack::client']

    include ::keystone::client


    # Configure keystone graceful shutdown timeout
    # TODO(mpeters): move to puppet-keystone for module configuration
    keystone_config {
      'DEFAULT/graceful_shutdown_timeout': value => 15;
    }

    # (Pike Rebase) Disable token post expiration window since this
    # allows authentication for upto 2 days worth of stale tokens.
    # TODO(knasim): move this to puppet-keystone along with graceful
    # shutdown timeout param
    keystone_config {
        'token/allow_expired_window': value => 0;
    }


    file { '/etc/keystone/keystone-extra.conf':
      ensure  => present,
      owner   => 'root',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-extra.conf.erb'),
    }
    -> class { '::keystone':
      enabled               => $enabled,
      enable_fernet_setup   => false,
      fernet_key_repository => "${keystone_key_repo_path}/fernet-keys",
      default_transport_url => $::platform::amqp::params::transport_url,
      service_name          => $service_name,
      token_expiration      => $token_expiration,
    }

    # create keystone policy configuration
    file { '/etc/keystone/policy.json':
      ensure  => present,
      owner   => 'keystone',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-policy.json.erb'),
    }

    # Keystone users can only be added to the SQL backend (write support for
    # the LDAP backend has been removed). We can therefore set password rules
    # irrespective of the backend
    if ! str2bool($::is_restore_in_progress) {
      # If the Restore is in progress then we need to apply the Keystone
      # Password rules as a runtime manifest, as the passwords in the hiera records
      # records may not be rule-compliant if this system was upgraded from R4
      # (where-in password rules were not in affect)
      include ::keystone::security_compliance
    }

    include ::keystone::ldap

    if $::platform::params::distributed_cloud_role == undef {
      # Set up cron job that will rotate fernet keys. This is done every month on
      # the first day of the month at 00:25 by default. The cron job runs on both
      # controllers, but the script will only take action on the active controller.
      cron { 'keystone-fernet-keys-rotater':
        ensure      => 'present',
        command     => '/usr/bin/keystone-fernet-keys-rotate-active',
        environment => 'PATH=/bin:/usr/bin:/usr/sbin',
        minute      => $fernet_keys_rotation_minute,
        hour        => $fernet_keys_rotation_hour,
        month       => $fernet_keys_rotation_month,
        monthday    => $fernet_keys_rotation_monthday,
        weekday     => $fernet_keys_rotation_weekday,
        user        => 'root',
      }
    }
  } else {
      class { '::keystone':
        enabled          => false,
      }
  }
}


class openstack::keystone::firewall
  inherits ::openstack::keystone::params {

  if !$::platform::params::region_config {
    platform::firewall::rule { 'keystone-api':
      service_name => 'keystone',
      ports        => $api_port,
    }
  }
}


class openstack::keystone::haproxy
  inherits ::openstack::keystone::params {

  include ::platform::params

  if !$::platform::params::region_config {
    platform::haproxy::proxy { 'keystone-restapi':
      server_name  => 's-keystone',
      public_port  => $api_port,
      private_port => $api_port,
    }
  }
}


class openstack::keystone::api
  inherits ::openstack::keystone::params {

  include ::platform::params

  if ($::openstack::keystone::params::service_create and
      $::platform::params::init_keystone) {
    include ::keystone::endpoint
    include ::openstack::keystone::endpointgroup

    # Cleanup the endpoints created at bootstrap if they are not in
    # the subcloud region.
    if ($::platform::params::distributed_cloud_role == 'subcloud' and
        $::platform::params::region_2_name != 'RegionOne') {
      Keystone_endpoint["${platform::params::region_2_name}/keystone::identity"] -> Keystone_endpoint['RegionOne/keystone::identity']
      keystone_endpoint { 'RegionOne/keystone::identity':
        ensure       => 'absent',
        name         => 'keystone',
        type         => 'identity',
        region       => 'RegionOne',
        public_url   => 'http://127.0.0.1:5000/v3',
        admin_url    => 'http://127.0.0.1:5000/v3',
        internal_url => 'http://127.0.0.1:5000/v3'
      }
    }
  }

  include ::openstack::keystone::firewall
  include ::openstack::keystone::haproxy
}


class openstack::keystone::bootstrap(
  $default_domain = 'Default',
) {
  include ::platform::params
  include ::platform::amqp::params
  include ::platform::drbd::cgcs::params

  $keystone_key_repo_path = "${::platform::drbd::cgcs::params::mountpoint}/keystone"
  $eng_workers = $::platform::params::eng_workers
  $bind_host = '0.0.0.0'

  # In the case of a classical Multi-Region deployment, apply the Keystone
  # controller configuration for Primary Region ONLY
  # (i.e. on which region_config is False), since Keystone is a Shared service
  #
  # In the case of a Distributed Cloud deployment, apply the Keystone
  # controller configuration for each SubCloud, since Keystone is also
  # a localized service.
  if ($::platform::params::init_keystone and
      (!$::platform::params::region_config or
        $::platform::params::distributed_cloud_role == 'subcloud')) {

    include ::keystone::db::postgresql

    Class[$name] -> Class['::platform::client'] -> Class['::openstack::client']

    # Create the parent directory for fernet keys repository
    file { $keystone_key_repo_path:
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      require => Class['::platform::drbd::cgcs'],
    }
    -> file { '/etc/keystone/keystone-extra.conf':
      ensure  => present,
      owner   => 'root',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-extra.conf.erb'),
    }
    -> class { '::keystone':
      enabled               => true,
      enable_bootstrap      => true,
      fernet_key_repository => "${keystone_key_repo_path}/fernet-keys",
      sync_db               => true,
      default_domain        => $default_domain,
      default_transport_url => $::platform::amqp::params::transport_url,
    }

    include ::keystone::client
    include ::keystone::endpoint
    include ::keystone::roles::admin

    # Ensure the default _member_ role is present
    keystone_role { '_member_':
      ensure => present,
    }


    # disabling the admin token per openstack recommendation
    include ::keystone::disable_admin_token_auth
  }
}


class openstack::keystone::reload {
  platform::sm::restart {'keystone': }
}


class openstack::keystone::endpointgroup
  inherits ::openstack::keystone::params {
  include ::platform::params
  include ::platform::client

  # $::platform::params::init_keystone should be checked by the caller.
  # as this class should be only invoked when initializing keystone.
  # i.e. is_initial_config_primary is true is expected.

  if ($::platform::params::distributed_cloud_role =='systemcontroller') {
    $reference_region = $::openstack::keystone::params::region_name
    $system_controller_region = $::openstack::keystone::params::system_controller_region
    $os_username = $::platform::client::params::admin_username
    $identity_region = $::platform::client::params::identity_region
    $keystone_region = $::platform::client::params::keystone_identity_region
    $keyring_file = $::platform::client::credentials::params::keyring_file
    $auth_url = $::platform::client::params::identity_auth_url
    $os_project_name = $::platform::client::params::admin_project_name
    $api_version = 3

    file { "/etc/keystone/keystone-${reference_region}-filter.conf":
      ensure  => present,
      owner   => 'root',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-defaultregion-filter.erb'),
    }
    -> file { "/etc/keystone/keystone-${system_controller_region}-filter.conf":
      ensure  => present,
      owner   => 'root',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-systemcontroller-filter.erb'),
    }
    -> exec { "endpointgroup-${reference_region}-command":
      cwd       => '/etc/keystone',
      logoutput => true,
      provider  => shell,
      require   => [ Class['openstack::keystone::api'], Class['::keystone::endpoint'] ],
      command   => template('openstack/keystone-defaultregion.erb'),
      path      =>  ['/usr/bin/', '/bin/', '/sbin/', '/usr/sbin/'],
    }
    -> exec { "endpointgroup-${system_controller_region}-command":
      cwd       => '/etc/keystone',
      logoutput => true,
      provider  => shell,
      require   => [ Class['openstack::keystone::api'], Class['::keystone::endpoint'] ],
      command   => template('openstack/keystone-systemcontroller.erb'),
      path      =>  ['/usr/bin/', '/bin/', '/sbin/', '/usr/sbin/'],
    }
  }
}


class openstack::keystone::server::runtime {
  include ::platform::client
  include ::openstack::client
  include ::openstack::keystone

  class {'::openstack::keystone::reload':
    stage => post
  }
}


class openstack::keystone::endpoint::runtime {

  if str2bool($::is_controller_active) {
    include ::keystone::endpoint

    include ::sysinv::keystone::auth
    include ::patching::keystone::auth
    include ::nfv::keystone::auth
    include ::fm::keystone::auth

    include ::ceilometer::keystone::auth

    include ::openstack::heat::params
    if $::openstack::heat::params::service_enabled {
      include ::heat::keystone::auth
      include ::heat::keystone::auth_cfn
    }

    include ::neutron::keystone::auth
    include ::nova::keystone::auth
    include ::nova::keystone::auth_placement

    include ::openstack::panko::params
    if $::openstack::panko::params::service_enabled {
      include ::panko::keystone::auth
    }

    include ::openstack::gnocchi::params
    if $::openstack::gnocchi::params::service_enabled {
      include ::gnocchi::keystone::auth
    }

    include ::openstack::cinder::params
    if $::openstack::cinder::params::service_enabled {
      include ::cinder::keystone::auth
    }

    include ::openstack::glance::params
    include ::glance::keystone::auth

    include ::openstack::murano::params
    if $::openstack::murano::params::service_enabled {
      include ::murano::keystone::auth
    }

    include ::openstack::magnum::params
    if $::openstack::magnum::params::service_enabled {
      include ::magnum::keystone::auth
      include ::magnum::keystone::domain
    }

    include ::openstack::ironic::params
    if $::openstack::ironic::params::service_enabled {
      include ::ironic::keystone::auth
    }

    include ::platform::ceph::params
    if $::platform::ceph::params::rgw_enabled {
      include ::platform::ceph::rgw::keystone::auth
    }

    include ::openstack::barbican::params
    if $::openstack::barbican::params::service_enabled {
      include ::barbican::keystone::auth
    }

    if $::platform::params::distributed_cloud_role =='systemcontroller' {
      include ::dcorch::keystone::auth
      include ::dcmanager::keystone::auth
    }

    include ::smapi::keystone::auth

  }
}

class openstack::keystone::upgrade (
  $upgrade_token_cmd,
  $upgrade_url = undef,
  $upgrade_token_file = undef,
) {

  if $::platform::params::init_keystone {
    include ::keystone::db::postgresql
    include ::platform::params
    include ::platform::amqp::params
    include ::platform::network::mgmt::params
    include ::platform::drbd::cgcs::params

    # the unit address is actually the configured default of the loopback address.
    $bind_host = $::platform::network::mgmt::params::controller0_address
    $eng_workers = $::platform::params::eng_workers

    $keystone_key_repo = "${::platform::drbd::cgcs::params::mountpoint}/keystone"

    # TODO(aning): For R5->R6 upgrade, a local keystone fernet keys repository may
    # need to be setup for the local keystone instance on standby controller to
    # service specific upgrade operations, since we need to keep the keys repository
    # in /opt/cgcs/keystone/fernet-keys intact so that service won't fail on active
    # controller during upgrade. Once the upgade finishes, the temparary local
    # fernet keys repository will be deleted.

    # Need to create the parent directory for fernet keys repository
    # This is a workaround to a puppet bug.
    file { $keystone_key_repo:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755'
    }
    -> file { '/etc/keystone/keystone-extra.conf':
      ensure  => present,
      owner   => 'root',
      group   => 'keystone',
      mode    => '0640',
      content => template('openstack/keystone-extra.conf.erb'),
    }
    -> class { '::keystone':
      upgrade_token_cmd     => $upgrade_token_cmd,
      upgrade_token_file    => $upgrade_token_file,
      enable_fernet_setup   => true,
      enable_bootstrap      => false,
      fernet_key_repository => "${keystone_key_repo}/fernet-keys",
      sync_db               => false,
      default_domain        => undef,
      default_transport_url => $::platform::amqp::params::transport_url,
    }

    # Add service account and endpoints for any new R6 services...
    # include ::<new service>::keystone::auth
    # No new services yet...

    # Always remove the upgrade token file after all new
    # services have been added
    file { $upgrade_token_file :
      ensure => absent,
    }

    include ::keystone::client
  }

}
