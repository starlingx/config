# TODO (rchurch): Make sure all includes have the correct global scope
class openstack::cinder::params (
  $service_enabled = false,
  $api_port = 8776,
  $api_proxy_port = 28776,
  $region_name = undef,
  $service_name = 'openstack-cinder',
  $service_type = 'volume',
  $service_type_v2 = 'volumev2',
  $service_type_v3 = 'volumev3',
  $configure_endpoint = true,
  $enabled_backends = [],
  $cinder_address = undef,
  $cinder_directory = '/opt/cgcs/cinder',
  $cinder_image_conversion_dir = '/opt/img-conversions/cinder',
  $cinder_device = '',
  $cinder_size = undef,
  $cinder_fs_device = '/dev/drbd4',
  $cinder_vg_name = 'cinder-volumes',
  $drbd_resource = 'drbd-cinder',
  $iscsi_ip_address = undef,
  $is_ceph_external = false,
  # Flag files
  $initial_cinder_config_flag = "${::platform::params::config_path}/.initial_cinder_config_complete",
  $initial_cinder_lvm_config_flag = "${::platform::params::config_path}/.initial_cinder_lvm_config_complete",
  $initial_cinder_ceph_config_flag = "${::platform::params::config_path}/.initial_cinder_ceph_config_complete",
  $node_cinder_lvm_config_flag = '/etc/platform/.node_cinder_lvm_config_complete',
  ) {
  $cinder_disk = regsubst($cinder_device, '-part\d+$', '')

  # Take appropriate actions based on the service states defined by:
  #  - $is_initial_cinder      => first time ever when cinder is configured;
  #  - $is_initial_cinder_lvm  => first time ever when LVM cinder is configured on the system;
  #  - $is_initial_cinder_ceph => first time ever when Ceph cinder is configured on the system;
  #  - $is_node_cinder_lvm     => cinder LVM is configured/reconfigured on a node;
  #  - $is_node_cinder_ceph    => cinder Ceph is configured/reconfigured on a node.
  # These states are dependent on two aspects:
  #  1. A flag file present on the disk either in:
  #     - DRBD synced /opt/platform, for system flags or in
  #     - local folder /etc/platform, for node specific flags
  #  2. Controller standby or active state. Sometimes manifests are applied at the same time on both
  #     controllers with most configuration happenning on the active node and minimal on the standby.
  if $service_enabled {
    # Check if this is the first time we ever configure cinder on this system
    if str2bool($::is_controller_active) and str2bool($::is_initial_cinder_config) {
      $is_initial_cinder = true
    } else {
      $is_initial_cinder = false
    }

    if 'lvm' in $enabled_backends {
      # Check if this is the first time we ever configure LVM on this system
      if str2bool($::is_controller_active) and str2bool($::is_initial_cinder_lvm_config) {
        $is_initial_cinder_lvm = true
      } else {
        $is_initial_cinder_lvm = false
      }
      # Check if we should configure/reconfigure cinder LVM for this node.
      # True in case of node reinstalls, device replacements, reconfigurations etc.
      if str2bool($::is_node_cinder_lvm_config) {
        $is_node_cinder_lvm = true
      } else {
        $is_node_cinder_lvm = false
      }
    } else {
      $is_initial_cinder_lvm = false
      $is_node_cinder_lvm = false
    }

    if 'ceph' in $enabled_backends or $is_ceph_external {
      # Check if this is the first time we ever configure Ceph on this system
      if str2bool($::is_controller_active) and str2bool($::is_initial_cinder_ceph_config) {
        $is_initial_cinder_ceph = true
      } else {
        $is_initial_cinder_ceph = false
      }
    } else {
      $is_initial_cinder_ceph = false
    }
    
    # Cinder needs to be running on initial configuration of either Ceph or LVM
    if str2bool($::is_controller_active) and ($is_initial_cinder_lvm or $is_initial_cinder_ceph) {
      $enable_cinder_service = true
    } else {
      $enable_cinder_service = false
    }

  } else {
    $is_initial_cinder = false
    $is_initial_cinder_lvm = false
    $is_node_cinder_lvm = false
    $is_initial_cinder_ceph = false
    $is_node_cinder_ceph = false
    $enable_cinder_service = false
  }
}


# Called from controller manifest
class openstack::cinder
  inherits ::openstack::cinder::params {

  # TODO (rchurch): This will create the cinder DB on a system that may never run cinder. This make sense?
  #if $is_initial_cinder {
  if $::platform::params::init_database {
    include platform::postgresql::server
    include ::cinder::db::postgresql
  }

  # TODO (rchurch): Make this happen after config_controller? If we do that we should
  # exec 'cinder-manage db sync' as root instead of 'cinder' user
  #if $is_initial_cinder {
  if str2bool($::is_initial_config_primary) {
    include ::cinder::db::sync
  }

  include ::platform::params
  include ::platform::amqp::params

  include ::platform::network::mgmt::params
  $controller_address = $::platform::network::mgmt::params::controller_address

  group { 'cinder':
    ensure => 'present',
    gid    => '165',
  }

  user { 'cinder':
    ensure           => 'present',
    comment          => 'OpenStack Cinder Daemons',
    gid              => '165',
    groups           => ['nobody', 'cinder', $::platform::params::protected_group_name],
    home             => '/var/lib/cinder',
    password         => '!!',
    password_max_age => '-1',
    password_min_age => '-1',
    shell            => '/sbin/nologin',
    uid              => '165',
  }

  if $service_enabled {
    file { "${cinder_directory}":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${cinder_image_conversion_dir}":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${cinder_directory}/data":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
  } else {
    file { "${cinder_directory}":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${cinder_directory}/data":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
  }

  class { '::cinder':
    rabbit_use_ssl        => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
  }

  include ::cinder::keystone::authtoken
  include ::cinder::scheduler
  include ::cinder::client
  include ::cinder::volume
  include ::cinder::ceilometer
  include ::cinder::glance

  include ::openstack::cinder::config
  include ::openstack::cinder::backends

  include ::openstack::cinder::backup
  include ::platform::multipath::params
 
  # TODO(mpeters): move to puppet module formal parameters
  cinder_config {
    'DEFAULT/my_ip': value => $controller_address;
    'DEFAULT/state_path': value => "${cinder_directory}/data";
    # Reduce the number of RPCs that can be handled in parallel from the
    # default of 64. Doing too much at once (e.g. creating volumes) results
    # in a lot of thrashing and operations time out.
    # Liberty renamed this from rpc_thread_pool_size to executor_thread_pool_size
    'DEFAULT/executor_thread_pool_size': value => '32';
    'DEFAULT/enable_force_upload': value => true;
    'DEFAULT/use_multipath_for_image_xfer': value => $::platform::multipath::params::enabled;
    'backend_defaults/use_multipath_for_image_xfer': value => $::platform::multipath::params::enabled;
  }

  # Run cinder-manage to purge deleted rows daily at the 30 minute mark
  cron { 'cinder-purge-deleted':
    ensure      => 'present',
    command     => '/usr/bin/cinder-purge-deleted-active',
    environment => 'PATH=/bin:/usr/bin:/usr/sbin',
    minute      => '30',
    hour        => '*/24',
    user        => 'root',
  }
}


class openstack::cinder::config::default(
  $config_params
) inherits ::openstack::cinder::params {
  # Realize any service parameter provided DEFAULT section params of cinder.conf
  create_resources('cinder_config', hiera_hash('openstack::cinder::config::default::config_params', {}))
}


class openstack::cinder::config
  inherits ::openstack::cinder::params {
    include ::openstack::cinder::config::default
}

class openstack::cinder::backup
  inherits ::openstack::cinder::params {

  # For now only support file backend backup
  include ::cinder::backup::posix
}


class openstack::cinder::backends::san
  inherits ::openstack::cinder::params {
    include ::openstack::cinder::emc_vnx
    include ::openstack::cinder::backends::hpe3par
    include ::openstack::cinder::hpelefthand
  }


class openstack::cinder::backends
  inherits ::openstack::cinder::params {

  class { '::cinder::backends':
    enabled_backends => $enabled_backends
  }

  if 'lvm' in $enabled_backends {
    include ::openstack::cinder::lvm
  }

  if 'ceph' in $enabled_backends or $is_ceph_external {
    include ::openstack::cinder::backends::ceph
  }

  include openstack::cinder::backends::san
}


class openstack::cinder::lvm::filesystem::drbd (
  $device = '/dev/drbd4',
  $lv_name = 'cinder-lv',
  $mountpoint = '/opt/cinder',
  $port = '7792',
  $vg_name = 'cinder-volumes',
  $drbd_handoff = true,
) inherits ::openstack::cinder::params {

  include ::platform::drbd::params
  include ::platform::drbd::cgcs::params

  if str2bool($::is_primary_disk_rotational) {
    $resync_after = $::platform::drbd::cgcs::params::resource_name
  } else {
    $resync_after = undef
  }

  if (str2bool($::is_controller_active) or
    (str2bool($::is_standalone_controller) and $is_node_cinder_lvm)
  ) {
    # Run DRBD cinder initial setup in two cases
    # 1) first time Cinder LVM is configured,
    # 2) when cinder's disk is replaced on a standalone controller
    #    (mostly to accommodate SX disk replacement).
    # Note: Cinder disk replacement is triggered from sysinv by removing
    # the checkpoint file behind is_node_cinder_lvm.
    $ha_primary = true
    $initial_setup = true
    $service_enable = true
    $service_ensure = "running"
  } else {
    $ha_primary = false
    $initial_setup = false
    $service_enable = false
    $service_ensure = "stopped"
  }

  if $is_node_cinder_lvm {

    # prepare disk for drbd
    file { '/etc/udev/mount.blacklist':
      ensure  => present,
      mode    => '0644',
      owner   => 'root',
      group   => 'root',
    } ->
    file_line { 'blacklist ${cinder_disk} automount':
      ensure => present,
      line   => $cinder_disk,
      path   => '/etc/udev/mount.blacklist',
    }
  }

  drbd::resource { $drbd_resource:
    disk          => "\"${cinder_device}\"",
    port          => $port,
    device        => $device,
    mountpoint    => $mountpoint,
    handlers      => {
      before-resync-target =>
        "/usr/local/sbin/sm-notify -s ${drbd_resource} -e sync-start",
      after-resync-target  =>
        "/usr/local/sbin/sm-notify -s ${drbd_resource} -e sync-end",
    },
    host1         => $::platform::drbd::params::host1,
    host2         => $::platform::drbd::params::host2,
    ip1           => $::platform::drbd::params::ip1,
    ip2           => $::platform::drbd::params::ip2,
    manage        => $is_node_cinder_lvm,
    ha_primary    => $ha_primary,
    initial_setup => $initial_setup,
    automount     => $::platform::drbd::params::automount,
    fs_type       => $::platform::drbd::params::fs_type,
    link_util     => $::platform::drbd::params::link_util,
    link_speed    => $::platform::drbd::params::link_speed,
    num_parallel  => $::platform::drbd::params::num_parallel,
    rtt_ms        => $::platform::drbd::params::rtt_ms,
    cpumask       => $::platform::drbd::params::cpumask,
    resync_after  => $resync_after,
    require       => [ Class['::platform::partitions'], File_line['final filter: update lvm global_filter'] ]
  }

  if ($is_initial_cinder_lvm or
    (str2bool($::is_standalone_controller) and $is_node_cinder_lvm)
  ){
    # Recreate cinder-volumes in two cases:
    # 1) first time Cinder LVM is configured,
    # 2) when cinder's disk is replaced on a standalone controller
    #    (mostly to accommodate SX disk replacement).
    # Note: Cinder disk replacement is triggered from sysinv by removing
    # the checkpoint file behind is_node_cinder_lvm.
    physical_volume { $device:
      ensure => present,
      require => Drbd::Resource[$drbd_resource]
    } ->
    volume_group { $vg_name:
      ensure           => present,
      physical_volumes => $device,
    } ->
    # Create an initial LV, because the LVM ocf resource does not work with
    # an empty VG.
    logical_volume { 'anchor-lv':
      ensure          => present,
      volume_group    => $vg_name,
      size            => '1M',
      size_is_minsize => true,
    } ->
    # Deactivate the VG now. If this isn't done, it prevents DRBD from
    # being stopped later by the SM.
    exec { 'Deactivate VG':
      command => "vgchange -a ln ${vg_name}",
    } ->
    # Make sure the primary resource is in the correct state so that on swact to
    # controller-1 sm has the resource in an acceptable state to become managed
    # and primary. But, if this primary is a single controller we will restart
    # SM so keep it primary

    # TODO (rchurch): fix up the drbd_handoff logic.
    exec { 'Set $drbd_resource role':
      command => str2bool($drbd_handoff) ? {true => "drbdadm secondary ${drbd_resource}", default => '/bin/true'},
      unless  => "drbdadm role ${drbd_resource} | egrep '^Secondary'",
    }
  }
}


class openstack::cinder::lvm(
  $lvm_type = 'thin',
) inherits ::openstack::cinder::params {

#  if $::platform::params::system_mode != 'simplex' {
#    include ::openstack::cinder::lvm::filesystem::drbd
#  } else {
#    include ::openstack::cinder::lvm::filesystem::simplex
#  }
  include ::openstack::cinder::lvm::filesystem::drbd

  file_line { 'snapshot_autoextend_threshold':
    path  => '/etc/lvm/lvm.conf',
    match => '^\s*snapshot_autoextend_threshold +=.*',
    line  => '   snapshot_autoextend_threshold = 80',
  }

  file_line { 'snapshot_autoextend_percent':
    path  => '/etc/lvm/lvm.conf',
    match => '^\s*snapshot_autoextend_percent +=.*',
    line  => '   snapshot_autoextend_percent = 20',
  }

  file { "${cinder_directory}/iscsi-target":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => File[$cinder_directory],
  } ->
  file { "${cinder_directory}/iscsi-target/saveconfig.json":
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => '{
                "fabric_modules": [],
                "storage_objects": [],
                "targets": []
                }',
  }

  if $lvm_type == 'thin' {
       $iscsi_lvm_config = {
         'lvm/iscsi_target_flags' => {'value' => 'direct'},
         'lvm/lvm_type' => {'value' => 'thin'},
         'DEFAULT/max_over_subscription_ratio' => {'value' => 1.0}
       }
  } else {
      $iscsi_lvm_config = {
          'lvm/iscsi_target_flags' => {'value' => 'direct'},
          'lvm/lvm_type' => {'value' => 'default'},
          'lvm/volume_clear' => {'value' => 'none'}
        }
  }

  cinder::backend::iscsi { 'lvm':
    iscsi_ip_address => $iscsi_ip_address,
    extra_options =>  $iscsi_lvm_config ,
    volumes_dir => "${cinder_directory}/data/volumes",
  }
}

define openstack::cinder::backend::ceph(
  $backend_enabled = false,
  $backend_name,
  $rbd_user = 'cinder',
  $rbd_pool,
  $rbd_ceph_conf = '/etc/ceph/ceph.conf'
) {

  if $backend_enabled {
    cinder::backend::rbd {$backend_name:
      backend_host => '$host',
      rbd_pool => $rbd_pool,
      rbd_user => $rbd_user,
      rbd_ceph_conf => $rbd_ceph_conf,
    }
  } else {
    cinder_config {
      "${backend_name}/volume_backend_name": ensure => absent;
      "${backend_name}/volume_driver":       ensure => absent;
      "${backend_name}/backend_host":        ensure => absent;
      "${backend_name}/rbd_ceph_conf":       ensure => absent;
      "${backend_name}/rbd_pool":            ensure => absent;
    }
  }
}


class openstack::cinder::backends::ceph (
  $ceph_backend_configs = {}
) inherits ::openstack::cinder::params {
  create_resources('openstack::cinder::backend::ceph', $ceph_backend_configs)
}


class openstack::cinder::emc_vnx(
  $feature_enabled,
  $config_params
) inherits ::openstack::cinder::params {
  create_resources('cinder_config', hiera_hash('openstack::cinder::emc_vnx::config_params', {}))

  if $feature_enabled {
    $scsi_id_ensure = 'link'
  } else {
    $scsi_id_ensure = 'absent'
  }

  #TODO(rchurch): Evaluate this with Pike... Still needed?
  # During creating EMC cinder bootable volume, linuxscsi.py in
  # python2-os-brick-1.1.0-1.el7.noarch invokes "scsi_id" command and
  # fails as "scsi_id" is not in the search PATH.  So create a symlink
  # here.  The fix is already in the later version of os-brick.  We
  # can remove this code when python2-os-brick is upgraded.
  file { '/usr/bin/scsi_id':
    ensure => $scsi_id_ensure,
    owner  => 'root',
    group  => 'root',
    target => '/lib/udev/scsi_id',
  }
}


define openstack::cinder::backend::hpe3par
{
  $hiera_params = "openstack::cinder::${name}::config_params"
  $feature_enabled = "openstack::cinder::${name}::feature_enabled"

  create_resources('cinder_config', hiera_hash($hiera_params, {}))
 
  if $feature_enabled {
    exec {"Including $name configuration":
      path    => [ '/usr/bin', '/usr/sbin', '/bin', '/sbin' ],
      command => "echo Including $name configuration",
    }
  }
}


class openstack::cinder::backends::hpe3par (
  $sections = []
) inherits ::openstack::cinder::params {
  ::openstack::cinder::backend::hpe3par {$sections:}
}


class openstack::cinder::hpelefthand(
  $feature_enabled,
  $config_params
) inherits ::openstack::cinder::params {
  create_resources('cinder_config', hiera_hash('openstack::cinder::hpelefthand::config_params', {}))

  # As HP SANs are addon PS supported options, make sure we have explicit
  # logging showing this is being included when the feature is enabled.
  if $feature_enabled {
    exec {'Including hpelefthand configuration':
      path    => [ '/usr/bin', '/usr/sbin', '/bin', '/sbin' ],
      command => 'echo Including hpelefthand configuration',
    }
  }
}


class openstack::cinder::firewall
  inherits ::openstack::cinder::params {

  if $service_enabled {
    platform::firewall::rule { 'cinder-api':
      service_name => 'cinder',
      ports => $api_port,
    }
  }
}


class openstack::cinder::haproxy
  inherits ::openstack::cinder::params {

  if $service_enabled {
    platform::haproxy::proxy { 'cinder-restapi':
      server_name => 's-cinder',
      public_port => $api_port,
      private_port => $api_port,
    }
  }
}


define openstack::cinder::api::backend(
  $type_enabled = false,
  $type_name,
  $backend_name
) {
  # Run it on the active controller, otherwise the prefetch step tries to query
  # cinder and can fail
  if str2bool($::is_controller_active) {
    if $type_enabled {
      cinder_type { $type_name:
        ensure     => present,
        properties => ["volume_backend_name=${backend_name}"]
      }
    } else {
      cinder_type { $type_name:
        ensure => absent
      }
    }
  }
}


class openstack::cinder::api::backends(
  $ceph_type_configs = {}
) inherits ::openstack::cinder::params {

  # Only include cinder_type the first time an lvm or ceph backend is
  # initialized
  if $is_initial_cinder_lvm {
    ::openstack::cinder::api::backend { 'lvm-store':
      type_enabled => true,
      type_name    => 'iscsi',
      backend_name => 'lvm'
    }
  }

  # Add/Remove any additional cinder ceph tier types
  create_resources('openstack::cinder::api::backend', $ceph_type_configs)

  # Add SAN volume types here when/if required
}


# Called from the controller manifest
class openstack::cinder::api
  inherits ::openstack::cinder::params {

  include ::platform::params
  $api_workers = $::platform::params::eng_workers

  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address

  $upgrade = $::platform::params::controller_upgrade
  if $service_enabled and (str2bool($::is_controller_active) or $upgrade) {
    include ::cinder::keystone::auth
    if $::platform::params::distributed_cloud_role == 'systemcontroller' {
      include ::dcorch::keystone::auth
      include ::platform::dcorch::firewall
      include ::platform::dcorch::haproxy
    }
  }

  class { '::cinder::api':
    bind_host           => $api_host,
    service_workers     => $api_workers,
    sync_db             => $::platform::params::init_database,
    enabled             => str2bool($enable_cinder_service)
  }

  if $::openstack::cinder::params::configure_endpoint {
    include ::openstack::cinder::firewall
    include ::openstack::cinder::haproxy
  }
  if $service_enabled {
    include ::openstack::cinder::api::backends
  }

  class { '::openstack::cinder::pre':
    stage => pre
  }

  class { '::openstack::cinder::post':
    stage => post
  }
}


class openstack::cinder::pre {
  include ::openstack::cinder::params
  $enabled = str2bool($::openstack::cinder::params::enable_cinder_service)
  if $::platform::params::distributed_cloud_role =='systemcontroller' and $enabled {
    # need to enable cinder-api-proxy in order to apply the cinder manifest
    exec { 'Enable Dcorch Cinder API Proxy':
      command => "systemctl enable dcorch-cinder-api-proxy; systemctl start dcorch-cinder-api-proxy",
    }
  }
}


class openstack::cinder::post
  inherits openstack::cinder::params {

  # Ensure that phases are marked as complete
  if $is_initial_cinder {
    file { $initial_cinder_config_flag:
      ensure => present
    }
  }

  if $is_initial_cinder_lvm {
    file { $initial_cinder_lvm_config_flag:
      ensure => present
    }
  }

  if $is_initial_cinder_ceph {
    file { $initial_cinder_ceph_config_flag:
      ensure => present
    }

    # To workaround an upstream bug in rbd code, we need to create
    # an empty file /etc/ceph/ceph.client.None.keyring in order to
    # do cinder backup and restore.
    file { "/etc/ceph/ceph.client.None.keyring":
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }

  if $is_node_cinder_lvm {
    file { $node_cinder_lvm_config_flag:
      ensure => present
    }
  }

  # cinder-api needs to be running in order to apply the cinder manifest,
  # however, it needs to be stopped/disabled to allow SM to manage the service.
  # To allow for the transition it must be explicitly stopped. Once puppet
  # can directly handle SM managed services, then this can be removed.
  exec { 'Disable OpenStack - Cinder API':
    command => "systemctl stop openstack-cinder-api; systemctl disable openstack-cinder-api",
    require => Class['openstack::cinder'],
  }

  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    # stop and disable the cinder api proxy to allow SM to manage the service
    exec { 'Disable Dcorch Cinder API Proxy':
      command => "systemctl stop dcorch-cinder-api-proxy; systemctl disable dcorch-cinder-api-proxy",
      require => Class['openstack::cinder'],
    }
  }
}


class openstack::cinder::reload {
  platform::sm::restart {'cinder-scheduler': }
  platform::sm::restart {'cinder-volume': }
  platform::sm::restart {'cinder-backup': }
  platform::sm::restart {'cinder-api': }
}


# Called for runtime changes
class openstack::cinder::runtime
  inherits ::openstack::cinder::params {

  include ::openstack::cinder
  include ::openstack::cinder::api

  class { '::openstack::cinder::reload':
    stage => post
  }
}


# Called for runtime changes on region
class openstack::cinder::endpoint::runtime {
  if str2bool($::is_controller_active) {
    include ::cinder::keystone::auth
  }
}


# Called for service_parameter runtime changes:
# - Currently cinder.conf only changes
#   - external SAN backend sections
#   - default section changes
class openstack::cinder::service_param::runtime
  inherits ::openstack::cinder::params {
  class { '::cinder::backends':
    enabled_backends => $enabled_backends
  }

  include ::openstack::cinder::config::default
  include ::openstack::cinder::backends::san

  class { '::openstack::cinder::reload':
    stage => post
  }
}


# Called for rbd backend runtime changes
class openstack::cinder::backends::ceph::runtime
  inherits ::openstack::cinder::params {
  class { '::cinder::backends':
    enabled_backends => $enabled_backends
  }

  if $service_enabled {
    include ::openstack::cinder::backends::ceph
    include ::openstack::cinder::api::backends
  }

  class { '::openstack::cinder::reload':
    stage => post
  }
}
