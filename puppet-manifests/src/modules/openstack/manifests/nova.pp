class openstack::nova::params (
  $nova_api_port = 8774,
  $nova_ec2_port = 8773,
  $placement_port = 8778,
  $nova_novnc_port = 6080,
  $nova_serial_port = 6083,
  $region_name = undef,
  $service_name = 'openstack-nova',
  $service_create = false,
  $configure_endpoint = true,
  $timeout = '55m',
) {
  include ::platform::network::mgmt::params
  include ::platform::network::infra::params

  # migration is performed over the managemet network if configured, otherwise
  # the management network is used
  if $::platform::network::infra::params::interface_name {
    $migration_version = $::platform::network::infra::params::subnet_version
    $migration_ip = $::platform::network::infra::params::interface_address
    $migration_network = $::platform::network::infra::params::subnet_network
    $migration_prefixlen = $::platform::network::infra::params::subnet_prefixlen
  } else {
    $migration_version = $::platform::network::mgmt::params::subnet_version
    $migration_ip = $::platform::network::mgmt::params::interface_address
    $migration_network = $::platform::network::mgmt::params::subnet_network
    $migration_prefixlen = $::platform::network::mgmt::params::subnet_prefixlen
  }

  # NOTE: this variable is used in the sshd_config, and therefore needs to
  # match the Ruby ERB template.
  $nova_migration_subnet = "${migration_network}/${migration_prefixlen}"
}


class openstack::nova {

  include ::platform::params
  include ::platform::amqp::params

  include ::platform::network::mgmt::params
  $metadata_host = $::platform::network::mgmt::params::controller_address

  class { '::nova':
    rabbit_use_ssl  => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
  }

  # User nova is created during python-nova rpm install.
  # Just update it's permissions.
  user { 'nova':
    ensure => 'present',
    groups => ['nova', $::platform::params::protected_group_name],
  }

  # TODO(mpeters): move to nova puppet module as formal parameters
  nova_config {
    'DEFAULT/notification_format': value => 'unversioned';
    'DEFAULT/metadata_host': value => $metadata_host;
  }
}

class openstack::nova::sshd
  inherits ::openstack::nova::params {

  service { 'sshd':
    ensure => 'running',
    enable => true,
  }

  file { "/etc/ssh/sshd_config":
    notify  => Service['sshd'],
    ensure  => 'present' ,
    mode    => '0600',
    owner   => 'root',
    group   => 'root',
    content => template('sshd/sshd_config.erb'),
  }

}

class openstack::nova::controller 
  inherits ::openstack::nova::params {

  include ::platform::params

  if $::platform::params::init_database {
    include ::nova::db::postgresql
    include ::nova::db::postgresql_api
  }

  include ::nova::pci
  include ::nova::scheduler
  include ::nova::scheduler::filter
  include ::nova::compute::ironic
  include ::nova::compute::serial

  include ::openstack::nova::sshd

  # TODO(mpeters): move to nova puppet module as formal parameters
  nova_config{
    'metrics/required': value => false;
  }

  class { '::nova::conductor':
    workers => $::platform::params::eng_workers_by_2,
  }

  # Run nova-manage to purge deleted rows daily at 15 minute mark
  cron { 'nova-purge-deleted':
    ensure  => 'present',
    command => '/usr/bin/nova-purge-deleted-active',
    environment => 'PATH=/bin:/usr/bin:/usr/sbin',
    minute  => '15',
    hour    => '*/24',
    user    => 'root',
  }
}


class openstack::nova::compute (
  $ssh_keys,
  $host_private_key,
  $host_public_key,
  $host_public_header,
  $host_key_type,
  $migration_private_key,
  $migration_public_key,
  $migration_key_type,
  $compute_monitors,
  $iscsi_initiator_name = undef,
) inherits ::openstack::nova::params {
  include ::nova::pci
  include ::platform::params

  include ::platform::network::mgmt::params
  include ::platform::network::infra::params
  include ::platform::multipath::params
  include ::nova::keystone::authtoken
  include ::nova::compute::neutron

  include ::openstack::nova::sshd

  $host_private_key_file = $host_key_type ? {
    'ssh-rsa'   => "/etc/ssh/ssh_host_rsa_key",
    'ssh-dsa'   => "/etc/ssh/ssh_host_dsa_key",
    'ssh-ecdsa' => "/etc/ssh/ssh_host_ecdsa_key",
    default     => undef
  }

  if ! $host_private_key_file {
    fail("Unable to determine name of private key file. Type specified was '${host_key_type}' but should be one of: ssh-rsa, ssh-dsa, ssh-ecdsa.")
  }

  $host_public_key_file = $host_key_type ? {
    'ssh-rsa'   => "/etc/ssh/ssh_host_rsa_key.pub",
    'ssh-dsa'   => "/etc/ssh/ssh_host_dsa_key.pub",
    'ssh-ecdsa' => "/etc/ssh/ssh_host_ecdsa_key.pub",
    default     => undef
  }

  if ! $host_public_key_file {
    fail("Unable to determine name of public key file. Type specified was '${host_key_type}' but should be one of: ssh-rsa, ssh-dsa, ssh-ecdsa.")
  }

  file { '/etc/ssh':
    ensure  => directory,
    mode    => '0700',
    owner   => 'root',
    group   => 'root',
  } ->

  file { $host_private_key_file:
    content => $host_private_key,
    mode    => '0600',
    owner   => 'root',
    group   => 'root',
  } ->

  file { $host_public_key_file:
    content => "${host_public_header} ${host_public_key}",
    mode    => '0644',
    owner   => 'root',
    group   => 'root',
  }

  $migration_private_key_file = $migration_key_type ? {
    'ssh-rsa'   => '/root/.ssh/id_rsa',
    'ssh-dsa'   => '/root/.ssh/id_dsa',
    'ssh-ecdsa' => '/root/.ssh/id_ecdsa',
    default     => undef
  }

  if ! $migration_private_key_file {
    fail("Unable to determine name of private key file. Type specified was '${migration_key_type}' but should be one of: ssh-rsa, ssh-dsa, ssh-ecdsa.")
  }

  $migration_auth_options = [
    "from=\"${nova_migration_subnet}\"",
    "command=\"/usr/bin/nova_authorized_cmds\"" ]

  file { '/root/.ssh':
    ensure  => directory,
    mode    => '0700',
    owner   => 'root',
    group   => 'root',
  } ->

  file { $migration_private_key_file:
    content => $migration_private_key,
    mode    => '0600',
    owner   => 'root',
    group   => 'root',
  } ->

  ssh_authorized_key { 'nova-migration-key-authorization':
    ensure  => present,
    key     => $migration_public_key,
    type    => $migration_key_type,
    user    => 'root',
    require => File['/root/.ssh'],
    options => $migration_auth_options,
  }

  # remove root user's known_hosts as a preventive measure
  # to ensure it doesn't interfere client side authentication
  # during VM migration.
  file { '/root/.ssh/known_hosts':
    ensure  => absent,
  }

  create_resources(sshkey, $ssh_keys, {})

  class { '::nova::compute':
    vncserver_proxyclient_address => $::platform::params::hostname,
  }

  if str2bool($::is_virtual) {
    # check that we actually support KVM virtualization
    $kvm_exists = inline_template("<% if File.exists?('/dev/kvm') -%>true<% else %>false<% end -%>")
    if $::virtual == 'kvm' and str2bool($kvm_exists) {
      $libvirt_virt_type = 'kvm'
    } else {
      $libvirt_virt_type = 'qemu'
    }
  } else {
    $libvirt_virt_type = 'kvm'
  }

  $libvirt_vnc_bind_host = $migration_version ? {
    4 => '0.0.0.0',
    6  => '::0',
  }

  include ::openstack::glance::params
  if "rbd" in $::openstack::glance::params::enabled_backends {
      $libvirt_inject_partition = "-2"
      $libvirt_images_type = "rbd"
  } else {
      $libvirt_inject_partition = "-1"
      $libvirt_images_type = "default"
  }

  class { '::nova::compute::libvirt':
    libvirt_virt_type => $libvirt_virt_type,
    vncserver_listen => $libvirt_vnc_bind_host,
    libvirt_inject_partition => $libvirt_inject_partition,
  }

  # TODO(mpeters): convert hard coded config values to hiera class parameters
  nova_config {
    'DEFAULT/my_ip': value => $migration_ip;

    'libvirt/libvirt_images_type': value => $libvirt_images_type;
    'libvirt/live_migration_inbound_addr': value => "${::platform::params::hostname}-infra";
    'libvirt/live_migration_uri': ensure => absent;
    'libvirt/volume_use_multipath': value => $::platform::multipath::params::enabled;

    # enable auto-converge by default
    'libvirt/live_migration_permit_auto_converge': value => "True";

    # Change the nfs mount options to provide faster detection of unclean
    # shutdown (e.g. if controller is powered down).
    "DEFAULT/nfs_mount_options": value => $::platform::params::nfs_mount_options;

    # WRS extension: compute_resource_debug
    "DEFAULT/compute_resource_debug": value => "False";

    # WRS extension: reap running deleted VMs
    "DEFAULT/running_deleted_instance_action": value => "reap";
    "DEFAULT/running_deleted_instance_poll_interval": value => "60";

    # Delete rbd_user, for now
    "DEFAULT/rbd_user": ensure => 'absent';

    # write metadata to a special configuration drive
    "DEFAULT/mkisofs_cmd": value => "/usr/bin/genisoimage";

    # configure metrics
    "DEFAULT/compute_available_monitors":
      value => "nova.compute.monitors.all_monitors";
    "DEFAULT/compute_monitors": value => $compute_monitors;

    # need retries under heavy I/O loads
    "DEFAULT/network_allocate_retries": value => 2;

    # TODO(mpeters): confirm if this is still required - deprecated
    'DEFAULT/volume_api_class':  value => 'nova.volume.cinder.API';

    'DEFAULT/default_ephemeral_format':  value => 'ext4';

    # turn on service tokens
    'service_user/send_service_user_token': value => 'true';
    'service_user/project_name': value => $::nova::keystone::authtoken::project_name;
    'service_user/password': value => $::nova::keystone::authtoken::password;
    'service_user/username': value => $::nova::keystone::authtoken::username;
    'service_user/region_name': value => $::nova::keystone::authtoken::region_name;
    'service_user/auth_url': value => $::nova::keystone::authtoken::auth_url;
    'service_user/user_domain_name': value => $::nova::keystone::authtoken::user_domain_name;
    'service_user/project_domain_name': value => $::nova::keystone::authtoken::project_domain_name;
    'service_user/auth_type': value => 'password';
  }

  file_line {'cgroup_controllers':
      ensure => present,
      path => '/etc/libvirt/qemu.conf',
      line => 'cgroup_controllers = [ "cpu", "cpuacct" ]',
      match => '^cgroup_controllers = .*',
  }

  if $iscsi_initiator_name {
      $initiator_content = "InitiatorName=${iscsi_initiator_name}\n"
      file { "/etc/iscsi/initiatorname.iscsi":
          ensure => 'present',
          owner  => 'root',
          group  => 'root',
          mode   => '0644',
          content => $initiator_content,
      } ->
      exec { "Restart iscsid.service":
          command => "bash -c 'systemctl restart iscsid.service'",
          onlyif => "systemctl status iscsid.service",
      }
  }
}

define openstack::nova::storage::wipe_new_pv {
  $cmd = join(["/sbin/pvs --nosuffix --noheadings ",$name," 2>/dev/null | grep nova-local || true"])
  $result = generate("/bin/sh", "-c", $cmd)
  if $result !~ /nova-local/ {
    exec { "Wipe New PV not in VG - $name":
      provider => shell,
      command => "wipefs -a $name",
      before => Lvm::Volume[instances_lv],
      require => Exec['remove device mapper mapping']
    }
  }
}

define openstack::nova::storage::wipe_pv_and_format {
  if $name !~ /part/ {
    exec { "Wipe removing PV $name":
      provider => shell,
      command => "wipefs -a $name",
      require => File_line[disable_old_lvg_disks]
    } ->
    exec { "GPT format disk PV - $name":
      provider => shell,
      command => "parted -a optimal --script $name -- mktable gpt",
    }
  }
  else {
    exec { "Wipe removing PV $name":
      provider => shell,
      command => "wipefs -a $name",
      require => File_line[disable_old_lvg_disks]
    }
  }
}

class openstack::nova::storage (
  $adding_pvs,
  $removing_pvs,
  $final_pvs,
  $lvm_global_filter = '[]',
  $lvm_update_filter = '[]',
  $instance_backing = 'image',
  $concurrent_disk_operations = 2,
  $images_rbd_pool = 'ephemeral',
  $images_rbd_ceph_conf = '/etc/ceph/ceph.conf'
) {
  $adding_pvs_str = join($adding_pvs," ")
  $removing_pvs_str = join($removing_pvs," ")

  # Ensure partitions update prior to local storage configuration
  Class['::platform::partitions'] -> Class[$name]

  case $instance_backing {
    'image': {
      $images_type = 'default'
      $images_volume_group = absent
      $round_to_extent = false
      $local_monitor_state = 'disabled'
      $images_rbd_pool_real = absent
      $images_rbd_ceph_conf_real = absent
    }
    'remote': {
      $images_type = 'rbd'
      $images_volume_group = absent
      $round_to_extent = false
      $local_monitor_state = 'disabled'
      $images_rbd_pool_real = $images_rbd_pool
      $images_rbd_ceph_conf_real = $images_rbd_ceph_conf
    }
    default: {
      fail("Unsupported instance backing: ${instance_backing}")
    }
  }

  nova_config {
    "DEFAULT/concurrent_disk_operations": value => $concurrent_disk_operations;
  }

  ::openstack::nova::storage::wipe_new_pv { $adding_pvs: }
  ::openstack::nova::storage::wipe_pv_and_format { $removing_pvs: }

  file_line { 'enable_new_lvg_disks':
      path  => '/etc/lvm/lvm.conf',
      line  => "    global_filter = ${lvm_update_filter}",
      match => '^[ ]*global_filter =',
  } ->
  nova_config {
      "libvirt/images_type": value => $images_type;
      "libvirt/images_volume_group": value => $images_volume_group;
      "libvirt/images_rbd_pool": value => $images_rbd_pool_real;
      "libvirt/images_rbd_ceph_conf": value => $images_rbd_ceph_conf_real;
  } ->
  exec { 'umount /var/lib/nova/instances':
    command => 'umount /var/lib/nova/instances; true',
  } ->
  exec { 'umount /dev/nova-local/instances_lv':
    command => 'umount /dev/nova-local/instances_lv; true',
  } ->
  exec { 'remove udev leftovers':
    unless  => 'vgs nova-local',
    command => 'rm -rf /dev/nova-local || true',
  } ->
  exec { 'remove device mapper mapping':
    command => "dmsetup remove /dev/mapper/nova--local-instances_lv || true",
  } ->
  file_line { 'disable_old_lvg_disks':
      path  => '/etc/lvm/lvm.conf',
      line  => "    global_filter = ${lvm_global_filter}",
      match => '^[ ]*global_filter =',
  } ->
  exec { 'add device mapper mapping':
    command => 'lvchange -ay /dev/nova-local/instances_lv || true',
  } ->
  lvm::volume { 'instances_lv':
    ensure => 'present',
    vg => 'nova-local',
    pv => $final_pvs,
    size => 'max',
    round_to_extent => $round_to_extent,
    allow_reduce => true,
    nuke_fs_on_resize_failure => true,
  } ->
  filesystem { '/dev/nova-local/instances_lv':
    ensure  => present,
    fs_type => 'ext4',
    options => '-F -F',
    require => Logical_volume['instances_lv']
  } ->
  file { '/var/lib/nova/instances':
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  } ->
  exec { 'mount /dev/nova-local/instances_lv':
    unless  => 'mount | grep -q /var/lib/nova/instances',
    command => 'mount -t ext4 /dev/nova-local/instances_lv /var/lib/nova/instances',
  }
}


class openstack::nova::network {
  include ::nova::network::neutron
}


class openstack::nova::placement {
  include ::nova::placement
}


class openstack::nova::firewall
  inherits ::openstack::nova::params {

  platform::firewall::rule { 'nova-api-rules':
    service_name => 'nova',
    ports        => $nova_api_port,
  }

  platform::firewall::rule { 'nova-placement-api':
    service_name => 'placement',
    ports        => $placement_port,
  }

  platform::firewall::rule { 'nova-novnc':
    service_name => 'nova-novnc',
    ports        => $nova_novnc_port,
  }

  platform::firewall::rule { 'nova-serial':
    service_name => 'nova-serial',
    ports        => $nova_serial_port,
  }
}


class openstack::nova::haproxy
  inherits ::openstack::nova::params {

  platform::haproxy::proxy { 'nova-restapi':
    server_name => 's-nova',
    public_port => $nova_api_port,
    private_port => $nova_api_port,
  }

  platform::haproxy::proxy { 'placement-restapi':
    server_name => 's-placement',
    public_port => $placement_port,
    private_port => $placement_port,
  }

  platform::haproxy::proxy { 'nova-novnc':
    server_name => 's-nova-novnc',
    public_port => $nova_novnc_port,
    private_port => $nova_novnc_port,
    x_forwarded_proto => false,
  }

  platform::haproxy::proxy { 'nova-serial':
    server_name => 's-nova-serial',
    public_port => $nova_serial_port,
    private_port => $nova_serial_port,
    server_timeout => $timeout,
    client_timeout => $timeout,
    x_forwarded_proto => false,
  }
}


class openstack::nova::api::services
  inherits ::openstack::nova::params {

  include ::nova::pci
  include ::platform::params

  include ::nova::vncproxy
  include ::nova::serialproxy
  include ::nova::consoleauth
  include ::nova_api_proxy::config

  class {'::nova::api':
    sync_db => $::platform::params::init_database,
    sync_db_api => $::platform::params::init_database,
    osapi_compute_workers => $::platform::params::eng_workers,
    metadata_workers => $::platform::params::eng_workers_by_2,
  }
}


class openstack::nova::api
  inherits ::openstack::nova::params {

  include ::platform::params

  if ($::openstack::nova::params::service_create and
      $::platform::params::init_keystone) {
    include ::nova::keystone::auth
    include ::nova::keystone::auth_placement
  }

  include ::openstack::nova::api::services

  if $::openstack::nova::params::configure_endpoint {
    include ::openstack::nova::firewall
    include ::openstack::nova::haproxy
  }
}


class openstack::nova::conductor::reload {
  exec { 'signal-nova-conductor':
    command => "pkill -HUP nova-conductor",
  }
}


class openstack::nova::api::reload {
  platform::sm::restart {'nova-api': }
}


class openstack::nova::controller::runtime {
  include ::openstack::nova
  include ::openstack::nova::controller
  include ::openstack::nova::api::services

  class {'::openstack::nova::api::reload':
    stage => post
  }

  class {'::openstack::nova::conductor::reload':
    stage => post
  }
}


class openstack::nova::api::runtime {

  # both the service configuration and firewall/haproxy needs to be updated
  include ::openstack::nova
  include ::openstack::nova::api
  include ::nova::compute::serial

  class {'::openstack::nova::api::reload':
    stage => post
  }
}


class openstack::nova::compute::pci
(
  $pci_pt_whitelist = [],
  $pci_sriov_whitelist = undef,
) {

  # The pci_passthrough option in the nova::compute class is not sufficient.
  # In particular, it sets the pci_passthrough_whitelist in nova.conf to an
  # empty string if the list is empty, causing the nova-compute process to fail.
  if $pci_sriov_whitelist {
      class { '::nova::compute::pci':
          passthrough => generate("/usr/bin/nova-sriov",
            $pci_pt_whitelist, $pci_sriov_whitelist),
      }
  } else {
      class { '::nova::compute::pci':
          passthrough => $pci_pt_whitelist,
      }
  }
}


class openstack::nova::compute::reload {
  include ::platform::kubernetes::params

  if $::platform::kubernetes::params::enabled != true {
    exec { 'pmon-restart-nova-compute':
      command => "pmon-restart nova-compute",
    }
  }
}


class openstack::nova::compute::runtime {
  include ::openstack::nova
  include ::openstack::nova::compute

  class {'::openstack::nova::compute::reload':
    stage => post
  }
}
