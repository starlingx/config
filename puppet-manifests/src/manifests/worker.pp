#
# puppet manifest for worker nodes
#

Exec {
  timeout => 300,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

include ::platform::config
include ::platform::users
include ::platform::sysctl::compute
include ::platform::dhclient
include ::platform::partitions
include ::platform::lvm::compute
include ::platform::compute
include ::platform::vswitch
include ::platform::network
include ::platform::fstab
include ::platform::password
include ::platform::ldap::client
include ::platform::ntp::client
include ::platform::ptp
include ::platform::lldp
include ::platform::patching
include ::platform::remotelogging
include ::platform::mtce
include ::platform::sysinv
include ::platform::devices
include ::platform::grub
include ::platform::collectd
include ::platform::filesystem::compute
include ::platform::docker
include ::platform::dockerdistribution::compute
include ::platform::kubernetes::worker
include ::platform::multipath
include ::platform::client
include ::platform::ceph::worker
include ::openstack::nova::storage

class { '::platform::config::worker::post':
  stage => post,
}

hiera_include('classes')
