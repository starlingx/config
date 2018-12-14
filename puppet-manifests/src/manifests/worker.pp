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
include ::platform::ceph
include ::platform::devices
include ::platform::grub
include ::platform::collectd
include ::platform::filesystem::compute
include ::platform::docker
include ::platform::kubernetes::worker
include ::platform::multipath
include ::platform::client

include ::openstack::client
include ::openstack::neutron
include ::openstack::neutron::agents
include ::openstack::nova
include ::openstack::nova::compute
include ::openstack::nova::compute::pci
include ::openstack::nova::storage
include ::openstack::nova::network
include ::openstack::nova::placement
include ::openstack::ceilometer
include ::openstack::ceilometer::polling

class { '::platform::config::worker::post':
  stage => post,
}

hiera_include('classes')
