#
# puppet manifest for storage hosts
#

Exec {
  timeout => 300,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

include ::platform::config
include ::platform::users
include ::platform::sysctl::storage
include ::platform::dhclient
include ::platform::partitions
include ::platform::lvm::storage
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
include ::platform::grub
include ::platform::collectd
include ::platform::filesystem::storage
include ::platform::docker
include ::platform::ceph::storage

class { '::platform::config::storage::post':
  stage => post,
}

hiera_include('classes')
