#
# puppet manifest for controller initial bootstrap
#

Exec {
  timeout => 600,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

include ::platform::config::bootstrap
include ::platform::users::bootstrap
include ::platform::ldap::bootstrap
include ::platform::drbd::bootstrap
include ::platform::postgresql::bootstrap
include ::platform::amqp::bootstrap

include ::openstack::keystone::bootstrap
include ::openstack::barbican::bootstrap
include ::platform::client::bootstrap

include ::platform::sysinv::bootstrap

# Puppet classes to enable the bring up of kubernetes master
include ::platform::docker::bootstrap
include ::platform::etcd::bootstrap

# Puppet classes to enable initial controller unlock
include ::platform::drbd::dockerdistribution::bootstrap
include ::platform::filesystem::backup
include ::platform::mtce::bootstrap
include ::platform::fm::bootstrap
