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
include ::platform::etcd::bootstrap

include ::openstack::keystone::bootstrap
include ::openstack::client::bootstrap

include ::platform::sysinv::bootstrap

