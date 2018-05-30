#
# puppet manifest for upgrade
#

Exec {
  timeout => 600,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

class { '::platform::params':
  controller_upgrade => true,
}

include ::platform::users::upgrade
include ::platform::postgresql::upgrade
include ::platform::amqp::upgrade

include ::openstack::keystone::upgrade
include ::openstack::client::upgrade

include ::platform::mtce::upgrade

include ::openstack::murano::upgrade
include ::openstack::ironic::upgrade

include ::openstack::nova::upgrade

include ::platform::drbd::upgrade
