#
# puppet manifest for controller hosts
#

Exec {
  timeout => 600,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

#
# Disable the firewall to protect against attempted
# restoration of kubernetes-related iptables rules
# during puppet apply, as kubernetes may not yet
# be running and the restore will fail.
#
class { '::firewall':
  ensure => stopped
}

include ::platform::config
include ::platform::users
include ::platform::sysctl::controller
include ::platform::filesystem::controller
include ::platform::firewall::oam
include ::platform::dhclient
include ::platform::partitions
include ::platform::lvm::controller
include ::platform::network
include ::platform::drbd
include ::platform::exports
include ::platform::dns
include ::platform::ldap::server
include ::platform::ldap::client
include ::platform::password
include ::platform::ntp::server
include ::platform::ptp
include ::platform::lldp
include ::platform::amqp::rabbitmq
include ::platform::postgresql::server
include ::platform::haproxy::server
include ::platform::grub
include ::platform::etcd
include ::platform::docker
include ::platform::dockerdistribution
include ::platform::kubernetes::master
include ::platform::helm

include ::platform::patching
include ::platform::patching::api

include ::platform::remotelogging
include ::platform::remotelogging::proxy

include ::platform::sysinv
include ::platform::sysinv::api
include ::platform::sysinv::conductor

include ::platform::mtce
include ::platform::mtce::agent

include ::platform::memcached

include ::platform::nfv
include ::platform::nfv::api

include ::platform::ceph::controller
include ::platform::ceph::rgw

include ::platform::influxdb
include ::platform::influxdb::logrotate
include ::platform::collectd

include ::platform::fm
include ::platform::fm::api

include ::platform::multipath
include ::platform::client
include ::openstack::keystone
include ::openstack::keystone::api

include ::openstack::horizon

include ::platform::dcmanager
include ::platform::dcmanager::manager

include ::platform::dcorch
include ::platform::dcorch::engine
include ::platform::dcorch::api_proxy
include ::platform::dcmanager::api

include ::platform::dcorch::snmp

include ::platform::smapi

include ::openstack::swift
include ::openstack::swift::api

include ::openstack::barbican
include ::openstack::barbican::api

include ::platform::sm

class { '::platform::config::controller::post':
  stage => post,
}

hiera_include('classes')
