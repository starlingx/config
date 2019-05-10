#
# Copyright (c) 2019 StarlingX.
#
# SPDX-License-Identifier: Apache-2.0
#
class platform::pciirqaffinity::params (
  $openstack_enabled,
  $openstack_auth_host,
  $openstack_user_domain,
  $openstack_project_domain,
  $openstack_keyring_service,
  $rabbit_host,
  $rabbit_port,
  $rabbit_userid,
  $rabbit_password,
  $rabbit_virtual_host,
) {}


class platform::pciirqaffinity
  inherits ::platform::pciirqaffinity::params {

  file { '/etc/pci_irq_affinity/config.ini':
    ensure  => 'present',
    replace => true,
    content => template('platform/pci-irq-affinity.conf.erb'),
  }
}


class platform::pciirqaffinity::reload {
  exec {'restart-pciirqaffinity-service':
    command => 'systemctl restart pci-irq-affinity-agent.service',
  }
}


class platform::pciirqaffinity::runtime {
  include ::platform::pciirqaffinity

  class {'::platform::pciirqaffinity::reload':
    stage => post
  }
}
