sysinv
=======

#### Table of Contents

1. [Overview - What is the sysinv module?](#overview)
2. [Module Description - What does the module do?](#module-description)
3. [Setup - The basics of getting started with sysinv](#setup)
4. [Implementation - An under-the-hood peek at what the module is doing](#implementation)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
7. [Contributors - Those with commits](#contributors)
8. [Release Notes - Notes on the most recent updates to the module](#release-notes)

Overview
--------

The sysinv module is a part of [Stackforge](https://github.com/stackfoge), an effort by the Openstack infrastructure team to provide continuous integration testing and code review for Openstack and Openstack community projects not part of the core software.  The module its self is used to flexibly configure and manage the block storage service for Openstack.

Module Description
------------------

The sysinv module is a thorough attempt to make Puppet capable of managing the entirety of sysinv.  This includes manifests to provision such things as keystone endpoints, RPC configurations specific to sysinv, and database connections.  Types are shipped as part of the sysinv module to assist in manipulation of configuration files.

This module is tested in combination with other modules needed to build and leverage an entire Openstack software stack.  These modules can be found, all pulled together in the [openstack module](https://github.com/stackfoge/puppet-openstack).

Setup
-----

**What the sysinv module affects**

* sysinv, the block storage service for Openstack.

### Installing sysinv

    example% puppet module install puppetlabs/sysinv

### Beginning with sysinv

To utilize the sysinv module's functionality you will need to declare multiple resources.  The following is a modified excerpt from the [openstack module](https://github.com/stackfoge/puppet-openstack).  This is not an exhaustive list of all the components needed, we recommend you consult and understand the [openstack module](https://github.com/stackforge/puppet-openstack) and the [core openstack](http://docs.openstack.org) documentation.

**Define a sysinv control node**

```puppet
class { '::sysinv':
  sql_connection      => 'mysql://sysinv:secret_block_password@openstack-controller.example.com/sysinv',
  rabbit_password     => 'secret_rpc_password_for_blocks',,
  rabbit_host         => 'openstack-controller.example.com',
  verbose             => true,
}

class { '::sysinv::api':
  keystone_password       => $keystone_password,
  keystone_enabled        => $keystone_enabled,
  keystone_user           => $keystone_user,
  keystone_auth_host      => $keystone_auth_host,
  keystone_auth_port      => $keystone_auth_port,
  keystone_auth_protocol  => $keystone_auth_protocol,
  service_port            => $keystone_service_port,
  package_ensure          => $sysinv_api_package_ensure,
  bind_host               => $sysinv_bind_host,
  enabled                 => $sysinv_api_enabled,
}

class { '::sysinv::scheduler': scheduler_driver => 'sysinv.scheduler.simple.SimpleScheduler', }
```

**Define a sysinv storage node**

```puppet
class { '::sysinv':
  sql_connection      => 'mysql://sysinv:secret_block_password@openstack-controller.example.com/sysinv',
  rabbit_password     => 'secret_rpc_password_for_blocks',,
  rabbit_host         => 'openstack-controller.example.com',
  verbose             => true,
}

class { '::sysinv::volume': }

class { '::sysinv::volume::iscsi': iscsi_ip_address => '10.0.0.2', }
```

Implementation
--------------

### sysinv

sysinv is a combination of Puppet manifest and ruby code to delivery configuration and extra functionality through types and providers.

Limitations
------------

* Setup of storage nodes is limited to Linux and LVM, i.e. Puppet won't configure a Nexenta appliacne but nova can be configured to use the Nexenta driver with Class['sysinv::volume::nexenta'].

Development
-----------

Developer documentation for the entire puppet-openstack project.

* https://wiki.openstack.org/wiki/Puppet-openstack#Developer_documentation

Contributors
------------

* https://github.com/stackforge/puppet-sysinv/graphs/contributors

Release Notes
-------------

**2.1.0**

* Added configuration of Sysinv quotas.
* Added support for NetApp direct driver backend.
* Added support for ceph backend.
* Added support for SQL idle timeout.
* Added support for RabbitMQ clustering with single IP.
* Fixed allowed_hosts/database connection bug.
* Fixed lvm2 setup failure for Ubuntu.
* Removed unnecessary mysql::server dependency.
* Pinned RabbitMQ and database module versions.
* Various lint and bug fixes.

**2.0.0**

* Upstream is now part of stackfoge.
* Nexenta, NFS, and SAN support added as sysinv volume drivers.
* Postgres support added.
* The Apache Qpid and the RabbitMQ message brokers available as RPC backends.
* Configurability of scheduler_driver.
* Various cleanups and bug fixes.
