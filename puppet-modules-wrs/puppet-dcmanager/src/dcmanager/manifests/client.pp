#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Dec 2017 Creation based off puppet-sysinv
#

# == Class: dcmanager::client
#
# Installs Dcmanager python client.
#
# === Parameters
#
# [*ensure*]
#   Ensure state for package. Defaults to 'present'.
#
class dcmanager::client(
  $package_ensure = 'present'
) {

  include dcmanager::params
  include dcmanager::deps

  package { 'dcmanagerclient':
    ensure => $package_ensure,
    name   => $::dcmanager::params::client_package,
    tag    => 'dcmanager-package',
  }
}
