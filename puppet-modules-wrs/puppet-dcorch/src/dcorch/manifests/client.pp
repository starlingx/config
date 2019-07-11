#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Dec 2017 Creation based off puppet-sysinv
#
#

# == Class: dcorch::client
#
# Installs dcorch python client.
#
# === Parameters
#
# [*ensure*]
#   Ensure state for package. Defaults to 'present'.
#
class dcorch::client(
  $package_ensure = 'present'
) {

  include dcorch::params
  include dcorch::deps

  package { 'dcorchclient':
    ensure => $package_ensure,
    name   => $::dcorch::params::client_package,
    tag    => 'dcorch-package',
  }
}
