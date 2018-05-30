#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Aug 2016: rebase mitaka
#  Jun 2016: rebase centos
#  Jun 2015: uprev kilo
#  Dec 2014: uprev juno
#  Jul 2014: rename ironic
#  Dec 2013: uprev grizzly, havana
#  Nov 2013: integrate source from https://github.com/stackforge/puppet-sysinv
#

# == Class: sysinv::client
#
# Installs Sysinv python client.
#
# === Parameters
#
# [*ensure*]
#   Ensure state for package. Defaults to 'present'.
#
class sysinv::client(
  $package_ensure = 'present'
) {

  include sysinv::params

  package { 'cgtsclient':
    ensure => $package_ensure,
    name   => $::sysinv::params::client_package,
  }
}
