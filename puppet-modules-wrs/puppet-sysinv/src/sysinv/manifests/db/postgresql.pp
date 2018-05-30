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

# Class that configures postgresql for sysinv
#
# Requires the Puppetlabs postgresql module.
# === Parameters
#
# [*password*]
#   (Required) Password to connect to the database.
#
# [*dbname*]
#   (Optional) Name of the database.
#   Defaults to 'sysinv'.
#
# [*user*]
#   (Optional) User to connect to the database.
#   Defaults to 'sysinv'.
#
#  [*encoding*]
#    (Optional) The charset to use for the database.
#    Default to undef.
#
#  [*privileges*]
#    (Optional) Privileges given to the database user.
#    Default to 'ALL'
#
class sysinv::db::postgresql(
  $password,
  $dbname = 'sysinv',
  $user   = 'sysinv',
  $encoding   = undef,
  $privileges = 'ALL',
) {

  ::openstacklib::db::postgresql { 'sysinv':
    password_hash => postgresql_password($user, $password),
    dbname        => $dbname,
    user          => $user,
    encoding      => $encoding,
    privileges    => $privileges,
  }

  ::Openstacklib::Db::Postgresql['sysinv'] ~> Service <| title == 'sysinv-api' |>
  ::Openstacklib::Db::Postgresql['sysinv'] ~> Service <| title == 'sysinv-conductor' |>
  ::Openstacklib::Db::Postgresql['sysinv'] ~> Exec <| title == 'sysinv-dbsync' |>
}
