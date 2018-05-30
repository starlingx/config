#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Dec 2017 Creation based off puppet-sysinv
#

# Class that configures postgresql for dcorch
#
# Requires the Puppetlabs postgresql module.
# === Parameters
#
# [*password*]
#   (Required) Password to connect to the database.
#
# [*dbname*]
#   (Optional) Name of the database.
#   Defaults to 'dcorch'.
#
# [*user*]
#   (Optional) User to connect to the database.
#   Defaults to 'dcorch'.
#
#  [*encoding*]
#    (Optional) The charset to use for the database.
#    Default to undef.
#
#  [*privileges*]
#    (Optional) Privileges given to the database user.
#    Default to 'ALL'
#
class dcorch::db::postgresql(
  $password,
  $dbname = 'dcorch',
  $user   = 'dcorch',
  $encoding   = undef,
  $privileges = 'ALL',
) {

  ::openstacklib::db::postgresql { 'dcorch':
    password_hash => postgresql_password($user, $password),
    dbname        => $dbname,
    user          => $user,
    encoding      => $encoding,
    privileges    => $privileges,
  }

  ::Openstacklib::Db::Postgresql['dcorch'] ~> Service <| title == 'dcorch-api-proxy' |>
  ::Openstacklib::Db::Postgresql['dcorch'] ~> Service <| title == 'dcorch-engine' |>
  ::Openstacklib::Db::Postgresql['dcorch'] ~> Exec <| title == 'dcorch-dbsync' |>
}
