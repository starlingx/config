#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Dec 2017 Creation based off puppet-sysinv
#

# Class that configures postgresql for dcmanager
#
# Requires the Puppetlabs postgresql module.
# === Parameters
#
# [*password*]
#   (Required) Password to connect to the database.
#
# [*dbname*]
#   (Optional) Name of the database.
#   Defaults to 'dcmanager'.
#
# [*user*]
#   (Optional) User to connect to the database.
#   Defaults to 'dcmanager'.
#
#  [*encoding*]
#    (Optional) The charset to use for the database.
#    Default to undef.
#
#  [*privileges*]
#    (Optional) Privileges given to the database user.
#    Default to 'ALL'
#
class dcmanager::db::postgresql(
  $password,
  $dbname = 'dcmanager',
  $user   = 'dcmanager',
  $encoding   = undef,
  $privileges = 'ALL',
) {

  include dcmanager::deps

  ::openstacklib::db::postgresql { 'dcmanager':
    password_hash => postgresql_password($user, $password),
    dbname        => $dbname,
    user          => $user,
    encoding      => $encoding,
    privileges    => $privileges,
  }

  Anchor['dcmanager::db::begin']
  ~> Class['dcmanager::db::postgresql']
  ~> Anchor['dcmanager::db::end']
}
