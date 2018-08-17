# == Class: fm::db::postgresql
#
# Class that configures postgresql for fm
# Requires the Puppetlabs postgresql module.
#
# === Parameters
#
# [*password*]
#   (Required) Password to connect to the database.
#
# [*dbname*]
#   (Optional) Name of the database.
#   Defaults to 'fm'.
#
# [*user*]
#   (Optional) User to connect to the database.
#   Defaults to 'fm'.
#
#  [*encoding*]
#    (Optional) The charset to use for the database.
#    Default to undef.
#
#  [*privileges*]
#    (Optional) Privileges given to the database user.
#    Default to 'ALL'
#
# == Dependencies
#
# == Examples
#
# == Authors
#
# == Copyright
#
class fm::db::postgresql(
  $password,
  $dbname     = 'fm',
  $user       = 'fm',
  $encoding   = undef,
  $privileges = 'ALL',
) {

  include ::fm::deps

  ::openstacklib::db::postgresql { 'fm':
    password_hash => postgresql_password($user, $password),
    dbname        => $dbname,
    user          => $user,
    encoding      => $encoding,
    privileges    => $privileges,
  }

  Anchor['fm::db::begin']
  ~> Class['fm::db::postgresql']
  ~> Anchor['fm::db::end']

}
