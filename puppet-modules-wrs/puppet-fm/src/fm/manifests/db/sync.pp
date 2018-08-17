#
# Class to execute "fm-dbsync"
#
# [*user*]
#   (optional) User to run dbsync command.
#   Defaults to 'fm'
#
class fm::db::sync (
  $user = 'fm',
){

  include ::fm::deps

  exec { 'fm-db-sync':
    command     => 'fm-dbsync --config-file /etc/fm/fm.conf',
    path        => '/usr/bin',
    refreshonly => true,
    user        => $user,
    try_sleep   => 5,
    tries       => 10,
    logoutput   => on_failure,
    subscribe   => [
      Anchor['fm::install::end'],
      Anchor['fm::config::end'],
      Anchor['fm::dbsync::begin']
    ],
    notify      => Anchor['fm::dbsync::end'],
  }

}
