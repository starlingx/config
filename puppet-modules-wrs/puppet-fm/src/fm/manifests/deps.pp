# == Class: fm::deps
#
#  FM anchors and dependency management
#
class fm::deps {
  # Setup anchors for install, config and service phases of the module.  These
  # anchors allow external modules to hook the begin and end of any of these
  # phases.  Package or service management can also be replaced by ensuring the
  # package is absent or turning off service management and having the
  # replacement depend on the appropriate anchors.  When applicable, end tags
  # should be notified so that subscribers can determine if installation,
  # config or service state changed and act on that if needed.
  anchor { 'fm::install::begin': }
  -> Package<| tag == 'fm-package'|>
  ~> anchor { 'fm::install::end': }
  -> anchor { 'fm::config::begin': }
  -> Fm_config<||>
  ~> anchor { 'fm::config::end': }
  -> anchor { 'fm::db::begin': }
  -> anchor { 'fm::db::end': }
  ~> anchor { 'fm::dbsync::begin': }
  -> anchor { 'fm::dbsync::end': }
  ~> anchor { 'fm::service::begin': }
  ~> Service<| tag == 'fm-service' |>
  ~> anchor { 'fm::service::end': }

  # api paste ini config should occur in the config block also.
  Anchor['fm::config::begin']
  -> Fm_api_paste_ini<||>
  ~> Anchor['fm::config::end']

  # all db settings should be applied and all packages should be installed
  # before dbsync starts
  Oslo::Db<||> -> Anchor['fm::dbsync::begin']

  # Installation or config changes will always restart services.
  Anchor['fm::install::end'] ~> Anchor['fm::service::begin']
  Anchor['fm::config::end']  ~> Anchor['fm::service::begin']
}

