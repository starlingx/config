# == Class: dcorch::deps
#
#  dcorch anchors and dependency management
#
class dcorch::deps {
  anchor { 'dcorch::install::begin': }
  -> Package<| tag == 'dcorch-package'|>
  ~> anchor { 'dcorch::install::end': }
  -> anchor { 'dcorch::config::begin': }
  -> Dcorch_config<||>
  ~> anchor { 'dcorch::config::end': }
  -> anchor { 'dcorch::db::begin': }
  -> anchor { 'dcorch::db::end': }
  ~> anchor { 'dcorch::dbsync::begin': }
  -> anchor { 'dcorch::dbsync::end': }
  ~> anchor { 'dcorch::service::begin': }
  ~> Service<| tag == 'dcorch-service' |>
  ~> anchor { 'dcorch::service::end': }

  Anchor['dcorch::config::begin']
  -> Dcorch_api_paste_ini<||>
  ~> Anchor['dcorch::config::end']

  Oslo::Db<||> -> Anchor['dcorch::dbsync::begin']

  # Installation or config changes will always restart services.
  Anchor['dcorch::install::end'] ~> Anchor['dcorch::service::begin']
  Anchor['dcorch::config::end']  ~> Anchor['dcorch::service::begin']
}
