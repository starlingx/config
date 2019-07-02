# == Class: dcmanager::deps
#
#  dcmanager anchors and dependency management
#
class dcmanager::deps {
  anchor { 'dcmanager::install::begin': }
  -> Package<| tag == 'dcmanager-package'|>
  ~> anchor { 'dcmanager::install::end': }
  -> anchor { 'dcmanager::config::begin': }
  -> Dcmanager_config<||>
  ~> anchor { 'dcmanager::config::end': }
  -> anchor { 'dcmanager::db::begin': }
  -> anchor { 'dcmanager::db::end': }
  ~> anchor { 'dcmanager::dbsync::begin': }
  -> anchor { 'dcmanager::dbsync::end': }
  ~> anchor { 'dcmanager::service::begin': }
  ~> Service<| tag == 'dcmanager-service' |>
  ~> anchor { 'dcmanager::service::end': }

  Oslo::Db<||> -> Anchor['dcmanager::dbsync::begin']

  # Installation or config changes will always restart services.
  Anchor['dcmanager::install::end'] ~> Anchor['dcmanager::service::begin']
  Anchor['dcmanager::config::end']  ~> Anchor['dcmanager::service::begin']
}
