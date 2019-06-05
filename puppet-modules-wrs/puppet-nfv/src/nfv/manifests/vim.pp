#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::vim (
  $enabled                  = false,
  $debug_config_file        = '/etc/nfv/vim/debug.ini',
  $debug_handlers           = 'syslog, stdout',
  $debug_syslog_address     = '/dev/log',
  $debug_syslog_facility    = 'user',
  $database_dir             = '/opt/platform/nfv/vim',
  $alarm_namespace          = 'nfv_vim.alarm.handlers.v1',
  $alarm_handlers           = 'File-Storage, Fault-Management',
  $alarm_audit_interval     =  30,
  $alarm_config_file        = '/etc/nfv/nfv_plugins/alarm_handlers/config.ini',
  $event_log_namespace      = 'nfv_vim.event_log.handlers.v1',
  $event_log_handlers       = 'File-Storage, Event-Log-Management',
  $event_log_config_file    ='/etc/nfv/nfv_plugins/event_log_handlers/config.ini',
  $nfvi_namespace           = 'nfv_vim.nfvi.plugins.v1',
  $nfvi_config_file         = '/etc/nfv/nfv_plugins/nfvi_plugins/config.ini',
  $image_plugin_disabled    = false,
  $block_storage_plugin_disabled = false,
  $compute_plugin_disabled  = false,
  $network_plugin_disabled  = false,
  $guest_plugin_disabled    = false,
  $fault_mgmt_plugin_disabled = false,
  $fault_management_pod_disabled = true,
  $vim_rpc_ip               = '127.0.0.1',
  $vim_rpc_port             = 4343,
  $vim_api_ip               = '0.0.0.0',
  $vim_api_port             = 4545,
  $vim_api_rpc_ip           = '127.0.0.1',
  $vim_api_rpc_port         = 0,
  $vim_webserver_ip         = '0.0.0.0',
  $vim_webserver_port       = 32323,
  $vim_webserver_source_dir = '/usr/lib64/python2.7/site-packages/nfv_vim/webserver',
  $instance_max_live_migrate_wait_in_secs = 180,
  $instance_single_hypervisor = false,
  $sw_mgmt_single_controller = false,
) {

  include nfv::params

  nfv_vim_config {
    # Debug Information
    'debug/config_file': value => $debug_config_file;
    'debug/handlers': value => $debug_handlers;
    'debug/syslog_address': value => $debug_syslog_address;
    'debug/syslog_facility': value => $debug_syslog_facility;

    # Database
    'database/database_dir': value => $database_dir;

    # Alarm
    'alarm/namespace': value => $alarm_namespace;
    'alarm/handlers': value => $alarm_handlers;
    'alarm/audit_interval': value => $alarm_audit_interval;
    'alarm/config_file': value => $alarm_config_file;

    # Event Log
    'event-log/namespace': value => $event_log_namespace;
    'event-log/handlers': value => $event_log_handlers;
    'event-log/config_file': value => $event_log_config_file;

    # NFVI
    'nfvi/namespace': value => $nfvi_namespace;
    'nfvi/config_file': value => $nfvi_config_file;
    'nfvi/image_plugin_disabled': value => $image_plugin_disabled;
    'nfvi/block_storage_plugin_disabled': value => $block_storage_plugin_disabled;
    'nfvi/compute_plugin_disabled': value => $compute_plugin_disabled;
    'nfvi/network_plugin_disabled': value => $network_plugin_disabled;
    'nfvi/guest_plugin_disabled': value => $guest_plugin_disabled;
    'nfvi/fault_mgmt_plugin_disabled': value => $fault_mgmt_plugin_disabled;
    # This flag is used to disable raising alarm to containerized fm
    # and will be removed in future.
    'nfvi/fault_management_pod_disabled': value => $fault_management_pod_disabled;

    # INSTANCE CONFIGURATION
    'instance-configuration/max_live_migrate_wait_in_secs': value => $instance_max_live_migrate_wait_in_secs;
    'instance-configuration/single_hypervisor': value => $instance_single_hypervisor;

    # VIM
    'vim/rpc_host': value => $vim_rpc_ip;
    'vim/rpc_port': value => $vim_rpc_port;

    # VIM-API
    'vim-api/host': value => $vim_api_ip;
    'vim-api/port': value => $vim_api_port;
    'vim-api/rpc_host': value => $vim_api_rpc_ip;
    'vim-api/rpc_port': value => $vim_api_rpc_port;

    # VIM-Webserver
    'vim-webserver/host': value => $vim_webserver_ip;
    'vim-webserver/port': value => $vim_webserver_port;
    'vim-webserver/source_dir': value => $vim_webserver_source_dir;

    # SW-MGMT CONFIGURATION
    'sw-mgmt-configuration/single_controller': value => $sw_mgmt_single_controller;
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }
}
