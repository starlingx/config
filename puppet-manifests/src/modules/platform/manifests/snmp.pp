class platform::snmp::params (
  $community_strings = [],
  $trap_destinations = [],
  $system_name = '',
  $system_location = '?',
  $system_contact = '?',
  $system_info = '',
  $software_version = '',
) { }

class platform::snmp::runtime
  inherits ::platform::snmp::params {

  $software_version = $::platform::params::software_version
  $system_info = $::system_info

  file { "/etc/snmp/snmpd.conf":
      ensure => 'present',
      replace => true,
      content => template('platform/snmpd.conf.erb')
  } ->

  # send HUP signal to snmpd if it is running
  exec { 'notify-snmp':
    command => "/usr/bin/pkill -HUP snmpd",
    onlyif => "ps -ef | pgrep snmpd"
  }
}
