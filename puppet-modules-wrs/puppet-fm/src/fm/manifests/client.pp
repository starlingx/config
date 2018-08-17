#
# Installs the fm python client.
#
# == parameters
#  [*ensure*]
#   (optional) Ensure state of the package.
#   Defaults to 'present'.
#
class fm::client (
  $ensure = 'present'
) {

  include ::fm::deps
  include ::fm::params

  package { 'fmclient':
    ensure => $ensure,
    name   => $::fm::params::client_package,
    tag    => 'fmclient',
  }
}

