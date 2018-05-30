#
# puppet manifest for runtime apply of configuration that executes a set of
# tasks that have been identified to execute based on the specific configuration
# change performed.
#

Exec {
  timeout => 300,
  path => '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin:/usr/local/sbin'
}

include ::platform::config

hiera_include('classes')
