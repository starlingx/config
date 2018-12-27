class platform::exports {

  include ::platform::params

  file { '/etc/exports':
    ensure => present,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  -> file_line { '/etc/exports /etc/platform':
    path  => '/etc/exports',
    line  => "/etc/platform\t\t ${::platform::params::mate_ipaddress}(no_root_squash,no_subtree_check,rw)",
    match => '^/etc/platform\s',
  }
  -> exec { 'Re-export filesystems':
    command => 'exportfs -r',
  }
}
