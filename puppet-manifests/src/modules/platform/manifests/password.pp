class platform::password {

  file { '/etc/pam.d/passwd':
    ensure  => present,
    content => template('platform/pam.passwd.erb'),
  }

  file_line { '/etc/nsswitch.conf add passwd ldap':
    path  => '/etc/nsswitch.conf',
    line  => 'passwd:     files sss ldap',
    match => '^passwd: *files sss',
  }

  file_line { '/etc/nsswitch.conf add shadow ldap':
    path  => '/etc/nsswitch.conf',
    line  => 'shadow:     files sss ldap',
    match => '^shadow: *files sss',
  }

  file_line { '/etc/nsswitch.conf add group ldap':
    path  => '/etc/nsswitch.conf',
    line  => 'group:     files sss ldap',
    match => '^group: *files sss',
  }

  file_line { '/etc/nsswitch.conf add sudoers ldap':
    path  => '/etc/nsswitch.conf',
    line  => 'sudoers:   files ldap',
    match => '^sudoers: *files',
  }

}
