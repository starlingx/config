class platform::ldap::params (
  $admin_pw,
  $admin_hashed_pw = undef,
  $provider_uri = undef,
  $server_id = undef,
  $ldapserver_remote = false,
  $ldapserver_host = undef,
  $bind_anonymous = false,
) {}

class platform::ldap::server
  inherits ::platform::ldap::params {
  if ! $ldapserver_remote {
    include ::platform::ldap::server::local
  }
}

class platform::ldap::server::local
  inherits ::platform::ldap::params {
  exec { 'slapd-convert-config':
    command => '/usr/sbin/slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/schema/',
    onlyif  => '/usr/bin/test -e /etc/openldap/slapd.conf'
  }

  exec { 'slapd-conf-move-backup':
    command => '/bin/mv -f /etc/openldap/slapd.conf /etc/openldap/slapd.conf.backup',
    onlyif  => '/usr/bin/test -e /etc/openldap/slapd.conf'
  }

  service { 'nscd':
    ensure     => 'running',
    enable     => true,
    name       => 'nscd',
    hasstatus  => true,
    hasrestart => true,
  }

  service { 'openldap':
    ensure     => 'running',
    enable     => true,
    name       => 'slapd',
    hasstatus  => true,
    hasrestart => true,
  }

  exec { 'stop-openldap':
    command => '/usr/bin/systemctl stop slapd.service',
  }

  exec { 'update-slapd-conf':
    command => "/bin/sed -i \\
                          -e 's#provider=ldap.*#provider=${provider_uri}#' \\
                          -e 's:serverID.*:serverID ${server_id}:' \\
                          -e 's:credentials.*:credentials=${admin_pw}:' \\
                          -e 's:^rootpw .*:rootpw ${admin_hashed_pw}:' \\
                          -e 's:modulepath .*:modulepath /usr/lib64/openldap:' \\
                          /etc/openldap/slapd.conf",
    onlyif  => '/usr/bin/test -e /etc/openldap/slapd.conf'
  }

  # don't populate the adminpw if binding anonymously
  if ! $bind_anonymous {
    file { '/usr/local/etc/ldapscripts/ldapscripts.passwd':
      content => $admin_pw,
    }
  }

  file { '/usr/share/cracklib/cracklib-small':
    ensure => link,
    target => '/usr/share/cracklib/cracklib-small.pwd',
  }

  # start openldap with updated config and updated nsswitch
  # then convert slapd config to db format. Note, slapd must have run and created the db prior to this.
  Exec['stop-openldap']
  -> Exec['update-slapd-conf']
  -> Service['nscd']
  -> Service['nslcd']
  -> Service['openldap']
  -> Exec['slapd-convert-config']
  -> Exec['slapd-conf-move-backup']
}


class platform::ldap::client
  inherits ::platform::ldap::params {
  file { '/etc/openldap/ldap.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/ldap.conf.erb'),
  }

  file { '/etc/nslcd.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/nslcd.conf.erb'),
  }
  -> service { 'nslcd':
    ensure     => 'running',
    enable     => true,
    name       => 'nslcd',
    hasstatus  => true,
    hasrestart => true,
  }

  if $::personality == 'controller' {
    file { '/usr/local/etc/ldapscripts/ldapscripts.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/ldapscripts.conf.erb'),
    }
  }
}

class platform::ldap::bootstrap
  inherits ::platform::ldap::params {
  include ::platform::params
  # Local ldap server is configured during bootstrap. It is later
  # replaced by remote ldapserver configuration (if needed) during
  # application of controller / compute / storage manifest.
  include ::platform::ldap::server::local
  include ::platform::ldap::client

  Class['platform::ldap::server::local'] -> Class[$name]

  $dn = 'cn=ldapadmin,dc=cgcs,dc=local'

  exec { 'populate initial ldap configuration':
    command => "ldapadd -D ${dn} -w ${admin_pw} -f /etc/openldap/initial_config.ldif"
  }
  -> exec { 'create ldap admin user':
    command => 'ldapadduser admin root'
  }
  -> exec { 'create ldap operator user':
    command => 'ldapadduser operator users'
  }
  -> exec { 'create ldap protected group':
    command => "ldapaddgroup ${::platform::params::protected_group_name} ${::platform::params::protected_group_id}"
  }
  -> exec { 'add admin to sys_protected protected group' :
    command => "ldapaddusertogroup admin ${::platform::params::protected_group_name}",
  }
  -> exec { 'add operator to sys_protected protected group' :
    command => "ldapaddusertogroup operator ${::platform::params::protected_group_name}",
  }

  # Change operator shell from default to /usr/local/bin/cgcs_cli
  -> file { '/tmp/ldap.cgcs-shell.ldif':
    ensure  => present,
    replace => true,
    source  => "puppet:///modules/${module_name}/ldap.cgcs-shell.ldif"
  }
  -> exec { 'ldap cgcs-cli shell update':
    command =>
      "ldapmodify -D ${dn} -w ${admin_pw} -f /tmp/ldap.cgcs-shell.ldif"
  }
}
