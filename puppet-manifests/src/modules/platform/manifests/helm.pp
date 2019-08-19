class platform::helm::repositories::params(
  $source_helm_repos_base_dir = '/opt/platform/helm_charts',
  $target_helm_repos_base_dir = '/www/pages/helm_charts',
  $helm_repositories = [ 'stx-platform', 'starlingx' ],
) {}

define platform::helm::repository (
  $repo_base = undef,
  $repo_port = undef,
  $create = false,
  $primary = false,
) {

  $repo_path = "${repo_base}/${name}"

  if str2bool($create) {
    file {$repo_path:
      ensure  => directory,
      path    => $repo_path,
      owner   => 'www',
      require => User['www'],
    }

    -> exec { "Generate index: ${repo_path}":
      command   => "helm repo index ${repo_path}",
      logoutput => true,
      user      => 'www',
      group     => 'www',
      require   => User['www'],
    }

    $before_relationship = Exec['Stop lighttpd']
    $require_relationship =  [ User['sysadmin'], Exec["Generate index: ${repo_path}"] ]
  } else {
    $before_relationship = undef
    $require_relationship =  User['sysadmin']
  }

  exec { "Adding StarlingX helm repo: ${name}":
    before      => $before_relationship,
    environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf' , 'HOME=/home/sysadmin'],
    command     => "helm repo add ${name} http://127.0.0.1:${repo_port}/helm_charts/${name}",
    logoutput   => true,
    user        => 'sysadmin',
    group       => 'sys_protected',
    require     => $require_relationship
  }
}

class platform::helm::repositories
  inherits ::platform::helm::repositories::params {
  include ::openstack::horizon::params
  include ::platform::users

  Anchor['platform::services']

  -> platform::helm::repository { $helm_repositories:
    repo_base => $target_helm_repos_base_dir,
    repo_port => $::openstack::horizon::params::http_port,
    create    => $::is_initial_config,
    primary   => $::is_initial_config_primary,
  }

  -> exec { 'Updating info of available charts locally from chart repo':
    environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/sysadmin' ],
    command     => 'helm repo update',
    logoutput   => true,
    user        => 'sysadmin',
    group       => 'sys_protected',
    require     => User['sysadmin']
  }
}

class platform::helm
  inherits ::platform::helm::repositories::params {

  include ::platform::docker::params

  file {$target_helm_repos_base_dir:
    ensure  => directory,
    path    => $target_helm_repos_base_dir,
    owner   => 'www',
    require => User['www']
  }

  Drbd::Resource <| |>

  -> file {$source_helm_repos_base_dir:
    ensure  => directory,
    path    => $source_helm_repos_base_dir,
    owner   => 'www',
    require => User['www']
  }

  if (str2bool($::is_initial_config) and $::personality == 'controller') {

    if str2bool($::is_initial_config_primary) {

      if $::platform::docker::params::gcr_registry {
        $gcr_registry = $::platform::docker::params::gcr_registry
      } else {
        $gcr_registry = 'gcr.io'
      }

      if $::platform::docker::params::quay_registry {
        $quay_registry = $::platform::docker::params::quay_registry
      } else {
        $quay_registry = 'quay.io'
      }

      Class['::platform::kubernetes::master']

      -> exec { 'load tiller docker image':
        command   => "docker image pull ${gcr_registry}/kubernetes-helm/tiller:v2.13.1",
        logoutput => true,
      }

      # TODO(tngo): If and when tiller image is upversioned, please ensure armada compatibility as part of the test
      -> exec { 'load armada docker image':
        command   => "docker image pull ${quay_registry}/airshipit/armada:8a1638098f88d92bf799ef4934abe569789b885e-ubuntu_bionic",
        logoutput => true,
      }

      -> exec { 'create service account for tiller':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf create serviceaccount --namespace kube-system tiller',
        logoutput => true,
      }

      -> exec { 'create cluster role binding for tiller service account':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller', # lint:ignore:140chars
        logoutput => true,
      }

      -> exec { 'initialize helm':
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/sysadmin' ],
        command     => "helm init --skip-refresh --service-account tiller --node-selectors \"node-role.kubernetes.io/master\"=\"\" --tiller-image=${gcr_registry}/kubernetes-helm/tiller:v2.13.1  --override spec.template.spec.hostNetwork=true", # lint:ignore:140chars
        logoutput   => true,
        user        => 'sysadmin',
        group       => 'sys_protected',
        require     => User['sysadmin']
      }

      exec { "bind mount ${target_helm_repos_base_dir}":
        command => "mount -o bind -t ext4 ${source_helm_repos_base_dir} ${target_helm_repos_base_dir}",
        require => File[ $source_helm_repos_base_dir, $target_helm_repos_base_dir ]
      }

    } else {

      Class['::platform::kubernetes::master']

      -> exec { 'initialize helm':
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/sysadmin' ],
        command     => 'helm init --skip-refresh --client-only',
        logoutput   => true,
        user        => 'sysadmin',
        group       => 'sys_protected',
        require     => User['sysadmin']
      }
    }

    include ::platform::helm::repositories
    include ::openstack::horizon::params
    $port = $::openstack::horizon::params::http_port

    exec { 'restart lighttpd for helm':
      require   => [File['/etc/lighttpd/lighttpd.conf', $target_helm_repos_base_dir, $source_helm_repos_base_dir],
                    Exec['initialize helm']],
      command   => 'systemctl restart lighttpd.service',
      logoutput => true,
    }

    -> Class['::platform::helm::repositories']
  }
}

class platform::helm::runtime {
  include ::platform::helm::repositories
}
