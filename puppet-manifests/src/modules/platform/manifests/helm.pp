class platform::helm::repository::params(
  $source_helm_repo_dir = '/opt/cgcs/helm_charts',
  $target_helm_repo_dir = '/www/pages/helm_charts',
) {}

class platform::helm
  inherits ::platform::helm::repository::params {

  include ::platform::docker::params

  file {$source_helm_repo_dir:
    ensure  => directory,
    path    => $source_helm_repo_dir,
    owner   => 'www',
    require => User['www']
  }

  -> file {$target_helm_repo_dir:
    ensure  => directory,
    path    => $target_helm_repo_dir,
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
        command   => "docker image pull ${quay_registry}/airshipit/armada:af8a9ffd0873c2fbc915794e235dbd357f2adab1",
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
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/wrsroot' ],
        command     => "helm init --skip-refresh --service-account tiller --node-selectors \"node-role.kubernetes.io/master\"=\"\" --tiller-image=${gcr_registry}/kubernetes-helm/tiller:v2.13.1", # lint:ignore:140chars
        logoutput   => true,
        user        => 'wrsroot',
        group       => 'wrs',
        require     => User['wrsroot']
      }

      exec { "bind mount ${target_helm_repo_dir}":
        command => "mount -o bind -t ext4 ${source_helm_repo_dir} ${target_helm_repo_dir}",
        require => Exec['add local starlingx helm repo']
      }
      # it needs to create the index file after the bind mount, otherwise
      # helm repo could not be updated until application-upload adds index
      -> exec { 'generate helm repo index on source':
        command   => "helm repo index ${source_helm_repo_dir}",
        logoutput => true,
        user      => 'www',
        group     => 'www',
        require   => User['www']
      }

    } else {

      Class['::platform::kubernetes::master']

      -> exec { 'initialize helm':
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/wrsroot' ],
        command     => 'helm init --skip-refresh --client-only',
        logoutput   => true,
        user        => 'wrsroot',
        group       => 'wrs',
        require     => User['wrsroot']
      }
    }

    include ::openstack::horizon::params
    $port = $::openstack::horizon::params::http_port
    exec { 'restart lighttpd for helm':
      require   => [File['/etc/lighttpd/lighttpd.conf', $target_helm_repo_dir], Exec['initialize helm']],
      command   => 'systemctl restart lighttpd.service',
      logoutput => true,
    }

    -> exec { 'generate helm repo index on target':
      command   => "helm repo index ${target_helm_repo_dir}",
      logoutput => true,
      user      => 'www',
      group     => 'www',
      require   => User['www']
    }

    -> exec { 'add local starlingx helm repo':
      before      => Exec['Stop lighttpd'],
      environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf' , 'HOME=/home/wrsroot'],
      command     => "helm repo add starlingx http://127.0.0.1:${port}/helm_charts",
      logoutput   => true,
      user        => 'wrsroot',
      group       => 'wrs',
      require     => User['wrsroot']
    }
  }
}

class platform::helm::runtime
{
  include ::platform::users

  include ::openstack::horizon::params
  $port = $::openstack::horizon::params::http_port

  exec { 'update local starlingx helm repo':
    environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf' , 'HOME=/home/wrsroot'],
    command     => "helm repo add starlingx http://127.0.0.1:${port}/helm_charts",
    logoutput   => true,
    user        => 'wrsroot',
    group       => 'wrs',
    require     => User['wrsroot']
  }
}
