class platform::helm
{
  include ::platform::kubernetes::params
  include ::platform::kubernetes::master

  if $::platform::kubernetes::params::enabled {
    if str2bool($::is_initial_config_primary) {

      Class['::platform::kubernetes::master']

      # TODO(jrichard): Upversion tiller image to v2.11.1 once released.
      -> exec { 'load tiller docker image':
        command   => 'docker image pull gcr.io/kubernetes-helm/tiller:v2.12.1',
        logoutput => true,
      }

      # TODO(tngo): If and when tiller image is upversioned, please ensure armada compatibility as part of the test
      -> exec { 'load armada docker image':
        command   => 'docker image pull quay.io/airshipit/armada:f807c3a1ec727c883c772ffc618f084d960ed5c9',
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

      # TODO(jrichard): Upversion tiller image to v2.11.1 once released.
      -> exec { 'initialize helm':
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf', 'HOME=/home/wrsroot' ],
        command     => 'helm init --skip-refresh --service-account tiller --node-selectors "node-role.kubernetes.io/master"="" --tiller-image=gcr.io/kubernetes-helm/tiller:v2.12.1', # lint:ignore:140chars
        logoutput   => true,
        user        => 'wrsroot',
        group       => 'wrs',
        require     => User['wrsroot']
      }

      -> file {'/www/pages/helm_charts':
        ensure  => directory,
        path    => '/www/pages/helm_charts',
        owner   => 'www',
        require => User['www']
      }

      -> exec { 'restart lighttpd for helm':
        require   => File['/etc/lighttpd/lighttpd.conf'],
        command   => 'systemctl restart lighttpd.service',
        logoutput => true,
      }

      -> exec { 'generate helm repo index':
        command   => 'helm repo index /www/pages/helm_charts',
        logoutput => true,
        user      => 'www',
        group     => 'www',
        require   => User['www']
      }

      -> exec { 'add local starlingx helm repo':
        before      => Exec['Stop lighttpd'],
        environment => [ 'KUBECONFIG=/etc/kubernetes/admin.conf' , 'HOME=/home/wrsroot'],
        command     => 'helm repo add starlingx http://127.0.0.1/helm_charts',
        logoutput   => true,
        user        => 'wrsroot',
        group       => 'wrs',
        require     => User['wrsroot']
      }
    }
  }
}

