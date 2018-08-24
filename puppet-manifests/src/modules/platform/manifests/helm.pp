class platform::helm
{
  include ::platform::kubernetes::params
  include ::platform::kubernetes::master

  if $::platform::kubernetes::params::enabled {
    if str2bool($::is_initial_config_primary) {

      Class['::platform::kubernetes::master'] ->

      exec { "load tiller docker image":
        command => "docker image pull gcr.io/kubernetes-helm/tiller:v2.9.1",
        logoutput => true,
      } ->

      exec { "create service account for tiller":
        command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf create serviceaccount --namespace kube-system tiller",
        logoutput => true,
      } ->

      exec { "create cluster role binding for tiller service account":
        command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller",
        logoutput => true,
      } ->

      exec { 'initialize helm':
        environment => [ "KUBECONFIG=/etc/kubernetes/admin.conf" ],
        command => "helm init --skip-refresh --service-account tiller",
        logoutput => true,
      }
    }
  }
}

