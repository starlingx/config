class platform::kubernetes::params (
  $enabled = false,
  $pod_network_cidr = undef,
  $apiserver_advertise_address = undef,
) { }

class platform::kubernetes::master::init
  inherits ::platform::kubernetes::params {

  Class['::platform::kubernetes::master'] -> Class[$name]

  # This init only needs to be done once. Only controller-0 is supported for
  # now...
  if str2bool($::is_initial_config_primary) {
    $resolv_conf = '/etc/resolv.conf'

    # Add a DNS server to allow access to kubernetes repo. This will no longer
    # be required once we are using our own internal repo.
    file_line { "${resolv_conf} nameserver 8.8.8.8":
      path => $resolv_conf,
      line => 'nameserver 8.8.8.8',
    } ->

    # Configure the master node. May want to use a config file instead of
    # command line parameters.
    exec { "configure master node":
      command => "kubeadm init --pod-network-cidr=$pod_network_cidr --apiserver-advertise-address=$apiserver_advertise_address",
      logoutput => true,
    } ->

    # Configure calico networking. This is just for prototyping - see the
    # following for proper deployment:
    # https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation
    exec { "configure calico networking":
      command =>
        "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/kubeadm/1.7/calico.yaml",
      logoutput => true,
    } ->

    # Remove the taint from the master node
    exec { "remove taint from master node":
      command =>
        "kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/master-",
      logoutput => true,
    }
  }
}

class platform::kubernetes::master
  inherits ::platform::kubernetes::params {

  if $enabled {
    include ::platform::kubernetes::master::init

    Class['::platform::docker::config'] -> Class[$name]
 
    $repo_file = "[kubernetes]
      name=Kubernetes
      baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
      enabled=1
      gpgcheck=1
      repo_gpgcheck=1
      gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg"
    $iptables_file = "net.bridge.bridge-nf-call-ip6tables = 1
      net.bridge.bridge-nf-call-iptables = 1"
    $kubeadm_conf = '/etc/systemd/system/kubelet.service.d/kubeadm.conf'

    # Configure the kubernetes repo to allow us to download docker images for
    # the kubernetes components. This will disappear once we have our own
    # repo.
    file { '/etc/yum.repos.d/kubernetes.repo':
      ensure  => file,
      content => "$repo_file",
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    } ->

    # Update iptables config. This is required based on:
    # https://kubernetes.io/docs/tasks/tools/install-kubeadm
    # This probably belongs somewhere else - initscripts package?
    file { '/etc/sysctl.d/k8s.conf':
      ensure  => file,
      content => "$iptables_file",
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    } ->
    exec { "update kernel parameters for iptables":
      command => "sysctl --system",
    } ->

    # Update kubelet configuration. Should probably just patch the kubelet
    # package to fix these things.
    file_line { "${kubeadm_conf} KUBELET_EXTRA_ARGS":
      path => $kubeadm_conf,
      line => 'Environment="KUBELET_EXTRA_ARGS=--cgroup-driver=cgroupfs"',
      match => '^Environment="KUBELET_EXTRA_ARGS=',
    } ->
    file_line { "${kubeadm_conf} KUBELET_NETWORK_ARGS":
      path => $kubeadm_conf,
      line => 'Environment="KUBELET_NETWORK_ARGS=--network-plugin=cni --cni-conf-dir=/etc/cni/net.d --cni-bin-dir=/opt/cni/bin"',
      match => '^Environment="KUBELET_NETWORK_ARGS=',
    } ->

    # Start kubelet.
    service { 'kubelet':
      ensure => 'running',
      enable => true,
    }
  }
}
