class platform::kubernetes::params (
  $enabled = false,
  $pod_network_cidr = undef,
  $apiserver_advertise_address = undef,
  $etcd_endpoint = undef,
  $ca_crt = undef,
  $ca_key = undef,
  $sa_key = undef,
  $sa_pub = undef,
) { }

class platform::kubernetes::kubeadm {
  $repo_file = "[kubernetes]
    name=Kubernetes
    baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
    enabled=1
    gpgcheck=1
    repo_gpgcheck=1
    gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg"
  $iptables_file = "net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1"

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

  # Replace kubelet configuration file.
  file {'/etc/systemd/system/kubelet.service.d/kubeadm.conf':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => "puppet:///modules/${module_name}/kubelet-service-conf"
  } ->

  # Start kubelet.
  service { 'kubelet':
    ensure => 'running',
    enable => true,
  } ->
  # A seperate enable is required since we have modified the service resource
  # to never enable services.
  exec { 'enable-kubelet':
    command => '/usr/bin/systemctl enable kubelet.service',
  }
}

class platform::kubernetes::master::init
  inherits ::platform::kubernetes::params {

  include ::platform::params

  if str2bool($::is_initial_config_primary) {
    # For initial controller install, configure kubernetes from scratch.
    $resolv_conf = '/etc/resolv.conf'

    # Add a DNS server to allow access to kubernetes repo. This will no longer
    # be required once we are using our own internal repo.
    file_line { "${resolv_conf} nameserver 8.8.8.8":
      path => $resolv_conf,
      line => 'nameserver 8.8.8.8',
    } ->

    # Configure the master node.
    file { "/etc/kubernetes/kubeadm.yaml":
      ensure => file,
      content => template('platform/kubeadm.yaml.erb'),
    } ->

    exec { "configure master node":
      command => "kubeadm init --config=/etc/kubernetes/kubeadm.yaml",
      logoutput => true,
    } ->

    # Update ownership/permissions for file created by "kubeadm init".
    # We want it readable by sysinv and wrsroot.
    file { "/etc/kubernetes/admin.conf":
      ensure => file,
      owner  => 'root',
      group  => $::platform::params::protected_group_name,
      mode   => '0640',
    } ->

    # Add a bash profile script to set a k8s env variable
    file {'bash_profile_k8s':
      path    => '/etc/profile.d/kubeconfig.sh',
      ensure  => file,
      mode    => '0644',
      source  => "puppet:///modules/${module_name}/kubeconfig.sh"
    } ->

    # Configure calico networking using the Kubernetes API datastore. This is
    # beta functionality and has this limitation:
    #   Note: Calico networking with the Kubernetes API datastore is beta
    #   because it does not yet support Calico IPAM. It uses host-local IPAM
    #   with Kubernetes pod CIDR assignments instead.
    # See https://docs.projectcalico.org/v3.1/getting-started/kubernetes/
    # installation/calico for more info.
    file { "/etc/kubernetes/rbac-kdd.yaml":
      ensure  => file,
      content => template('platform/rbac-kdd.yaml.erb'),
    } ->
    exec { "configure calico RBAC":
      command =>
        "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/rbac-kdd.yaml",
      logoutput => true,
    } ->
    file { "/etc/kubernetes/calico.yaml":
      ensure  => file,
      content => template('platform/calico.yaml.erb'),
    } ->
    exec { "install calico networking":
      command =>
        "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/calico.yaml",
      logoutput => true,
    } ->

    # Restrict the kube-dns pod to master nodes
    exec { "restrict kube-dns to master nodes":
      command => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment kube-dns -p \'{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/master":""}}}}}\'',
      logoutput => true,
    } ->

    # Remove the taint from the master node
    exec { "remove taint from master node":
      command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf taint node ${::platform::params::hostname} node-role.kubernetes.io/master-",
      logoutput => true,
    }
  } else {
    if str2bool($::is_initial_config) {
      # For subsequent controller installs, install kubernetes using the
      # existing certificates.

      # Create necessary certificate files
      file { "/etc/kubernetes/pki":
        ensure => directory,
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
      } ->
      file { '/etc/kubernetes/pki/ca.crt':
        ensure  => file,
        content => "$ca_crt",
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      } ->
      file { '/etc/kubernetes/pki/ca.key':
        ensure  => file,
        content => "$ca_key",
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      } ->
      file { '/etc/kubernetes/pki/sa.key':
        ensure  => file,
        content => "$sa_key",
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      } ->
      file { '/etc/kubernetes/pki/sa.pub':
        ensure  => file,
        content => "$sa_pub",
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      } ->

      # Configure the master node.
      file { "/etc/kubernetes/kubeadm.yaml":
        ensure  => file,
        content => template('platform/kubeadm.yaml.erb'),
      } ->

      exec { "configure master node":
        command   => "kubeadm init --config=/etc/kubernetes/kubeadm.yaml",
        logoutput => true,
      } ->

      # Update ownership/permissions for file created by "kubeadm init".
      # We want it readable by sysinv and wrsroot.
      file { "/etc/kubernetes/admin.conf":
        ensure => file,
        owner  => 'root',
        group  => $::platform::params::protected_group_name,
        mode   => '0640',
      } ->

      # Add a bash profile script to set a k8s env variable
      file {'bash_profile_k8s':
        path    => '/etc/profile.d/kubeconfig.sh',
        ensure  => present,
        mode    => '0644',
        source  => "puppet:///modules/${module_name}/kubeconfig.sh"
      } ->

      # Restrict the kube-dns pod to master nodes. It seems that each time
      # kubeadm init is run, it undoes any changes to the deployment.
      exec { "restrict kube-dns to master nodes":
        command => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment kube-dns -p \'{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/master":""}}}}}\'',
        logoutput => true,
      } ->

      # Remove the taint from the master node
      exec { "remove taint from master node":
        command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf taint node ${::platform::params::hostname} node-role.kubernetes.io/master-",
        logoutput => true,
      }
    }
  }
}

class platform::kubernetes::master
  inherits ::platform::kubernetes::params {

  if $enabled {
    contain ::platform::kubernetes::kubeadm
    contain ::platform::kubernetes::master::init

    Class['::platform::etcd'] -> Class[$name]
    Class['::platform::docker::config'] -> Class[$name]
    Class['::platform::kubernetes::kubeadm'] ->
    Class['::platform::kubernetes::master::init']
  }
}

class platform::kubernetes::worker::params (
  $join_cmd = undef,
) { }

class platform::kubernetes::worker::init
  inherits ::platform::kubernetes::worker::params {

  Class['::platform::docker::config'] -> Class[$name]

  # Configure the worker node. Only do this once, so check whether the
  # kubelet.conf file has already been created (by the join).
  exec { "configure worker node":
    command => "$join_cmd",
    logoutput => true,
    unless => 'test -f /etc/kubernetes/kubelet.conf',
  }
}

class platform::kubernetes::worker
  inherits ::platform::kubernetes::params {

  # Worker configuration is not required on AIO hosts, since the master
  # will already be configured and includes support for running pods.
  if $enabled and $::personality != 'controller' {
    contain ::platform::kubernetes::kubeadm
    contain ::platform::kubernetes::worker::init

    Class['::platform::kubernetes::kubeadm'] ->
    Class['::platform::kubernetes::worker::init']
  }

  if $enabled {
    file { "/var/run/.disable_compute_services":
      ensure => file,
      replace => no,
    }
  }
}
