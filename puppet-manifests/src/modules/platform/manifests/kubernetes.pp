class platform::kubernetes::params (
  $enabled = true,
  $pod_network_cidr = undef,
  $service_network_cidr = undef,
  $apiserver_advertise_address = undef,
  $etcd_endpoint = undef,
  $service_domain = undef,
  $dns_service_ip = undef,
  $ca_crt = undef,
  $ca_key = undef,
  $sa_key = undef,
  $sa_pub = undef,
) { }

class platform::kubernetes::kubeadm {
  include ::platform::docker::params

  $iptables_file = "net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1"

  if $::platform::docker::params::k8s_registry {
    $k8s_registry = $::platform::docker::params::k8s_registry
  } else {
    $k8s_registry = undef
  }

  # kubelet use --pod-infra-container-image to indentify the specified image
  # TODO: this is not needed after kubernetes upgraded to 1.13
  #       because the imageRepository setting will be used
  if $k8s_registry {
    file { '/etc/sysconfig/kubelet':
      ensure  => file,
      content => template('platform/kubelet.conf.erb'),
    }
  }

  # Update iptables config. This is required based on:
  # https://kubernetes.io/docs/tasks/tools/install-kubeadm
  # This probably belongs somewhere else - initscripts package?
  file { '/etc/sysctl.d/k8s.conf':
    ensure  => file,
    content => $iptables_file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }
  -> exec { 'update kernel parameters for iptables':
    command => 'sysctl --system',
  }

  # Create manifests directory required by kubelet
  -> file { '/etc/kubernetes/manifests':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  # Start kubelet.
  -> service { 'kubelet':
    enable => true,
  }
  # A seperate enable is required since we have modified the service resource
  # to never enable services.
  -> exec { 'enable-kubelet':
    command => '/usr/bin/systemctl enable kubelet.service',
  }
}

class platform::kubernetes::master::init
  inherits ::platform::kubernetes::params {

  include ::platform::params
  include ::platform::docker::params

  # This is used for imageRepository in template kubeadm.yaml.erb
  if $::platform::docker::params::k8s_registry {
    $k8s_registry = $::platform::docker::params::k8s_registry
  } else {
    $k8s_registry = undef
  }

  # This is used for calico image in template calico.yaml.erb
  if $::platform::docker::params::quay_registry {
    $quay_registry = $::platform::docker::params::quay_registry
  } else {
    $quay_registry = 'quay.io'
  }

  if str2bool($::is_initial_config_primary) {
    # For initial controller install, configure kubernetes from scratch.
    $resolv_conf = '/etc/resolv.conf'

    # Configure the master node.
    file { '/etc/kubernetes/kubeadm.yaml':
      ensure  => file,
      content => template('platform/kubeadm.yaml.erb'),
    }

    -> exec { 'configure master node':
      command   => 'kubeadm init --config=/etc/kubernetes/kubeadm.yaml',
      logoutput => true,
    }

    # Update ownership/permissions for file created by "kubeadm init".
    # We want it readable by sysinv and wrsroot.
    -> file { '/etc/kubernetes/admin.conf':
      ensure => file,
      owner  => 'root',
      group  => $::platform::params::protected_group_name,
      mode   => '0640',
    }

    # Add a bash profile script to set a k8s env variable
    -> file {'bash_profile_k8s':
      ensure => file,
      path   => '/etc/profile.d/kubeconfig.sh',
      mode   => '0644',
      source => "puppet:///modules/${module_name}/kubeconfig.sh"
    }

    # Configure calico networking using the Kubernetes API datastore. This is
    # beta functionality and has this limitation:
    #   Note: Calico networking with the Kubernetes API datastore is beta
    #   because it does not yet support Calico IPAM. It uses host-local IPAM
    #   with Kubernetes pod CIDR assignments instead.
    # See https://docs.projectcalico.org/v3.2/getting-started/kubernetes/
    # installation/calico for more info.
    -> file { '/etc/kubernetes/rbac-kdd.yaml':
      ensure  => file,
      content => template('platform/rbac-kdd.yaml.erb'),
    }
    -> exec { 'configure calico RBAC':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/rbac-kdd.yaml',
      logoutput => true,
    }
    -> file { '/etc/kubernetes/calico.yaml':
      ensure  => file,
      content => template('platform/calico.yaml.erb'),
    }
    -> exec { 'install calico networking':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/calico.yaml',
      logoutput => true,
    }

    # kubernetes 1.12 uses coredns rather than kube-dns.
    # Restrict the dns pod to master nodes
    -> exec { 'restrict coredns to master nodes':
      command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/master":""}}}}}\'', # lint:ignore:140chars
      logoutput => true,
    }

    -> exec { 'Use anti-affinity for coredns pods':
      command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"k8s-app","operator":"In","values":["kube-dns"]}]},"topologyKey":"kubernetes.io/hostname"}]}}}}}}\'', # lint:ignore:140chars
      logoutput => true,
    }

    # Remove the taint from the master node
    -> exec { 'remove taint from master node':
      command   => "kubectl --kubeconfig=/etc/kubernetes/admin.conf taint node ${::platform::params::hostname} node-role.kubernetes.io/master- || true", # lint:ignore:140chars
      logoutput => true,
    }

    # Add kubelet service override
    -> file { '/etc/systemd/system/kubelet.service.d/kube-stx-override.conf':
      ensure  => file,
      content => template('platform/kube-stx-override.conf.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    # set kubelet monitored by pmond
    -> file { '/etc/pmon.d/kubelet.conf':
      ensure  => file,
      content => template('platform/kubelet-pmond-conf.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    # Reload systemd
    -> exec { 'perform systemctl daemon reload for kubelet override':
      command   => 'systemctl daemon-reload',
      logoutput => true,
    }
  } else {
    if str2bool($::is_initial_config) {
      # For subsequent controller installs, install kubernetes using the
      # existing certificates.

      # Create necessary certificate files
      file { '/etc/kubernetes/pki':
        ensure => directory,
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
      }
      -> file { '/etc/kubernetes/pki/ca.crt':
        ensure  => file,
        content => $ca_crt,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }
      -> file { '/etc/kubernetes/pki/ca.key':
        ensure  => file,
        content => $ca_key,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      }
      -> file { '/etc/kubernetes/pki/sa.key':
        ensure  => file,
        content => $sa_key,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      }
      -> file { '/etc/kubernetes/pki/sa.pub':
        ensure  => file,
        content => $sa_pub,
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
      }

      # Configure the master node.
      -> file { '/etc/kubernetes/kubeadm.yaml':
        ensure  => file,
        content => template('platform/kubeadm.yaml.erb'),
      }

      -> exec { 'configure master node':
        command   => 'kubeadm init --config=/etc/kubernetes/kubeadm.yaml',
        logoutput => true,
      }

      # Update ownership/permissions for file created by "kubeadm init".
      # We want it readable by sysinv and wrsroot.
      -> file { '/etc/kubernetes/admin.conf':
        ensure => file,
        owner  => 'root',
        group  => $::platform::params::protected_group_name,
        mode   => '0640',
      }

      # Add a bash profile script to set a k8s env variable
      -> file {'bash_profile_k8s':
        ensure => present,
        path   => '/etc/profile.d/kubeconfig.sh',
        mode   => '0644',
        source => "puppet:///modules/${module_name}/kubeconfig.sh"
      }

      # kubernetes 1.12 uses coredns rather than kube-dns.
      # Restrict the dns pod to master nodes. It seems that each time
      # kubeadm init is run, it undoes any changes to the deployment.
      -> exec { 'restrict coredns to master nodes':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/master":""}}}}}\'', # lint:ignore:140chars
        logoutput => true,
      }

      -> exec { 'Use anti-affinity for coredns pods':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"k8s-app","operator":"In","values":["kube-dns"]}]},"topologyKey":"kubernetes.io/hostname"}]}}}}}}\'', # lint:ignore:140chars
        logoutput => true,
      }

      # Remove the taint from the master node
      -> exec { 'remove taint from master node':
        command   => "kubectl --kubeconfig=/etc/kubernetes/admin.conf taint node ${::platform::params::hostname} node-role.kubernetes.io/master- || true", # lint:ignore:140chars
        logoutput => true,
      }

      # Add kubelet service override
      -> file { '/etc/systemd/system/kubelet.service.d/kube-stx-override.conf':
        ensure  => file,
        content => template('platform/kube-stx-override.conf.erb'),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }

      # set kubelet monitored by pmond
      -> file { '/etc/pmon.d/kubelet.conf':
        ensure  => file,
        content => template('platform/kubelet-pmond-conf.erb'),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }

      # Reload systemd
      -> exec { 'perform systemctl daemon reload for kubelet override':
        command   => 'systemctl daemon-reload',
        logoutput => true,
      }
    }
  }
}

class platform::kubernetes::master
  inherits ::platform::kubernetes::params {

  contain ::platform::kubernetes::kubeadm
  contain ::platform::kubernetes::master::init
  contain ::platform::kubernetes::firewall

  Class['::platform::etcd'] -> Class[$name]
  Class['::platform::docker::config'] -> Class[$name]
  # Ensure DNS is configured as name resolution is required when
  # kubeadm init is run.
  Class['::platform::dns'] -> Class[$name]
  Class['::platform::kubernetes::kubeadm']
  -> Class['::platform::kubernetes::master::init']
  -> Class['::platform::kubernetes::firewall']
}

class platform::kubernetes::worker::params (
  $join_cmd = undef,
) { }

class platform::kubernetes::worker::init
  inherits ::platform::kubernetes::worker::params {

  Class['::platform::docker::config'] -> Class[$name]

  # Configure the worker node. Only do this once, so check whether the
  # kubelet.conf file has already been created (by the join).
  exec { 'configure worker node':
    command   => $join_cmd,
    logoutput => true,
    unless    => 'test -f /etc/kubernetes/kubelet.conf',
  }

  # Add kubelet service override
  -> file { '/etc/systemd/system/kubelet.service.d/kube-stx-override.conf':
    ensure  => file,
    content => template('platform/kube-stx-override.conf.erb'),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # set kubelet monitored by pmond
  -> file { '/etc/pmon.d/kubelet.conf':
    ensure  => file,
    content => template('platform/kubelet-pmond-conf.erb'),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # Reload systemd
  -> exec { 'perform systemctl daemon reload for kubelet override':
    command   => 'systemctl daemon-reload',
    logoutput => true,
  }
}

class platform::kubernetes::worker
  inherits ::platform::kubernetes::params {

  # Worker configuration is not required on AIO hosts, since the master
  # will already be configured and includes support for running pods.
  if $::personality != 'controller' {
    contain ::platform::kubernetes::kubeadm
    contain ::platform::kubernetes::worker::init

    Class['::platform::kubernetes::kubeadm']
    -> Class['::platform::kubernetes::worker::init']
  }

  file { '/var/run/.disable_worker_services':
    ensure  => file,
    replace => no,
  }
  # TODO: The following exec is a workaround. Once kubernetes becomes the
  # default installation, /etc/pmon.d/libvirtd.conf needs to be removed from
  # the load.
  exec { 'Update PMON libvirtd.conf':
    command => "/bin/sed -i 's#mode  = passive#mode  = ignore #' /etc/pmon.d/libvirtd.conf",
    onlyif  => '/usr/bin/test -e /etc/pmon.d/libvirtd.conf'
  }
}

# TODO: remove port 9001 once we have a public docker image registry using standard ports.
# add 5000 as the default port for private registry
class platform::kubernetes::firewall::params (
  $transport = 'tcp',
  $table = 'nat',
  $dports = [80, 443, 9001, 5000],
  $chain = 'POSTROUTING',
  $jump = 'SNAT',
) {}

class platform::kubernetes::firewall
  inherits ::platform::kubernetes::firewall::params {

  include ::platform::params
  include ::platform::network::oam::params
  include ::platform::network::mgmt::params
  include ::platform::docker::params

  # add http_proxy and https_proxy port to k8s firewall
  # in order to allow worker node access public network via proxy
  if $::platform::docker::params::http_proxy {
    $http_proxy_str_array = split($::platform::docker::params::http_proxy, ':')
    $http_proxy_port = $http_proxy_str_array[length($http_proxy_str_array) - 1]
    if $http_proxy_port =~ /^\d+$/ {
      $http_proxy_port_val = $http_proxy_port
    }
  }

  if $::platform::docker::params::https_proxy {
    $https_proxy_str_array = split($::platform::docker::params::https_proxy, ':')
    $https_proxy_port = $https_proxy_str_array[length($https_proxy_str_array) - 1]
    if $https_proxy_port =~ /^\d+$/ {
      $https_proxy_port_val = $https_proxy_port
    }
  }

  if defined('$http_proxy_port_val') {
    if defined('$https_proxy_port_val') and ($http_proxy_port_val != $https_proxy_port_val) {
      $dports = $dports << $http_proxy_port_val << $https_proxy_port_val
    } else {
      $dports = $dports << $http_proxy_port_val
    }
  } elsif defined('$https_proxy_port_val') {
    $dports = $dports << $https_proxy_port_val
  }

  $system_mode = $::platform::params::system_mode
  $oam_float_ip = $::platform::network::oam::params::controller_address
  $mgmt_subnet = $::platform::network::mgmt::params::subnet_network
  $mgmt_prefixlen = $::platform::network::mgmt::params::subnet_prefixlen

  $s_mgmt_subnet = "${mgmt_subnet}/${mgmt_prefixlen}"
  $d_mgmt_subnet = "! ${s_mgmt_subnet}"

  if $system_mode != 'simplex' {
    firewall { '000 kubernetes nat':
      table       => $table,
      chain       => $chain,
      proto       => $transport,
      jump        => $jump,
      dport       => $dports,
      destination => $d_mgmt_subnet,
      source      => $s_mgmt_subnet,
      tosource    => $oam_float_ip
    }
  }
}
