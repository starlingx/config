class platform::kubernetes::params (
  $enabled = true,
  $node_ip = undef,
  $pod_network_cidr = undef,
  $pod_network_ipversion = 4,
  $service_network_cidr = undef,
  $apiserver_advertise_address = undef,
  $etcd_endpoint = undef,
  $service_domain = undef,
  $dns_service_ip = undef,
  $host_labels = [],
  $ca_crt = undef,
  $ca_key = undef,
  $sa_key = undef,
  $sa_pub = undef,
  $k8s_cpuset = undef,
  $k8s_nodeset = undef,
  $k8s_reserved_cpus = undef,
  $k8s_reserved_mem = undef,
  $apiserver_cert_san = []

) { }

class platform::kubernetes::cgroup::params (
  $cgroup_root = '/sys/fs/cgroup',
  $cgroup_name = 'k8s-infra',
  $controllers = ['cpuset', 'cpu', 'cpuacct', 'memory', 'systemd', 'pids'],
) {}

class platform::kubernetes::cgroup
  inherits ::platform::kubernetes::cgroup::params {
  include ::platform::kubernetes::params

  $k8s_cpuset = $::platform::kubernetes::params::k8s_cpuset
  $k8s_nodeset = $::platform::kubernetes::params::k8s_nodeset

  # Default to float across all cpus and numa nodes
  if !defined('$k8s_cpuset') {
    $k8s_cpuset = generate('/bin/cat', '/sys/devices/system/cpu/online')
    notice("System default cpuset ${k8s_cpuset}.")
  }
  if !defined('$k8s_nodeset') {
    $k8s_nodeset = generate('/bin/cat', '/sys/devices/system/node/online')
    notice("System default nodeset ${k8s_nodeset}.")
  }

  # Create kubelet cgroup for the minimal set of required controllers.
  # NOTE: The kubernetes cgroup_manager_linux func Exists() checks that
  # specific subsystem cgroup paths actually exist on the system. The
  # particular cgroup cgroupRoot must exist for the following controllers:
  # "cpu", "cpuacct", "cpuset", "memory", "systemd", "pids".
  # Reference:
  #  https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/cm/cgroup_manager_linux.go
  # systemd automatically mounts cgroups and controllers, so don't need
  # to do that here.
  notice("Create ${cgroup_root}/${controllers}/${cgroup_name}")
  $controllers.each |String $controller| {
    $cgroup_dir = "${cgroup_root}/${controller}/${cgroup_name}"
    file { $cgroup_dir :
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    # Modify k8s cpuset resources to reflect platform configured cores.
    # NOTE: Using 'exec' here instead of 'file' resource type with 'content'
    # tag to update contents under /sys, since puppet tries to create files
    # with temp names in the same directory, and the kernel only allows
    # specific filenames to be created in these particular directories.
    # This causes puppet to fail if we use the 'content' tag.
    # NOTE: Child cgroups cpuset must be subset of parent. In the case where
    # child directories already exist and we change the parent's cpuset to
    # be a subset of what the children have, will cause the command to fail
    # with "-bash: echo: write error: device or resource busy".
    if $controller == 'cpuset' {
      $cgroup_mems = "${cgroup_dir}/cpuset.mems"
      $cgroup_cpus = "${cgroup_dir}/cpuset.cpus"
      $cgroup_tasks = "${cgroup_dir}/tasks"

      notice("Set ${cgroup_name} nodeset: ${k8s_nodeset}, cpuset: ${k8s_cpuset}")
      File[ $cgroup_dir ]
      -> exec { "Create ${cgroup_mems}" :
        command => "/bin/echo ${k8s_nodeset} > ${cgroup_mems} || :",
      }
      -> exec { "Create ${cgroup_cpus}" :
        command => "/bin/echo ${k8s_cpuset} > ${cgroup_cpus} || :",
      }
      -> file { $cgroup_tasks :
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }
  }
}

class platform::kubernetes::kubeadm {

  include ::platform::docker::params
  include ::platform::kubernetes::params

  $node_ip = $::platform::kubernetes::params::node_ip
  $host_labels = $::platform::kubernetes::params::host_labels
  $k8s_reserved_cpus = $::platform::kubernetes::params::k8s_reserved_cpus
  $k8s_reserved_mem = $::platform::kubernetes::params::k8s_reserved_mem

  $iptables_file = "net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1"

  # Configure kubelet cpumanager options
  if str2bool($::is_worker_subfunction)
    and !('openstack-compute-node'
          in $host_labels) {
    $k8s_cpu_manager_opts = join([
      '--cpu-manager-policy=static',
      '--system-reserved-cgroup=/system.slice',
      join([
        '--system-reserved=',
        "cpu=${k8s_reserved_cpus},",
        "memory=${k8s_reserved_mem}Mi"])
      ], ' ')
  } else {
    $k8s_cpu_manager_opts = '--cpu-manager-policy=none'
  }

  # Enable kubelet extra parameters that are node specific such as
  # cpumanager
  file { '/etc/sysconfig/kubelet':
    ensure  => file,
    content => template('platform/kubelet.conf.erb'),
  }
  # The cpu_manager_state file is regenerated when cpumanager starts or
  # changes allocations so it is safe to remove before kubelet starts.
  # This file persists so cpumanager's DefaultCPUSet becomes inconsistent
  # when we offline/online CPUs or change the number of reserved cpus.
  -> exec { 'remove cpu_manager_state':
    command => 'rm -f /var/lib/kubelet/cpu_manager_state || true',
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

  $apiserver_loopback_address = $pod_network_ipversion ? {
    4 => '127.0.0.1',
    6 => '::1',
  }

  $apiserver_certsans = concat($apiserver_cert_san, $apiserver_loopback_address, $apiserver_advertise_address)

  # This is used for imageRepository in template kubeadm.yaml.erb
  if $::platform::docker::params::k8s_registry {
    $k8s_registry = $::platform::docker::params::k8s_registry
  } else {
    $k8s_registry = 'k8s.gcr.io'
  }

  # This is used for calico image in template calico.yaml.erb
  if $::platform::docker::params::quay_registry {
    $quay_registry = $::platform::docker::params::quay_registry
  } else {
    $quay_registry = 'quay.io'
  }

  # This is used for device plugin images in template multus.yaml.erb,
  # sriov-cni.yaml.erb and sriovdp-daemonset.yaml.erb
  if $::platform::docker::params::docker_registry {
    $docker_registry = $::platform::docker::params::docker_registry
  } else {
    $docker_registry = 'docker.io'
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
    # We want it readable by sysinv and sysadmin.
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

    # Deploy Multus as a Daemonset, and Calico is used as the default network
    # (a network interface that every pod will be created with), each network
    # attachment is made in addition to this default network.
    -> file { '/etc/kubernetes/multus.yaml':
      ensure  => file,
      content => template('platform/multus.yaml.erb'),
    }
    -> exec {'deploy multus daemonset':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/multus.yaml',
      logoutput => true,
    }

    # Configure calico networking using the Kubernetes API datastore.
    -> file { '/etc/kubernetes/calico.yaml':
      ensure  => file,
      content => template('platform/calico.yaml.erb'),
    }
    -> exec { 'install calico networking':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/calico.yaml',
      logoutput => true,
    }

    # Deploy sriov-cni as a Daemonset
    -> file { '/etc/kubernetes/sriov-cni.yaml':
      ensure  => file,
      content => template('platform/sriov-cni.yaml.erb'),
    }
    -> exec {'deploy sriov-cni daemonset':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/sriov-cni.yaml',
      logoutput => true,
    }

    # Deploy SRIOV network device plugin as a Daemonset
    -> file { '/etc/kubernetes/sriovdp-daemonset.yaml':
      ensure  => file,
      content => template('platform/sriovdp-daemonset.yaml.erb'),
    }
    -> exec {'deploy sriov device plugin daemonset':
      command   =>
        'kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/sriovdp-daemonset.yaml',
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

    # Initial kubernetes config done on node
    -> file { '/etc/platform/.initial_k8s_config_complete':
      ensure => present,
    }
  } else {
    if str2bool($::is_initial_k8s_config) {
      # This allows subsequent node installs
      # Notes regarding ::is_initial_k8s_config check:
      # - Ensures block is only run for new node installs (e.g. controller-1)
      #  or reinstalls. This part is needed only once;
      # - Ansible configuration is independently configuring Kubernetes. A retry
      #   in configuration by puppet leads to failed manifest application.
      #   This flag is created by Ansible on controller-0;
      # - Ansible replay is not impacted by flag creation.

      # If alternative k8s registry requires the authentication,
      # kubeadm required images need to be pre-pulled on controller
      if $k8s_registry != 'k8s.gcr.io' and $::platform::docker::params::k8s_registry_secret != undef {
        File['/etc/kubernetes/kubeadm.yaml']
        -> platform::docker::login_registry { 'login k8s registry':
          registry_url    => $k8s_registry,
          registry_secret => $::platform::docker::params::k8s_registry_secret
        }

        -> exec { 'kubeadm to pre pull images':
          command   => 'kubeadm config images pull --config /etc/kubernetes/kubeadm.yaml',
          logoutput => true,
          before    => Exec['configure master node']
        }

        -> exec { 'logout k8s registry':
          command   => "docker logout ${k8s_registry}",
          logoutput => true,
        }
      }

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
      # We want it readable by sysinv and sysadmin.
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

      # Initial kubernetes config done on node
      -> file { '/etc/platform/.initial_k8s_config_complete':
        ensure => present,
      }
    }
  }
}

class platform::kubernetes::master
  inherits ::platform::kubernetes::params {

  contain ::platform::kubernetes::kubeadm
  contain ::platform::kubernetes::cgroup
  contain ::platform::kubernetes::master::init
  contain ::platform::kubernetes::coredns
  contain ::platform::kubernetes::firewall

  Class['::platform::etcd'] -> Class[$name]
  Class['::platform::docker::config'] -> Class[$name]
  # Ensure DNS is configured as name resolution is required when
  # kubeadm init is run.
  Class['::platform::dns'] -> Class[$name]
  Class['::platform::kubernetes::kubeadm']
  -> Class['::platform::kubernetes::cgroup']
  -> Class['::platform::kubernetes::master::init']
  -> Class['::platform::kubernetes::coredns']
  -> Class['::platform::kubernetes::firewall']
}

class platform::kubernetes::worker::params (
  $join_cmd = undef,
) { }

class platform::kubernetes::worker::init
  inherits ::platform::kubernetes::worker::params {

  Class['::platform::docker::config'] -> Class[$name]

  if str2bool($::is_initial_config) {
    include ::platform::params

    if $::platform::docker::params::k8s_registry {
      $k8s_registry = $::platform::docker::params::k8s_registry
    } else {
      $k8s_registry = 'k8s.gcr.io'
    }

    # If alternative k8s registry requires the authentication,
    # k8s pause image needs to be pre-pulled on worker nodes
    if $k8s_registry != 'k8s.gcr.io' and $::platform::docker::params::k8s_registry_secret != undef {
      # Get the pause image tag from kubeadm required images
      # list and replace with alternative k8s registry
      $get_k8s_pause_img = "kubeadm config images list 2>/dev/null |\
        awk '/^k8s.gcr.io\\/pause:/{print \$1}' | sed 's/k8s.gcr.io/${k8s_registry}/'"
      $k8s_pause_img = generate('/bin/sh', '-c', $get_k8s_pause_img)

      if k8s_pause_img {
        platform::docker::login_registry { 'login k8s registry':
          registry_url    => $k8s_registry,
          registry_secret => $::platform::docker::params::k8s_registry_secret
        }

        -> exec { 'load k8s pause image':
          command   => "docker image pull ${k8s_pause_img}",
          logoutput => true,
          before    => Exec['configure worker node']
        }

        -> exec { 'logout k8s registry':
          command   => "docker logout ${k8s_registry}",
          logoutput => true,
        }
      }
    }
  }

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

class platform::kubernetes::worker::pci
(
  $pcidp_network_resources = undef,
) {
  include ::platform::kubernetes::params

  file { '/etc/pcidp':
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  -> file { '/etc/pcidp/config.json':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('platform/pcidp.conf.erb'),
  }
}


class platform::kubernetes::worker
  inherits ::platform::kubernetes::params {

  # Worker configuration is not required on AIO hosts, since the master
  # will already be configured and includes support for running pods.
  if $::personality != 'controller' {
    contain ::platform::kubernetes::kubeadm
    contain ::platform::kubernetes::cgroup
    contain ::platform::kubernetes::worker::init

    Class['::platform::kubernetes::kubeadm']
    -> Class['::platform::kubernetes::cgroup']
    -> Class['::platform::kubernetes::worker::init']
  } else {
    # Reconfigure cgroups cpusets on AIO
    contain ::platform::kubernetes::cgroup

    # Add refresh dependency for kubelet for hugepage allocation
    Class['::platform::compute::allocate']
    ~> service { 'kubelet':
    }
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

  contain ::platform::kubernetes::worker::pci
}

class platform::kubernetes::coredns {

  include ::platform::params

  if str2bool($::is_initial_config_primary) or str2bool($::is_initial_k8s_config) {
    if $::platform::params::system_mode != 'simplex' {
      # For duplex and multi-node system, restrict the dns pod to master nodes
      exec { 'restrict coredns to master nodes':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/master":""}}}}}\'', # lint:ignore:140chars
        logoutput => true,
      }

      -> exec { 'Use anti-affinity for coredns pods':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system patch deployment coredns -p \'{"spec":{"template":{"spec":{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"k8s-app","operator":"In","values":["kube-dns"]}]},"topologyKey":"kubernetes.io/hostname"}]}}}}}}\'', # lint:ignore:140chars
        logoutput => true,
      }
    } else {
      # For simplex system, 1 coredns is enough
      exec { '1 coredns for simplex mode':
        command   => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system scale --replicas=1 deployment coredns', # lint:ignore:140chars
        logoutput => true,
      }
    }
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
  $oam_interface = $::platform::network::oam::params::interface_name
  $mgmt_subnet = $::platform::network::mgmt::params::subnet_network
  $mgmt_prefixlen = $::platform::network::mgmt::params::subnet_prefixlen

  $s_mgmt_subnet = "${mgmt_subnet}/${mgmt_prefixlen}"
  $d_mgmt_subnet = "! ${s_mgmt_subnet}"

  if $system_mode != 'simplex' {
    platform::firewall::rule { 'kubernetes-nat':
      service_name => 'kubernetes',
      table        => $table,
      chain        => $chain,
      proto        => $transport,
      jump         => $jump,
      ports        => $dports,
      host         => $s_mgmt_subnet,
      destination  => $d_mgmt_subnet,
      outiface     => $oam_interface,
      tosource     => $oam_float_ip,
    }
  }
}
