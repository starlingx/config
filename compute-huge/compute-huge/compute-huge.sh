#!/bin/bash
################################################################################
# Copyright (c) 2013-2016 Wind River Systems, Inc.
# 
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
# compute-huge.sh
# - mounts hugepages memory backing for libvirt/qemu and vswitch
# - allocates per-NUMA node hugepages values based on compute node
#   topology and memory engineered parameters.
# - IMPORTANT: mount of hugetlbfs must be called after udev is
#   initialized, otherwise libvirt/qemu will not properly recognize
#   the mount as HugeTLBFS.
# - generates /etc/nova/compute_extend.conf which nova-compute reads on init
# - updates grub.conf kernel boot arg parameters based on hugepages and cores

. /usr/bin/tsconfig

# Enable the 'extglob' feature to allow grouping in pattern matching
shopt -s extglob

# Utility functions
LOG_FUNCTIONS=${LOG_FUNCTIONS:-"/etc/init.d/log_functions.sh"}
CPUMAP_FUNCTIONS=${CPUMAP_FUNCTIONS:-"/etc/init.d/cpumap_functions.sh"}
source /etc/init.d/functions
[[ -e ${LOG_FUNCTIONS} ]] && source ${LOG_FUNCTIONS}
[[ -e ${CPUMAP_FUNCTIONS} ]] && source ${CPUMAP_FUNCTIONS}

# Configuration
PRODUCT_NAME=$(dmidecode --string 'system-product-name' 2>/dev/null)
RESERVE_CONF=${RESERVE_CONF:-"/etc/nova/compute_reserved.conf"}
VSWITCH_CONF=${VSWITCH_CONF:-"/etc/vswitch/vswitch.conf"}
linkname=$(readlink -n -f $0)
scriptname=$(basename $linkname)

# Enable debug logs (uncomment)
LOG_DEBUG=1

# Flag file that is touched to signal that it is safe to enable the board
COMPUTE_HUGE_GOENABLED="/var/run/compute_huge_goenabled"

# Flag file that is touched to signal that compute-huge has run at least once
COMPUTE_HUGE_RUN_ONCE="/etc/platform/.compute_huge_run_once"

# Flag file that is touched to indicate that hei host needs a reboot to finish the config
RECONFIG_REBOOT_REQUIRED="/var/run/.reconfig_reboot_required"

# Grub configuration files
GRUB_DEFAULTS=/etc/default/grub
if [ -f /etc/centos-release ] ; then
    GRUB=grub2-mkconfig
    if [ -d /sys/firmware/efi ] ; then
        GRUB_CONFIG=/boot/efi/EFI/centos/grub.cfg
    else
        GRUB_CONFIG=/boot/grub2/grub.cfg
    fi
else
    GRUB=grub-mkconfig
    GRUB_CONFIG=/boot/grub/grub.cfg
fi

# Various globals
declare -i N_CPUS=1
declare -i N_SOCKETS=1
declare -i N_SIBLINGS_IN_PKG=1
declare -i N_CORES_IN_PKG=1
declare -i N_THREADS=1
declare -i N_NUMA=1
declare -i MEMTOTAL_MiB=0
declare -i do_huge=1
declare -i is_reconfig=0

# Disable Broadwell kvm-intel.eptad flag to prevent kernel oops/memory issues.
declare BROADWELL_EPTAD="0" # Broadwell flag kvm-intel.eptad (0=disable, 1=enable)

# NOTE: cgroups currently disabled - this was previously working with DEV 0001,
# however we now get write permission errors. cgroups is supported by libvirt
# to give domain accounting, but is optional. Likely need to re-enable this to
# support performance measurements.
declare -i do_cgroups=0

# Ensure that first configuration doesn't contain stale info,
# clear these fields prior to reading config file.
if [ ! -f ${COMPUTE_HUGE_RUN_ONCE} ]; then
    sed -i "s#^COMPUTE_VM_MEMORY_2M=.*\$#COMPUTE_VM_MEMORY_2M=\(\)#" ${RESERVE_CONF}
    sed -i "s#^COMPUTE_VM_MEMORY_1G=.*\$#COMPUTE_VM_MEMORY_1G=\(\)#" ${RESERVE_CONF}
fi

# Load configuration files (declare arrays that get sourced)
declare -a COMPUTE_PLATFORM_CORES
declare -a COMPUTE_VSWITCH_CORES
declare -a COMPUTE_VSWITCH_MEMORY
declare -a COMPUTE_VM_MEMORY_2M
declare -a COMPUTE_VM_MEMORY_1G
[[ -e ${RESERVE_CONF} ]] && source ${RESERVE_CONF}
[[ -e ${VSWITCH_CONF} ]] && source ${VSWITCH_CONF}
. /etc/platform/platform.conf

################################################################################
# vswitch_cpu_list() - compute the vswitch cpu list, including it's siblings
################################################################################
function vswitch_cpu_list() {
    local CONF_FILE=${VSWITCH_CONF}
    local KEY="VSWITCH_CPU_LIST="

    provision_list=$(curl -sf http://controller:6385/v1/ihosts/${UUID}/icpus/vswitch_cpu_list)
    if [ $? -eq 0 ]; then
       list=`echo ${provision_list} | bc`
       grep ${KEY} ${CONF_FILE} > /dev/null
       if [ $? -ne 0 ]; then
          echo "$KEY\"$list"\" >>  ${CONF_FILE}
       else
          #update vswitch.conf
          sed -i "s/^VSWITCH_CPU_LIST=.*/VSWITCH_CPU_LIST=\"${list}\"/" /etc/vswitch/vswitch.conf
       fi
    else
       list=$(get_vswitch_cpu_list)
    fi
    # Expand vswitch cpulist
    vswitch_cpulist=$(expand_sequence ${list} " ")

    cpulist=""
    for e in $vswitch_cpulist
    do
       # claim hyperthread siblings if SMT enabled
       SIBLINGS_CPULIST=$(cat /sys/devices/system/cpu/cpu${e}/topology/thread_siblings_list 2>/dev/null)
       siblings_cpulist=$(expand_sequence ${SIBLINGS_CPULIST} " ")
       for s in $siblings_cpulist
       do
          in_list ${s} ${cpulist}
          if [ $? -eq 1 ]
          then
              cpulist=$(append_list ${s} ${cpulist})
          fi
       done
    done

    echo "$cpulist"
    return 0
}

################################################################################
# platform_cpu_list() - compute the platform cpu list, including it's siblings
################################################################################
function platform_cpu_list() {
    local CONF_FILE=${RESERVE_CONF}
    local KEY="PLATFORM_CPU_LIST="

    provision_list=$(curl -sf http://controller:6385/v1/ihosts/${UUID}/icpus/platform_cpu_list)
    if [ $? -eq 0 ]; then
       list=`echo ${provision_list} | bc`
       grep ${KEY} ${CONF_FILE} > /dev/null
       if [ $? -ne 0 ]; then
          echo "$KEY\"$list"\" >>  ${CONF_FILE}
       else
          #update compute_reserved.conf
          sed -i "s/^${KEY}.*/${KEY}\"${list}\"/" ${CONF_FILE}
       fi
    else
       list=$(get_platform_cpu_list)
    fi
    # Expand platform cpulist
    platform_cpulist=$(expand_sequence ${list} " ")

    cpulist=""
    for e in $platform_cpulist
    do
       # claim hyperthread siblings if SMT enabled
       SIBLINGS_CPULIST=$(cat /sys/devices/system/cpu/cpu${e}/topology/thread_siblings_list 2>/dev/null)
       siblings_cpulist=$(expand_sequence ${SIBLINGS_CPULIST} " ")
       for s in $siblings_cpulist
       do
          in_list ${s} ${cpulist}
          if [ $? -eq 1 ]
          then
              cpulist=$(append_list ${s} ${cpulist})
          fi
       done
    done

    echo "$cpulist"
    return 0
}

################################################################################
# check_cpu_configuration() - check that the current state of the CPU (e.g.,
# hyperthreading enabled/disabled) matches the expected state that was last
# written to the configuration file.
#
# NOTE: Puppet manifests are generated on unlock via sysinv profile.
#       Config file is updated via manifest (cgcs_vswitch_095).
#
################################################################################
function check_cpu_configuration() {
    local CONFIGURED=$(condense_sequence $(expand_sequence ${COMPUTE_CPU_LIST} " "))
    local ACTUAL="0-$((${N_CPUS} - 1))"
    local INIT="0-1"

    if [ -z "${CONFIGURED}" -o -z "${ACTUAL}" ]; then
       log_error "Unable to compare configured=${CONFIGURED} and actual=${ACTUAL} CPU configurations"
       return 2
    fi

    if [ "${CONFIGURED}" == "${INIT}" ]; then
       log_debug "CPU configuration init: configured=${CONFIGURED} and actual=${ACTUAL}"
       return 0
    fi

    if [ "${CONFIGURED}" != "${ACTUAL}" ]; then
        log_error "CPU configurations mismatched: configured=${CONFIGURED} and actual=${ACTUAL}"
        return 1
    fi

    return 0
}

################################################################################
# check_kernel_boot_args() - check that the kernel boot arguments are in
# agreement with the current set of logical CPU instances. That is, check that
# the hyperthreading state has not changed since the last time we updated our
# grub configuration.
# - check Broadwell kvm-intel.eptad flag is in agreement with current setting
#
################################################################################
function check_kernel_boot_args() {
  local BASE_CPULIST=$1
  local ISOL_CPULIST=$2

  local BASE_CPUMAP=$(cpulist_to_cpumap ${BASE_CPULIST} ${N_CPUS})
  local RCU_NOCBS_CPUMAP=$(invert_cpumap ${BASE_CPUMAP} ${N_CPUS})
  local RCU_NOCBS_CPULIST=$(cpumap_to_cpulist ${RCU_NOCBS_CPUMAP} ${N_CPUS})

  ## Query the current boot args and store them in a hash/map for easy access
  local CMDLINE=($(cat /proc/cmdline))
  declare -A BOOTARGS
  for ITEM in ${CMDLINE[@]}; do
     KV=(${ITEM//=/ })
     BOOTARGS[${KV[0]}]=${KV[1]}
  done

  ## Audit the attributes that impacts VM scheduling behaviour
  if [ "${BOOTARGS[isolcpus]}" != "${ISOL_CPULIST}" ]; then
      log_error "Kernel boot argument mismatch: isolcpus=${BOOTARGS[isolcpus]} expecting ${ISOL_CPULIST}"
      return 1
  fi

  if [ "${BOOTARGS[rcu_nocbs]}" != "${RCU_NOCBS_CPULIST}" ]; then
      log_error "Kernel boot argument mismatch: rcu_nocbs=${BOOTARGS[rcu_nocbs]} expecting ${RCU_NOCBS_CPULIST}"
      return 1
  fi

  if [ "${BOOTARGS[kthread_cpus]}" != "${BASE_CPULIST}" ]; then
      log_error "Kernel boot argument mismatch: kthread_cpus=${BOOTARGS[kthread_cpus]} expecting ${BASE_CPULIST}"
      return 1
  fi

  if [ "${BOOTARGS[irqaffinity]}" != "${BASE_CPULIST}" ]; then
      log_error "Kernel boot argument mismatch: irqaffinity=${BOOTARGS[irqaffinity]} expecting ${BASE_CPULIST}"
      return 1
  fi

  if grep -q -E "^model\s+:\s+79$" /proc/cpuinfo
  then
      if [ "${BOOTARGS[kvm-intel.eptad]}" != "${BROADWELL_EPTAD}" ]; then
          log_error "Kernel boot argument mismatch: kvm-intel.eptad=${BOOTARGS[kvm-intel.eptad]} expecting ${BROADWELL_EPTAD}"
          return 1
      fi
  fi

  return 0
}

################################################################################
# update_grub_configuration() - update the grub configuration so that the
# kernel boot arguments are correct on the next reboot.
#
################################################################################
function update_grub_configuration() {
  local BASE_CPULIST=$1
  local ISOL_CPULIST=$2

  local BASE_CPUMAP=$(cpulist_to_cpumap ${BASE_CPULIST} ${N_CPUS})
  local RCU_NOCBS_CPUMAP=$(invert_cpumap ${BASE_CPUMAP} ${N_CPUS})
  local RCU_NOCBS_CPULIST=$(cpumap_to_cpulist ${RCU_NOCBS_CPUMAP} ${N_CPUS})

  log "Updating grub configuration:"

  if [ ! -f ${GRUB_DEFAULTS} ]; then
      log_error "Missing grub defaults file ${GRUB_DEFAULTS}"
      return 1
  fi

  if [ ! -f ${GRUB_CONFIG} ]; then
      log_error "Missing grub config file ${GRUB_CONFIG}"
      return 1
  fi

  source ${GRUB_DEFAULTS}
  if [ -z "${GRUB_CMDLINE_LINUX}" ]; then
      log_error "Missing grub cmdline variable: GRUB_CMDLINE_LINUX"
      return 1
  fi

  ## Remove the arguments that we need to update (or remove)
  VALUE="${GRUB_CMDLINE_LINUX//?([[:blank:]])+(kvm-intel.eptad|default_hugepagesz|hugepagesz|hugepages|isolcpus|nohz_full|rcu_nocbs|kthread_cpus|irqaffinity)=+([-,0-9MG])/}"

  ## Add the new argument values

  # Broadwell specific flags (model: 79)
  if grep -q -E "^model\s+:\s+79$" /proc/cpuinfo
  then
      VALUE="${VALUE} kvm-intel.eptad=${BROADWELL_EPTAD}"
  fi
  if grep -q pdpe1gb /proc/cpuinfo
  then
      VALUE="${VALUE} hugepagesz=1G hugepages=${N_NUMA}"
  fi
  VALUE="${VALUE} hugepagesz=2M hugepages=0"
  VALUE="${VALUE} default_hugepagesz=2M"
  VALUE="${VALUE} isolcpus=${ISOL_CPULIST}"
  VALUE="${VALUE} rcu_nocbs=${RCU_NOCBS_CPULIST}"
  VALUE="${VALUE} kthread_cpus=${BASE_CPULIST}"
  VALUE="${VALUE} irqaffinity=${BASE_CPULIST}"
  if [[ "$subfunction" == *"compute,lowlatency" ]]; then
      # As force_grub_update() and check_cpu_grub_configuration call this
      # function with an ISOL_CPULIST with from lowlatency compute checks we'll
      # use it here for the nohz_full option
      VALUE="${VALUE} nohz_full=${ISOL_CPULIST}"
  fi

  if [ "${VALUE}" == "${GRUB_CMDLINE_LINUX}" ] &&
    grep -q -e "${GRUB_CMDLINE_LINUX}" /proc/cmdline
  then
      log_debug "Unchanged cmdline: ${GRUB_CMDLINE_LINUX}"
      return 0
  fi

  ## Replace the value in the file and re-run the grub config tool
  perl -pi -e 's/(GRUB_CMDLINE_LINUX)=.*/\1=\"'"${VALUE}"'\"/g' ${GRUB_DEFAULTS}
  ${GRUB} -o ${GRUB_CONFIG} 2>/dev/null
  RET=$?
  if [ ${RET} -ne 0 ]; then
      log_error "Failed to run grub-mkconfig, rc=${RET}"
      return 1
  fi
  source ${GRUB_DEFAULTS}
  if [ -z "${GRUB_CMDLINE_LINUX}" ]; then
      log_error "Missing grub cmdline variable: GRUB_CMDLINE_LINUX"
      return 1
  else
      log_debug "Updated cmdline: ${GRUB_CMDLINE_LINUX}"
  fi
  sync

  return 0
}
 
################################################################################
# force_grub_update() - force an update to the grub configuration so that the
# kernel boot arguments are correct on the next reboot.
#
################################################################################
function force_grub_update() {
  log_debug "stop: force_grub_update"

  ## fetch the cpu topology
  get_topology

  ## calculate the base and isolation cpu lists
  local BASE_CPULIST=$(platform_cpu_list)
  local ISOL_CPULIST=$(vswitch_cpu_list)

  if [[ "$subfunction" == *"compute,lowlatency" ]]; then
      local BASE_CPUMAP=$(cpulist_to_cpumap ${BASE_CPULIST} ${N_CPUS})
      local RCU_NOCBS_CPUMAP=$(invert_cpumap ${BASE_CPUMAP} ${N_CPUS})
      local RCU_NOCBS_CPULIST=$(cpumap_to_cpulist ${RCU_NOCBS_CPUMAP} ${N_CPUS})

      ISOL_CPULIST=$RCU_NOCBS_CPULIST
  fi

  if [ -z "${ISOL_CPULIST}" ]; then
      log_error "isolcpus cpu list is empty"
      return 1
  fi

  ## update grub with new settings
  update_grub_configuration ${BASE_CPULIST} ${ISOL_CPULIST}
  RET=$?

  return ${RET}
}

################################################################################
# check_cpu_grub_configuration() - check kernel boot arguments to ensure
# that the current CPU configuration matches the isolation and platform arguments
#  passed to the kernel at boot time.
#
################################################################################
function check_cpu_grub_configuration() {
  ## calculate the base and isolation cpu lists
  local BASE_CPULIST=$(platform_cpu_list)
  local ISOL_CPULIST=$(vswitch_cpu_list)

  if [[ "$subfunction" == *"compute,lowlatency" ]]; then
      local BASE_CPUMAP=$(cpulist_to_cpumap ${BASE_CPULIST} ${N_CPUS})
      local RCU_NOCBS_CPUMAP=$(invert_cpumap ${BASE_CPUMAP} ${N_CPUS})
      local RCU_NOCBS_CPULIST=$(cpumap_to_cpulist ${RCU_NOCBS_CPUMAP} ${N_CPUS})

      ISOL_CPULIST=$RCU_NOCBS_CPULIST
  fi

  if [ -z "${ISOL_CPULIST}" ]; then
      log_error "isolcpus cpu list is empty"
      return 1
  fi

  if [ -z "${BASE_CPULIST}" ]; then
      log_error "platform cpu list is empty"
      return 1
  fi
  
  ## check that the boot arguments are consistent with the current
  ## base/isolation cpu lists
  check_kernel_boot_args ${BASE_CPULIST} ${ISOL_CPULIST}
  RET=$?
  if [ ${RET} -eq 1 ]; then
      log_error "Boot args check failed; updating grub configuration"
      update_grub_configuration ${BASE_CPULIST} ${ISOL_CPULIST}
      RET=$?
      if [ ${RET} -ne 0 ]; then
          log_error "Failed to update grub configuration, rc=${RET}"
          return 2
      fi

      return 1
  fi

  return 0
}

################################################################################
# check_configuration() - check system configuration
#
################################################################################
function check_configuration() {
    ## Since script is called multiple times, remove previous flag
    rm -f ${COMPUTE_HUGE_GOENABLED}

    if [ -z "${N_CPUS}" ]; then
        log_error "N_CPUS environment variable not set"
        return 1
    fi

    # Check that the actual CPU configuration matches configured settings
    check_cpu_configuration
    RET1=$?
    if [ ${RET1} -gt 1 ]; then
        return ${RET1}
    fi

    # Check that CPU isolation and platform configuration has been applied according to the
    # current CPU configuration
    check_cpu_grub_configuration
    RET2=$?
    if [ ${RET2} -gt 1 ]; then
        return ${RET2}
    fi

    RET=$[ ${RET1} + ${RET2} ]
    if [ ${RET} -eq 0 ]; then
        ## All checks passed; safe to enable
        log_debug "compute-huge-goenabled: pass"
        touch ${COMPUTE_HUGE_GOENABLED}
    elif [ "$nodetype" = "controller" \
            -a ! -f ${COMPUTE_HUGE_RUN_ONCE} \
            -a ! -f ${PLATFORM_SIMPLEX_FLAG} ]; then
        touch ${COMPUTE_HUGE_RUN_ONCE}
        log_debug "Rebooting to process config changes"
        /sbin/reboot
    else
        log_error "compute-huge-goenabled: failed"
        if [ ! -f ${COMPUTE_HUGE_RUN_ONCE} ]; then
            touch ${RECONFIG_REBOOT_REQUIRED}
        fi
    fi

    # Mark when configuration run via compute_config packstack applyscript
    if [ ${is_reconfig} -eq 1 ]; then
        if [ ! -f ${COMPUTE_HUGE_RUN_ONCE} ]; then
            log_debug "check_configuration: config FIRST_RUN"
        else
            log_debug "check_configuration: config"
        fi
        touch ${COMPUTE_HUGE_RUN_ONCE}
    fi

    return 0
}


################################################################################
# get_topology() - deduce CPU and NUMA topology
#
################################################################################
function get_topology() {
    # number of logical cpus
    N_CPUS=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/^[pP]rocessor/ { n +=1 } END { print (n>0) ? n : 1}')

    # number of sockets (i.e. packages)
    N_SOCKETS=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/physical id/ { a[$4] = 1; } END { n=0; for (i in a) n++; print (n>0) ? n : 1 }')

    # number of logical cpu siblings per package
    N_SIBLINGS_IN_PKG=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/^siblings/ {n = $3} END { print (n>0) ? n: 1 }')

    # number of cores per package
    N_CORES_IN_PKG=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/^cpu cores/ {n = $4} END { print (n>0) ? n : 1 }')

    # number of SMT threads per core
    N_THREADS=$[ $N_SIBLINGS_IN_PKG / $N_CORES_IN_PKG ]

    # number of numa nodes
    N_NUMA=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)

    # Total physical memory
    MEMTOTAL_MiB=$(cat /proc/meminfo 2>/dev/null | \
        awk '/^MemTotal/ {n = int($2/1024)} END { print (n>0) ? n : 0 }')

    log_debug "TOPOLOGY: CPUS:${N_CPUS} SOCKETS:${N_SOCKETS}" \
              "SIBLINGS:${N_SIBLINGS_IN_PKG} CORES:${N_CORES_IN_PKG} THREADS:${N_THREADS}" \
              "NODES:${N_NUMA} MEMTOTAL:${MEMTOTAL_MiB} MiB"

    # Get kernel command line options
    CMDLINE=$(cat /proc/cmdline 2>/dev/null)
    if [[ $CMDLINE =~ (console=.*) ]]; then
        log_debug "cmdline: ${BASH_REMATCH[1]}"
    fi
}

################################################################################
# is_strict() - determine whether we are using strict memory accounting
#
################################################################################
function is_strict() {
    RET=0
    OC_MEM=$(cat /proc/sys/vm/overcommit_memory 2>/dev/null)
    if [ ${OC_MEM} -eq 2 ]; then
        echo 1  # strict
    else
        echo 0  # non-strict
    fi
}

################################################################################
# get_memory() - determine memory breakdown for standard linux memory and
#                default hugepages
#
################################################################################
function get_memory() {
    local NODESYSFS=/sys/devices/system/node
    local HTLBSYSFS=""
    local -i Ki=1024
    local -i Ki2=512
    local -i SZ_2M_Ki=2048
    local -i SZ_1G_Ki=1048576

    # number of numa nodes
    local n_numa=$(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l)

    # Parse all values of /proc/meminfo
    declare -gA meminfo
    while read -r line
    do
        if [[ $line =~ ^([[:alnum:]_]+):[[:space:]]+([[:digit:]]+) ]]; then
            meminfo[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
        fi
    done < "/proc/meminfo"

    # Parse all values of /sys/devices/system/node/node*/meminfo
    declare -gA memnode
    for ((node=0; node < n_numa; node++))
    do
        while read -r line
        do
            if [[ $line =~ ^Node[[:space:]]+[[:digit:]]+[[:space:]]+([[:alnum:]_]+):[[:space:]]+([[:digit:]]+) ]]; then
                memnode[$node,${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
            fi
        done < "/sys/devices/system/node/node${node}/meminfo"
    done

    # Parse all values of /sys/devices/system/node/node*/meminfo_extra
    for ((node=0; node < n_numa; node++))
    do
        memnode[$node,'MemFreeInit']=${memnode[$node,'MemTotal']}
        if [ -f /sys/devices/system/node/node${node}/meminfo_extra ]; then
            while read -r line
            do
                if [[ $line =~ ^Node[[:space:]]+[[:digit:]]+[[:space:]]+([[:alnum:]_]+):[[:space:]]+([[:digit:]]+) ]]; then
                    memnode[$node,${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
                fi
            done < "/sys/devices/system/node/node${node}/meminfo_extra"
        fi
    done

    # Parse all values of /sys/devices/system/node/node*/hugepages/hugepages-${pgsize}kB
    declare -a pgsizes
    pgsizes+=(${SZ_2M_Ki})
    pgsizes+=(${SZ_1G_Ki})
    for ((node=0; node < n_numa; node++))
    do
        for pgsize in ${pgsizes[@]}
        do
            memnode[$node,$pgsize,'nr']=0
            memnode[$node,$pgsize,'nf']=0
        done
    done
    for ((node=0; node < n_numa; node++))
    do
        for pgsize in ${pgsizes[@]}
        do
            HTLBSYSFS=${NODESYSFS}/node${node}/hugepages/hugepages-${pgsize}kB
            if [ -d ${HTLBSYSFS} ]; then
                memnode[$node,$pgsize,'nr']=$(cat ${HTLBSYSFS}/nr_hugepages)
                memnode[$node,$pgsize,'nf']=$(cat ${HTLBSYSFS}/free_hugepages)
            fi
        done
    done

    # Calculate available memory
    is_strict=$(is_strict)
    if [ $is_strict -eq 1 ]; then
        strict_msg='strict accounting'
        meminfo['Avail']=$[ ${meminfo['CommitLimit']} - ${meminfo['Committed_AS']} ]
    else
        strict_msg='non-strict accounting'
        meminfo['Avail']=$[ ${meminfo['MemFree']} +
                            ${meminfo['Cached']} +
                            ${meminfo['Buffers']} +
                            ${meminfo['SReclaimable']} ]
    fi
    # Used memory (this includes kernel overhead, so it is a bit bogus)
    meminfo['Used']=$[ ${meminfo['MemTotal']} - ${meminfo['Avail']} ]
    for ((node=0; node < n_numa; node++))
    do
        memnode[${node},'Avail']=$[ ${memnode[$node,'MemFree']} +
                                    ${memnode[$node,'FilePages']} +
                                    ${memnode[$node,'SReclaimable']} ]
        memnode[${node},'HTot']=0
        memnode[${node},'HFree']=0
        for pgsize in ${pgsizes[@]}
        do
            memnode[${node},'HTot']=$[ ${memnode[${node},'HTot']} +
                ${pgsize} * ${memnode[$node,${pgsize},'nr']} ]
            memnode[${node},'HFree']=$[ ${memnode[${node},'HFree']} +
                ${pgsize} * ${memnode[$node,${pgsize},'nf']} ]
        done
    done

    # Print memory usage summary
    log_debug "MEMORY OVERALL: MiB (${strict_msg})"

    # Print overall memory
    MEM=$(printf "%6s %6s %6s %6s %6s %6s %6s %6s %6s %6s %6s %6s %6s" \
        'Tot' 'Used' 'Free' 'Ca' 'Buf' 'Slab' 'CAS' 'CLim' 'Dirty' 'WBack' 'Active' 'Inact' 'Avail')
    log_debug "${MEM}"
    MEM=$(printf "%6d %6d %6d %6d %6d %6d %6d %6d %6d %6d %6d %6d %6d" \
        $[ (${meminfo['MemTotal']}     + $Ki2) / $Ki ] \
        $[ (${meminfo['Used']}         + $Ki2) / $Ki ] \
        $[ (${meminfo['MemFree']}      + $Ki2) / $Ki ] \
        $[ (${meminfo['Cached']}       + $Ki2) / $Ki ] \
        $[ (${meminfo['Buffers']}      + $Ki2) / $Ki ] \
        $[ (${meminfo['Slab']}         + $Ki2) / $Ki ] \
        $[ (${meminfo['Committed_AS']} + $Ki2) / $Ki ] \
        $[ (${meminfo['CommitLimit']}  + $Ki2) / $Ki ] \
        $[ (${meminfo['Dirty']}        + $Ki2) / $Ki ] \
        $[ (${meminfo['Writeback']}    + $Ki2) / $Ki ] \
        $[ (${meminfo['Active']}       + $Ki2) / $Ki ] \
        $[ (${meminfo['Inactive']}     + $Ki2) / $Ki ] \
        $[ (${meminfo['Avail']}        + $Ki2) / $Ki ])
    log_debug "${MEM}"

    # Print per-numa node memorybreakdown
    log_debug "MEMORY PER-NUMA NODE: MiB"
    MEM=""
    for ((node=0; node < n_numa; node++))
    do
        L=$(printf " %7s %7s %7s %7s" "$node:Init" "$node:Avail" "$node:Htot" "$node:HFree")
        MEM="${MEM}${L}"
    done
    log_debug "${MEM}"
    MEM=""
    for ((node=0; node < n_numa; node++))
    do
        L=$(printf " %7d %7d %7d %7d" \
            $[ (${memnode[$node,'MemFreeInit']} + $Ki2) / $Ki ] \
            $[ (${memnode[$node,'Avail']}       + $Ki2) / $Ki ] \
            $[ (${memnode[$node,'HTot']}        + $Ki2) / $Ki ] \
            $[ (${memnode[$node,'HFree']}       + $Ki2) / $Ki ])
        MEM="${MEM}${L}"
    done
    log_debug "${MEM}"
}

################################################################################
# mount_cgroups()
#  - mounts cgroups and all available controllers.
#  - cgroup domains used by libvirt/qemu
#
################################################################################
function mount_cgroups() {
    local RET=0

    # mount /sys/fs/cgroup
    log_debug "Mounting cgroups"
    mountpoint -q /sys/fs/cgroup || \
        mount -t tmpfs -o uid=0,gid=0,mode=0755 cgroup /sys/fs/cgroup
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to mount cgroups, rc=${RET}"
        return ${RET}
    fi
    
    # mount each available cgroup controller
    for cnt in $(cat /proc/cgroups | awk '!/#/ {print $1;}')
    do
        mkdir -p /sys/fs/cgroup/$cnt
        mountpoint -q /sys/fs/cgroup/$cnt || \
            (mount -n -t cgroup -o $cnt cgroup /sys/fs/cgroup/$cnt || \
            rmdir /sys/fs/cgroup/$cnt || true)
    done
    return ${RET}
}

################################################################################
# mount_resctrl()
#  - mounts resctrl for Cache Allocation Technology
#
################################################################################
function mount_resctrl() {
    local RET=0

    # mount /sys/fs/resctrl
    log_debug "Mounting resctrl"
    mountpoint -q /sys/fs/resctrl || \
        mount -t resctrl resctrl /sys/fs/resctrl
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to mount resctrl, rc=${RET}"
        return ${RET}
    fi

    return ${RET}
}


################################################################################
# Set Power Management QoS resume latency constraints for CPUs.
# The PM QoS resume latency limit is set to shalow C-state for vswitch CPUs.
# All other CPUs are allowed to go to the deepest C-state available.
#
################################################################################
set_pmqos_policy() {
    local RET=0

    if [[ "$subfunction" == *"compute,lowlatency" ]]; then
        ## Set low wakeup latency (shalow C-state) for vswitch CPUs using PM QoS interface
        local VSWITCH_CPULIST=$(vswitch_cpu_list)
        /bin/bash -c "/usr/bin/set-cpu-wakeup-latency.sh low ${VSWITCH_CPULIST}" 2>/dev/null
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to set low wakeup CPU latency for vswitch CPUs ${VSWITCH_CPULIST}, rc=${RET}"
        fi
        ## Set high wakeup latency (deep C-state) for non-vswitch CPUs using PM QoS interface
        local NON_VSWITCH_CPULIST=$(invert_cpulist ${VSWITCH_CPULIST} ${N_CPUS})
        /bin/bash -c "/usr/bin/set-cpu-wakeup-latency.sh high ${NON_VSWITCH_CPULIST}" 2>/dev/null
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to set high wakeup CPU latency for non-vswitch CPUs ${NON_VSWITCH_CPULIST}, rc=${RET}"
        fi    
    fi

    return ${RET}
}

################################################################################
# Mounts virtual hugetlbfs filesystems for each supported page size.
#  return: 0 - success; 1 - failure
#
################################################################################
function mount_hugetlbfs_auto
{
    local SYSFSLIST=($(ls -1d /sys/kernel/mm/hugepages/hugepages-*))
    local SYSFS=""
    local RET=0

    if ! grep -q hugetlbfs /proc/filesystems
    then
        log_error "hugetlbfs not enabled"
        return 1
    fi

    for SYSFS in ${SYSFSLIST[@]}; do
        local PGNAME=$(basename $SYSFS)
        local PGSIZE=${PGNAME/hugepages-/}

        local HUGEMNT=/mnt/huge-${PGSIZE}
        log_debug "Mounting hugetlbfs at: $HUGEMNT"
        if [ ! -d ${HUGEMNT} ]; then
            mkdir -p ${HUGEMNT}
        fi

        grep -q ${HUGEMNT} /proc/mounts || \
            mount -t hugetlbfs -o pagesize=${PGSIZE} none ${HUGEMNT}
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to mount hugetlbfs at ${HUGEMNT}, rc=${RET}"
            return ${RET}
        fi
    done

    return ${RET}
}

################################################################################
# Mounts virtual hugetlbfs filesystems for specific supported page size.
#  param: MNT_HUGE - mount point for hugepages
#  param: PGSIZE   - pagesize attribute (eg, 2M, 1G)
#  return: 0 - success; 1 - failure
#
################################################################################
function mount_hugetlbfs
{
    local MNT_HUGE=$1
    local PGSIZE=$2
    local RET=0
    log_debug "Mounting hugetlbfs at: $MNT_HUGE"

    if ! grep -q hugetlbfs /proc/filesystems
    then
        log_error "hugetlbfs not enabled"
        return 1
    fi

    mountpoint -q ${MNT_HUGE}
    if [ $? -eq 1 ]
    then
        mkdir -p ${MNT_HUGE}
        mount -t hugetlbfs -o pagesize=${PGSIZE} hugetlbfs ${MNT_HUGE}
        RET=$?
        if [ ${RET} -ne 0 ]
        then
            log_error "Failed to mount hugetlbfs at ${MNT_HUGE}, rc=${RET}"
            return ${RET}
        fi
    fi
    return 0
}

################################################################################
# Allocates a set of HugeTLB pages according to the specified parameters.
# The first parameter specifies the NUMA node (e.g., node0, node1, etc.).
# The second parameter specifies the HugeTLB page size (e.g, 2048kB,
# 1048576kB, etc).
# The third parameter specifies the number of pages for the given page size.
################################################################################
function allocate_one_pagesize
{
    local NODE=$1
    local PGSIZE=$2
    local PGCOUNT=$3
    local NODESYSFS=/sys/devices/system/node
    local HTLBSYSFS=""
    local RET=0

    log_debug "Allocating ${PGCOUNT} HugeTLB pages of ${PGSIZE} on ${NODE}"

    if [ ! -d "${NODESYSFS}" ]; then
        ## Single NUMA node
        if [ "${NODE}" != "node0" ]; then
            log_error "${NODE} is not valid on a single NUMA node system"
            return 1
        fi
        NODESYSFS=/sys/kernel/mm/
    else
        NODESYSFS=${NODESYSFS}/${NODE}
        if [ ! -d "${NODESYSFS}" ]; then
            log_error "NUMA node ${NODE} does not exist"
            return 1
        fi
    fi

    HTLBSYSFS=${NODESYSFS}/hugepages/hugepages-${PGSIZE}
    if [ ! -d ${HTLBSYSFS} ]; then
        log_error "No HugeTLB support for ${PGSIZE} pages on ${NODE}"
        return 1
    fi

    ## Request pages
    echo ${PGCOUNT} > ${HTLBSYSFS}/nr_hugepages
    RET=$?
    if [ ${RET} -ne 0 ]
    then
        log_error "Failed to allocate ${PGCOUNT} pages on ${HTLBSYSFS}, rc=${RET}"
        return ${RET}
    fi

    return ${RET}
}

################################################################################
# Allocates HugeTLB memory according to the attributes specified in the
# parameter list.  The first parameters is expected to be a reference to an
# array rather than the actual contents of an array.
#
# Each element of the array is expected to be in the following format.
#   "<node>:<pgsize>:<pgcount>"
# For example,
#   ("node0:2048kB:256" "node0:1048576kB:2")
#
################################################################################
function allocate_hugetlb_memory
{
    local MEMLIST=("${!1}")
    local MEMDESC=""
    local ARRAY=""
    local RET=0

    ## Reserve memory for each node + pagesize
    for MEMDESC in ${MEMLIST[@]}
    do
        ARRAY=(${MEMDESC//:/ })
        if [ ${#ARRAY[@]} -ne 3 ]; then
            log_error "Invalid element format ${MEMDESC}, expecting 'node:pgsize:pgcount'"
            return 1
        fi

        NODE=${ARRAY[0]}
        PGSIZE=${ARRAY[1]}
        PGCOUNT=${ARRAY[2]}
        allocate_one_pagesize ${NODE} ${PGSIZE} ${PGCOUNT}
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to setup HugeTLB for ${NODE}:${PGSIZE}:${PGCOUNT}, rc=${RET}"
            return ${RET}
        fi
    done

    return 0
}

################################################################################
# per_numa_resources()
#  - mounts and allocates hugepages for Compute node libvirt
#  - hugepage requirements are calculated per NUMA node
#    based on engineering of BASE and VSWITCH
#  - it is assumed this is done very early in init to prevent fragmentation
#  - calculates reserved cpulists for BASE and vswitch
#
################################################################################
function per_numa_resources() {
    local err=0
    local NODESYSFS=/sys/devices/system/node
    local HTLBSYSFS=""
    local node

    do_huge=${do_huge:-1}

    log_debug "Setting per-NUMA resources: ${PRODUCT_NAME}"

    # Check for per-node NUMA topology
    NODESYSFS0=${NODESYSFS}/node0
    if [ ! -d "${NODESYSFS0}" ]; then
        log_error "NUMA node0 does not exist"
        return 1
    fi

    # Check that we have support for 2MB hugepages
    if [ ${do_huge} -eq 1 ]
    then
        node=0
        pgsize=2048
        HTLBSYSFS=${NODESYSFS}/node${node}/hugepages/hugepages-${pgsize}kB
        if [ ! -d ${HTLBSYSFS} ]; then
            do_huge=0
            log_error "No HugeTLB support for ${pgsize}kB pages on node${node}, do_huge=0"
        fi
    fi

    # Workaround: customize /etc/nova/rootwrap.d/
    ROOTWRAP=/etc/nova/rootwrap.d
    FILTER=${ROOTWRAP}/compute-extend.filters
    mkdir -p ${ROOTWRAP}
    PERM=$(stat --format=%a ${ROOTWRAP})
    chmod 755 ${ROOTWRAP}
    : > ${FILTER}
    echo "# nova-rootwrap command filters for compute nodes" >> ${FILTER}
    echo "# This file should be owned by (and only-writeable by) the root user" >> ${FILTER}
    echo "[Filters]" >> ${FILTER}
    echo "cat: CommandFilter, cat, root" >> ${FILTER}
    echo "taskset: CommandFilter, taskset, root" >> ${FILTER}
    chmod ${PERM} ${ROOTWRAP}

    # Minimally need 1GB for compute in VirtualBox
    declare -i compute_min_MB=1600
    declare -i compute_min_non0_MB=500

    # Minimally need 6GB for controller in VirtualBox
    declare -i controller_min_MB=6000

    # Some constants
    local -i Ki=1024
    local -i Ki2=512
    local -i SZ_4K_Ki=4
    local -i SZ_2M_Ki=2048
    local -i SZ_1G_Ki=1048576

    # Declare memory page sizes
    declare -A pgsizes
    pgsizes[${SZ_4K_Ki}]='4K'
    pgsizes[${SZ_2M_Ki}]='2M'
    pgsizes[${SZ_1G_Ki}]='1G'

    # Declare per-numa memory storage
    declare -A do_manual
    declare -A tot_memory
    declare -A base_memory
    declare -A vs_pages
    declare -A vm_pages
    declare -A max_vm_pages
    for ((node=0; node < N_NUMA; node++))
    do
        do_manual[$node]=0
        tot_memory[$node]=0
        base_memory[$node]=0
        for pgsize in "${!pgsizes[@]}"
        do
            vm_pages[${node},${pgsize}]=0
            max_vm_pages[${node},${pgsize}]=0
            vs_pages[${node},${pgsize}]=0
        done
    done

    # Track vswitch hugepages. Note that COMPUTE_VSWITCH_MEMORY is defined in
    # /etc/nova/compute_reserved.conf .
    for MEMDESC in ${COMPUTE_VSWITCH_MEMORY[@]}
    do
        ARRAY=(${MEMDESC//:/ })
        if [ ${#ARRAY[@]} -ne 3 ]; then
            log_error "Invalid element format ${MEMDESC}, expecting 'node:pgsize:pgcount'"
            return 1
        fi
        node=${ARRAY[0]#node}
        pgsize=${ARRAY[1]%kB}
        pgcount=${ARRAY[2]}
        if [ ${node} -ge ${N_NUMA} ]; then
            continue
        fi
        HTLBSYSFS=${NODESYSFS}/node${node}/hugepages/hugepages-${pgsize}kB
        if [ ! -d ${HTLBSYSFS} ]; then
            log_debug "SKIP: No HugeTLB support for ${pgsize}kB pages on node${node}"
            continue
        fi

        # Keep track of vswitch pages (we'll add them back in later)
        vs_pages[${node},${pgsize}]=$[ ${vs_pages[${node},${pgsize}]} + $pgcount ]
    done

    # Track total VM memory. Note that COMPUTE_VM_MEMORY_2M and
    # COMPUTE_VM_MEMORY_1G is defined in /etc/nova/compute_reserved.conf .
    for MEMDESC in ${COMPUTE_VM_MEMORY_2M[@]} ${COMPUTE_VM_MEMORY_1G[@]}
    do
        ARRAY=(${MEMDESC//:/ })
        if [ ${#ARRAY[@]} -ne 3 ]; then
            log_debug "Invalid element format ${MEMDESC}, expecting 'node:pgsize:pgcount'"
            break
        fi
        node=${ARRAY[0]#node}
        pgsize=${ARRAY[1]%kB}
        pgcount=${ARRAY[2]}
        if [ ${node} -ge ${N_NUMA} ]; then
            continue
        fi
        HTLBSYSFS=${NODESYSFS}/node${node}/hugepages/hugepages-${pgsize}kB
        if [ ! -d ${HTLBSYSFS} ]; then
            log_debug "SKIP: No HugeTLB support for ${pgsize}kB pages on node${node}"
            continue
        fi

        # Cumulate total VM memory
        do_manual[${node}]=1
        vm_pages[${node},${pgsize}]=$[ ${vm_pages[${node},${pgsize}]} + $pgcount ]
    done

    # Track base reserved cores and memory. Note that COMPUTE_BASE_RESERVED is
    # defined in /etc/nova/compute_reserved.conf .
    for MEMDESC in ${COMPUTE_BASE_RESERVED[@]}
    do
        ARRAY=(${MEMDESC//:/ })
        if [ ${#ARRAY[@]} -ne 3 ]; then
            log_error "Invalid element format ${MEMDESC}, expecting 'node:memory:cores'"
            return 1
        fi
        local -i node=${ARRAY[0]#node}
        local -i memory=${ARRAY[1]%MB}
        local -i cores=${ARRAY[2]}

        # On small systems, clip memory overhead to more reasonable minimal
        # settings in the case sysinv hasn't set run yet.
        INIT_MiB=$[ (${memnode[${node},'MemFreeInit']} + ${Ki2}) / ${Ki} ]
        MEMFREE=$[ ${INIT_MiB} - ${memory} ]
        if [ ${MEMFREE} -lt 1000 ]; then
            if [ ${node} -eq 0 ]; then
                memory=${compute_min_MB}
                if [ "$nodetype" = "controller" ]; then
                    ((memory += controller_min_MB))
                fi
            else
                memory=${compute_min_non0_MB}
            fi
        fi

        base_memory[$node]=$memory
    done

    # Declare array to store hugepage allocation info
    declare -a HUGE_MEMORY
    declare -a VM_MEMORY_2M
    declare -a VM_MEMORY_1G
    HUGE_MEMORY=()
    VM_MEMORY_2M=()
    VM_MEMORY_1G=()

    # Calculate memory breakdown for this numa node
    for ((node=0; node < N_NUMA; node++))
    do
        # Top-down memory calculation:
        #   NODE_TOTAL_MiB = MemFreeInit
        if [ -f /sys/devices/system/node/node${node}/meminfo_extra ]; then
            NODE_TOTAL_INIT_MiB=$(grep MemFreeInit \
                /sys/devices/system/node/node${node}/meminfo_extra | \
                awk '{printf "%d", ($4+512)/1024;}')
        else
            NODE_TOTAL_INIT_MiB=$(grep MemTotal \
                /sys/devices/system/node/node${node}/meminfo | \
                awk '{printf "%d", ($4+512)/1024;}')
        fi

        # Bottom-up memory calculation (total hugepages + usable linux mem)
        #   NODE_TOTAL_MiB = HTOT + (AVAIL + PSS)
        HTOT_MiB=$[ (${memnode[${node},'HTot']} + ${Ki2}) / ${Ki} ]
        AVAIL_MiB=$[ (${memnode[${node},'Avail']} + ${Ki2}) / ${Ki} ]
        if [ $node -eq 0 ]; then
            # Assume calling this when VMs not launched, so assume numa 0
            PSS_MiB=$(cat /proc/*/smaps 2>/dev/null | \
                      awk '/^Pss:/ {a += $2;} END {printf "%d\n", a/1024.0;}')
        else
            PSS_MiB=0
        fi
        NODE_TOTAL_MiB=$[ ${HTOT_MiB} + ${AVAIL_MiB} + ${PSS_MiB} ]
        tot_memory[${node}]=${NODE_TOTAL_MiB}

        # Engineered amount of memory for vswitch plus VMs.
        ENG_MiB=$[ ${NODE_TOTAL_MiB} - ${base_memory[$node]} ]
        if [ ${ENG_MiB} -lt 0 ]; then
            ENG_MiB=0
        fi

        # Amount of memory left for VMs
        VM_MiB=$[ ${ENG_MiB}
                  - ${SZ_2M_Ki} * ${vs_pages[$node,${SZ_2M_Ki}]} / ${Ki}
                  - ${SZ_1G_Ki} * ${vs_pages[$node,${SZ_1G_Ki}]} / ${Ki} ]

        # Prevent allocating hugepages if host is too small
        if [ ${do_huge} -eq 0 -o $VM_MiB -le 16 ]
        then
            VM_MiB=0
            log_error "insufficient memory on node $node to allocate hugepages"
        fi

        # Maximize use of 2M pages if not using pre-determined 2M and 1G pages.
        if [ ${do_manual[${node}]} -ne 1 ]; then
            vm_pages[${node},${SZ_2M_Ki}]=$[ ${Ki} * ${VM_MiB} / ${SZ_2M_Ki} / 16 * 16 ]
        fi

        # Calculate remaining memory as 4K pages
        vm_pages[${node},${SZ_4K_Ki}]=$[ (${Ki} * ${VM_MiB}
            - ${SZ_2M_Ki} * ${vm_pages[${node},${SZ_2M_Ki}]}
            - ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]}) / ${SZ_4K_Ki} ]
        min_4K=$[ 32 * ${Ki} / ${SZ_4K_Ki} ]
        if [ ${vm_pages[${node},${SZ_4K_Ki}]} -lt ${min_4K} ]; then
            vm_pages[${node},${SZ_4K_Ki}]=0
        fi

        # Sanity check
        # The memory pages specifed in the $RESERVE_CONF file should not
        # exceed the available memory in the system.  Validate the values by
        # calculating the memory required for specified pages, and comparing
        # with available memory.
        #
        # We will override configured pages if the specified values are out of
        # range.  Note that we do not expect this to happen (unless a DIMM
        # fails, or some other error) as we check available pages before
        # allowing user to change allocated pages.
        local requested_VM_MiB=$[
            ${SZ_4K_Ki} * ${vm_pages[${node},${SZ_4K_Ki}]} / ${Ki}
            + ${SZ_2M_Ki} * ${vm_pages[${node},${SZ_2M_Ki}]} / ${Ki}
            + ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]} / ${Ki} ]

        if [ ${requested_VM_MiB} -gt ${VM_MiB} ]; then

            # We're over comitted - clamp memory usage to actual available
            # memory.  In addition to the log files, we also want to output
            # to console
            log_error "Over-commited VM memory: " \
                "Requested ${requested_VM_MiB} MiB through ${RESERVE_CONF} " \
                "but ${VM_MiB} MiB available."

            # Reduce 1G pages to the max number that will fit (leave 1G pages
            # unchanged if it's already small enough)
            if [ $[ ${VM_MiB} * ${Ki} / ${SZ_1G_Ki} ] -lt \
                ${vm_pages[${node},${SZ_1G_Ki}]} ]; then
                vm_pages[${node},${SZ_1G_Ki}]=$[ ${VM_MiB} * ${Ki} / ${SZ_1G_Ki} ]
            fi

            # Calculate the 2M pages based on amount of memory left over after
            # 1G pages accounted for
            vm_pages[${node},${SZ_2M_Ki}]=$[ (${Ki} * ${VM_MiB}
                - ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]})
                / ${SZ_2M_Ki} / 16 * 16 ]

            # Anything left over is 4K pages
            vm_pages[${node},${SZ_4K_Ki}]=$[ (${Ki} * ${VM_MiB}
                - ${SZ_2M_Ki} * ${vm_pages[${node},${SZ_2M_Ki}]}
               - ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]}) / ${SZ_4K_Ki} ]

            if [ ${vm_pages[${node},${SZ_4K_Ki}]} -lt ${min_4K} ]; then
                vm_pages[${node},${SZ_4K_Ki}]=0
            fi

            requested_VM_MiB=$[
                ${SZ_4K_Ki} * ${vm_pages[${node},${SZ_4K_Ki}]} / ${Ki}
                + ${SZ_2M_Ki} * ${vm_pages[${node},${SZ_2M_Ki}]} / ${Ki}
                + ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]} / ${Ki} ]
            log_error "VM memory reduced to ${requested_VM_MiB} MiB " \
                "using ${vm_pages[${node},${SZ_1G_Ki}]} 1G pages and " \
                "${vm_pages[${node},${SZ_2M_Ki}]} 2M pages"
        fi

        # Calculate total hugepages to be allocated.  Setting HUGE_MEMORY will
        # reset nr_hugepages. Always set values even if 0.
        if grep -q pdpe1gb /proc/cpuinfo
        then
            pages_1G=$[ ${vm_pages[${node},${SZ_1G_Ki}]} + ${vs_pages[${node},${SZ_1G_Ki}]} ]
            HUGE_MEMORY+=("node${node}:${SZ_1G_Ki}kB:${pages_1G}")
            pages_1G=$[ ${vm_pages[${node},${SZ_1G_Ki}]} ]
            VM_MEMORY_1G+=("node${node}:${SZ_1G_Ki}kB:${pages_1G}")
        fi
        pages_2M=$[ ${vm_pages[${node},${SZ_2M_Ki}]} + ${vs_pages[${node},${SZ_2M_Ki}]} ]
        HUGE_MEMORY+=("node${node}:${SZ_2M_Ki}kB:${pages_2M}")
        pages_2M=$[ ${vm_pages[${node},${SZ_2M_Ki}]} ]
        VM_MEMORY_2M+=("node${node}:${SZ_2M_Ki}kB:${pages_2M}")

        # Calculate maximum possible VM pages of a given pagesize
        max_vm_pages[${node},${SZ_2M_Ki}]=$[ ${Ki} * ${VM_MiB} / ${SZ_2M_Ki} / 16 * 16 ]
        max_vm_pages[${node},${SZ_1G_Ki}]=$[ ${Ki} * ${VM_MiB} / ${SZ_1G_Ki} ]

        # Calculate a few things to print out
        max_2M=${max_vm_pages[${node},${SZ_2M_Ki}]}
        max_1G=${max_vm_pages[${node},${SZ_1G_Ki}]}
        vm_4K_MiB=$[ ${SZ_4K_Ki} * ${vm_pages[${node},${SZ_4K_Ki}]} / ${Ki} ]
        vm_2M_MiB=$[ ${SZ_2M_Ki} * ${vm_pages[${node},${SZ_2M_Ki}]} / ${Ki} ]
        vm_1G_MiB=$[ ${SZ_1G_Ki} * ${vm_pages[${node},${SZ_1G_Ki}]} / ${Ki} ]
        vs_2M_MiB=$[ ${SZ_2M_Ki} * ${vs_pages[${node},${SZ_2M_Ki}]} / ${Ki} ]
        vs_1G_MiB=$[ ${SZ_1G_Ki} * ${vs_pages[${node},${SZ_1G_Ki}]} / ${Ki} ]
        log_debug "Memory: node:${node}, TOTAL:${NODE_TOTAL_MiB} MiB," \
            "INIT:${NODE_TOTAL_INIT_MiB} MiB," \
            "AVAIL:${AVAIL_MiB} MiB, PSS:${PSS_MiB} MiB," \
            "HTOT:${HTOT_MiB} MiB"
        log_debug "Memory: node:${node}," \
            "ENG:${ENG_MiB} MiB, VM:${VM_MiB} MiB," \
            "4K:${vm_4K_MiB} MiB, 2M:${vm_2M_MiB} MiB, 1G:${vm_1G_MiB} MiB," \
            "manual-set:${do_manual[$node]}"
        log_debug "Memory: node:${node}," \
            "max: 2M:${max_2M} pages, 1G:${max_1G} pages"
        log_debug "Memory: node:${node}," \
            "vswitch: 2M:${vs_2M_MiB} MiB, 1G:${vs_1G_MiB} MiB;" \
            "BASE:${base_memory[$node]} MiB reserved"
    done

    # Summarize overall lists and hugetlb
    log_debug "compute_hugetlb: ${HUGE_MEMORY[@]}"

    # Write out maximum possible hugepages of each type and total memory
    max_2M=""; max_1G=""; tot_MiB=""
    for ((node=0; node < N_NUMA; node++))
    do
        max_2M=$(append_list ${max_vm_pages[${node},${SZ_2M_Ki}]} ${max_2M})
        max_1G=$(append_list ${max_vm_pages[${node},${SZ_1G_Ki}]} ${max_1G})
        tot_MiB=$(append_list ${tot_memory[${node}]} ${tot_MiB})
    done
    CONF=/etc/nova/compute_hugepages_total.conf
    echo "# Compute total possible hugepages to allocate (generated: do not modify)" > ${CONF}
    echo "compute_hp_total_2M=${max_2M}" >> ${CONF}
    echo "compute_hp_total_1G=${max_1G}" >> ${CONF}
    echo "compute_total_MiB=${tot_MiB}" >> ${CONF}
    echo "" >> ${CONF}

    # Write out extended nova compute options; used with nova accounting.
    CONF=/etc/nova/compute_extend.conf
    echo "# Compute extended nova options (generated: do not modify)" > ${CONF}

    # memory allocations of each type
    vs_2M=""; vs_1G=""; vm_4K=""; vm_2M=""; vm_1G=""
    for ((node=0; node < N_NUMA; node++))
    do
        vs_2M=$(append_list ${vs_pages[${node},${SZ_2M_Ki}]} ${vs_2M})
        vs_1G=$(append_list ${vs_pages[${node},${SZ_1G_Ki}]} ${vs_1G})
        vm_4K=$(append_list ${vm_pages[${node},${SZ_4K_Ki}]} ${vm_4K})
        vm_2M=$(append_list ${vm_pages[${node},${SZ_2M_Ki}]} ${vm_2M})
        vm_1G=$(append_list ${vm_pages[${node},${SZ_1G_Ki}]} ${vm_1G})
    done
    echo "# memory options" >> ${CONF}
    echo "compute_vswitch_2M_pages=${vs_2M}" >> ${CONF}
    echo "compute_vswitch_1G_pages=${vs_1G}" >> ${CONF}
    echo "compute_vm_4K_pages=${vm_4K}" >> ${CONF}
    echo "compute_vm_2M_pages=${vm_2M}" >> ${CONF}
    echo "compute_vm_1G_pages=${vm_1G}" >> ${CONF}
    echo "" >> ${CONF}

    # Allocate hugepages of each pgsize for each NUMA node
    if [ ${do_huge} -eq 1 ]; then
        allocate_hugetlb_memory HUGE_MEMORY[@]

        # Write out current hugepages to configuration file,
        # keeping each individual array element quoted.
        q=(); for e in "${VM_MEMORY_2M[@]}"; do q+="\"${e}\" "; done
        r="${q[@]}"; r="${r%"${r##*[![:space:]]}"}" 
        sed -i "s#^COMPUTE_VM_MEMORY_2M=.*\$#COMPUTE_VM_MEMORY_2M=\($r\)#" ${RESERVE_CONF}

        q=(); for e in "${VM_MEMORY_1G[@]}"; do q+="\"${e}\" "; done
        r="${q[@]}"; r="${r%"${r##*[![:space:]]}"}" 
        sed -i "s#^COMPUTE_VM_MEMORY_1G=.*\$#COMPUTE_VM_MEMORY_1G=\($r\)#" ${RESERVE_CONF}
    fi
}

################################################################################
# Start/Setup all Compute node resources
# - Enabled a performance boost by mounting HugeTLBFS.
#   This reduces TLB entries, hence reduces processor cache-thrash.
# - Allocates aggregate nr_hugepages per NUMA node.
# - Mounts cgroups .
#
################################################################################
function start_compute() {
    local RET=0
    log_debug "start_compute"

    # Flush page cache
    sync; echo 3 > /proc/sys/vm/drop_caches

    # Determine cpu topology
    get_topology

    # Determine memory breakdown
    get_memory

    check_configuration
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to check configuration, rc=${RET}"
        return ${RET}
    fi

    # Mount HugeTLBFS for vswitch and libvirt
    mount_hugetlbfs_auto
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to auto mount HugeTLB filesystem(s), rc=${RET}"
        return ${RET}
    fi

    # Check that 2MB hugepages are available for libvirt
    MOUNT=/mnt/huge-2048kB
    mountpoint -q $MOUNT
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to mount 2048kB HugeTLB pages for libvirt, rc=${RET}, disabling huge"
        do_huge=0
    fi

    # Calculate aggregate hugepage memory requirements for vswitch + libvirt.
    # Set nr_hugepages per NUMA node.
    per_numa_resources
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to allocate sufficient resources, rc=${RET}"
        return ${RET}
    fi

    # Mount cgroups to take advantage of per domain accounting.
    if [ ${do_cgroups} -eq 1 ]; then
        mount_cgroups
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to mount cgroups, rc=${RET}"
            return ${RET}
        fi
    fi

    # Mount resctrl to allow Cache Allocation Technology per VM
    RESCTRL=/sys/fs/resctrl
    if [ -d $RESCTRL ]; then
        mount_resctrl
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to mount resctrl, rc=${RET}"
            return ${RET}
        fi
    fi

    # Set Power Management QoS resume latency constraints for all CPUs.
    set_pmqos_policy 
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to set Power Management QoS policy, rc=${RET}"
        return ${RET}
    fi

    # Disable IRQ balance service
    IRQBALANCED=/etc/init.d/irqbalanced
    if [ -x ${IRQBALANCED} ]; then
        ${IRQBALANCED} stop &> /dev/null
        RET=$?
        if [ ${RET} -ne 0 ]; then
            log_error "Failed to stop IRQ balance service, rc=${RET}"
            return ${RET}
        fi
    fi

    return ${RET}
}

################################################################################
# Start Action
################################################################################
function start() {
    local RET=0
    echo -n "Starting ${scriptname}: "

    # COMPUTE Node related setup
    if [ -x /etc/init.d/nova-compute ]
    then
        start_compute
        RET=$?
    fi

    print_status ${RET}
    return ${RET}
}

################################################################################
# Stop Action 
################################################################################
function stop
{
    local RET=0
    echo -n "Stopping ${scriptname}: "

    force_grub_update
    RET=$?

    print_status ${RET}
    return ${RET}
}


################################################################################
# Restart Action
################################################################################
function restart() {
    stop
    start
}

################################################################################
# Main Entry
#
################################################################################
case "$1" in
start)
    start
    ;;
stop)
    stop
    ;;
restart|reload)
    is_reconfig=1
    restart
    ;;
status)
    echo -n "OK"
    ;;
*)
    echo $"Usage: $0 {start|stop|restart|reload|status}"
    exit 1
esac

exit $?
