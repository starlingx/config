#!/bin/bash
################################################################################
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################

source /etc/platform/platform.conf

################################################################################
# Utility function to expand a sequence of numbers (e.g., 0-7,16-23)
################################################################################
function expand_sequence {
    SEQUENCE=(${1//,/ })
    DELIMITER=${2:-","}

    LIST=
    for entry in ${SEQUENCE[@]}; do
        range=(${entry/-/ })
        a=${range[0]}
        b=${range[1]:-${range[0]}}

        for i in $(seq $a $b); do
            LIST="${LIST}${DELIMITER}${i}"
        done
    done
    echo ${LIST:1}
}

################################################################################
# Append a string to comma separated list string
################################################################################
function append_list {
    local PUSH=$1
    local LIST=$2
    if [ -z "${LIST}" ]; then
        LIST=${PUSH}
    else
        LIST="${LIST},${PUSH}"
    fi
    echo ${LIST}
    return 0
}

################################################################################
# Condense a sequence of numbers to a list of ranges (e.g, 7-12,15-16)
################################################################################
function condense_sequence {
    local arr=( $(printf '%s\n' "$@" | sort -n) )
    local first
    local last
    local cpulist=""
    for ((i=0; i < ${#arr[@]}; i++)); do
        num=${arr[$i]}
        if [[ -z $first ]]; then
            first=$num
            last=$num
            continue
        fi
        if [[ num -ne $((last + 1)) ]]; then
            if [[ first -eq last ]]; then
                cpulist=$(append_list ${first} ${cpulist})
            else
                cpulist=$(append_list "${first}-${last}" ${cpulist})
            fi
            first=$num
            last=$num
        else
            : $((last++))
        fi
    done
    if [[ first -eq last ]]; then
        cpulist=$(append_list ${first} ${cpulist})
    else
        cpulist=$(append_list "${first}-${last}" ${cpulist})
    fi
    echo "$cpulist"
}

################################################################################
# Converts a CPULIST (e.g., 0-7,16-23) to a CPUMAP (e.g., 0x00FF00FF).  The
# CPU map is returned as a string representation of a large hexidecimal
# number but without the leading "0x" characters.
#
################################################################################
function cpulist_to_cpumap {
    local CPULIST=$1
    local NR_CPUS=$2
    local CPUMAP=0
    local CPUID=0
    if [ -z "${NR_CPUS}" ] || [ ${NR_CPUS} -eq 0 ]; then
        echo 0
        return 0
    fi
    for CPUID in $(expand_sequence $CPULIST " "); do
        if [ "${CPUID}" -lt "${NR_CPUS}" ]; then
            CPUMAP=$(echo "${CPUMAP} + (2^${CPUID})" | bc -l)
        fi
    done

    echo "obase=16;ibase=10;${CPUMAP}" | bc -l
    return 0
}

################################################################################
# Converts a CPUMAP (e.g., 0x00FF00FF) to a CPULIST (e.g., 0-7,16-23).  The
# CPUMAP is expected in hexidecimal (base=10) form without the leading "0x"
# characters.
#
################################################################################
function cpumap_to_cpulist {
    local CPUMAP
    CPUMAP=$(echo "obase=10;ibase=16;$1" | bc -l)
    local NR_CPUS=$2
    local list=()
    local cpulist=""
    for((i=0; i < NR_CPUS; i++))
    do
        ## Since 'bc' does not support any bitwise operators this expression:
        ##     if (CPUMAP & (1 << CPUID))
        ## has to be rewritten like this:
        ##     if (CPUMAP % (2**(CPUID+1)) > ((2**(CPUID)) - 1))
        ##
        ISSET=$(echo "scale=0; (${CPUMAP} % 2^(${i}+1)) > (2^${i})-1" | bc -l)
        if [ "${ISSET}" -ne 0 ]; then
            list+=($i)
        fi
    done
    cpulist=$(condense_sequence ${list[@]} )
    echo "$cpulist"
    return 0
}

################################################################################
# Bitwise NOT of a hexidecimal representation of a CPULIST.   The value is
# returned as a hexidecimal value but without the leading "0x" characters
#
################################################################################
function invert_cpumap {
    local CPUMAP
    CPUMAP=$(echo "obase=10;ibase=16;$1" | bc -l)
    local NR_CPUS=$2
    local INVERSE_CPUMAP=0

    for CPUID in $(seq 0 $((NR_CPUS - 1))); do
        ## See comment in previous function
        ISSET=$(echo "scale=0; (${CPUMAP} % 2^(${CPUID}+1)) > (2^${CPUID})-1" | bc -l)
        if [ "${ISSET}" -eq 1 ]; then
            continue
        fi

        INVERSE_CPUMAP=$(echo "${INVERSE_CPUMAP} + (2^${CPUID})" | bc -l)
    done

    echo "obase=16;ibase=10;${INVERSE_CPUMAP}" | bc -l
    return 0
}

################################################################################
# Builds the complement representation of a CPULIST
#
################################################################################
function invert_cpulist {
    local CPULIST=$1
    local NR_CPUS=$2
    local CPUMAP
    CPUMAP=$(cpulist_to_cpumap ${CPULIST} ${NR_CPUS})
    cpumap_to_cpulist $(invert_cpumap ${CPUMAP} ${NR_CPUS}) ${NR_CPUS}
    return 0
}

################################################################################
# in_list() - check whether item is contained in list
#  param: item
#  param: list  (i.e. 0-3,8-11)
#  returns: 0 - item is contained in list;
#           1 - item is not contained in list
#
################################################################################
function in_list {
    local item="$1"
    local list="$2"

    # expand list format 0-3,8-11 to a full sequence {0..3} {8..11}
    local exp_list
    exp_list=$(echo ${list} | \
        sed -e 's#,# #g' -e 's#\([0-9]*\)-\([0-9]*\)#{\1\.\.\2}#g')

    local e
    for e in $(eval echo ${exp_list}); do
        [[ "$e" == "$item" ]] && return 0
    done
    return 1
}

################################################################################
# any_in_list() - check if any item of sublist is contained in list
#  param: sublist
#  param: list
#  returns: 0 - an item of sublist is contained in list;
#           1 - no sublist items contained in list
#
################################################################################
function any_in_list {
    local sublist="$1"
    local list="$2"
    local e
    local exp_list

    # expand list format 0-3,8-11 to a full sequence {0..3} {8..11}
    exp_list=$(echo ${list} | \
        sed -e 's#,# #g' -e 's#\([0-9]*\)-\([0-9]*\)#{\1\.\.\2}#g')
    declare -A a_list
    for e in $(eval echo ${exp_list}); do
        a_list[$e]=1
    done

    # expand list format 0-3,8-11 to a full sequence {0..3} {8..11}
    exp_list=$(echo ${sublist} | \
        sed -e 's#,# #g' -e 's#\([0-9]*\)-\([0-9]*\)#{\1\.\.\2}#g')
    declare -A a_sublist
    for e in $(eval echo ${exp_list}); do
        a_sublist[$e]=1
    done

    # Check if any element of sublist is in list
    for e in "${!a_sublist[@]}"; do
        if [[ "${a_list[$e]}" == 1 ]]; then
            return 0 # matches
        fi
    done
    return 1 # no match
}

################################################################################
# Return list of CPUs reserved for platform
################################################################################
function get_platform_cpu_list {
    ## Define platform cpulist based on engineering a number of cores and
    ## whether this is a combo or not, and include SMT siblings.
    if [[ $subfunction = *worker* ]]; then
        RESERVE_CONF="/etc/platform/worker_reserved.conf"
        [[ -e ${RESERVE_CONF} ]] && source ${RESERVE_CONF}
        if [ -n "$PLATFORM_CPU_LIST" ];then
            echo "$PLATFORM_CPU_LIST"
            return 0
        fi
    fi

    local PLATFORM_SOCKET=0
    local PLATFORM_START=0
    local PLATFORM_CORES=1
    if [ "$nodetype" = "controller" ]; then
        PLATFORM_CORES=$(($PLATFORM_CORES+1))
    fi
    local PLATFORM_CPULIST
    PLATFORM_CPULIST=$(topology_to_cpulist ${PLATFORM_SOCKET} ${PLATFORM_START} ${PLATFORM_CORES})
    echo ${PLATFORM_CPULIST}
}

################################################################################
# Return list of CPUs reserved for vswitch
################################################################################
function get_vswitch_cpu_list {
    ## Define default avp cpulist based on engineered number of platform cores,
    ## engineered avp cores, and include SMT siblings.
    if [[ $subfunction = *worker* ]]; then
        VSWITCH_CONF="/etc/vswitch/vswitch.conf"
        [[ -e ${VSWITCH_CONF} ]] && source ${VSWITCH_CONF}
        if [ -n "$VSWITCH_CPU_LIST" ];then
            echo "$VSWITCH_CPU_LIST"
            return 0
        fi
    fi

    local N_CORES_IN_PKG
    N_CORES_IN_PKG=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/^cpu cores/ {n = $4} END { print (n>0) ? n : 1 }')
    # engineer platform cores
    local PLATFORM_CORES=1
    if [ "$nodetype" = "controller" ]; then
        PLATFORM_CORES=$(($PLATFORM_CORES+1))
    fi

    # engineer AVP cores
    local AVP_SOCKET=0
    local AVP_START=${PLATFORM_CORES}
    local AVP_CORES=1
    if [ ${N_CORES_IN_PKG} -gt 4 ]; then
        AVP_CORES=$(($AVP_CORES+1))
    fi
    local AVP_CPULIST
    AVP_CPULIST=$(topology_to_cpulist ${AVP_SOCKET} ${AVP_START} ${AVP_CORES})
    echo ${AVP_CPULIST}
}

################################################################################
# vswitch_expanded_cpu_list() - compute the vswitch cpu list, including it's siblings
################################################################################
function vswitch_expanded_cpu_list {
    list=$(get_vswitch_cpu_list)

    # Expand vswitch cpulist
    vswitch_cpulist=$(expand_sequence ${list} " ")

    cpulist=""
    for e in $vswitch_cpulist; do
        # claim hyperthread siblings if SMT enabled
        SIBLINGS_CPULIST=$(cat /sys/devices/system/cpu/cpu${e}/topology/thread_siblings_list 2>/dev/null)
        siblings_cpulist=$(expand_sequence ${SIBLINGS_CPULIST} " ")
        for s in $siblings_cpulist; do
            in_list ${s} ${cpulist}
            if [ $? -eq 1 ]; then
                cpulist=$(append_list ${s} ${cpulist})
            fi
        done
    done

    echo "$cpulist"
    return 0
}

################################################################################
# platform_expanded_cpu_list() - compute the platform cpu list, including it's siblings
################################################################################
function platform_expanded_cpu_list {
    list=$(get_platform_cpu_list)

    # Expand platform cpulist
    platform_cpulist=$(expand_sequence ${list} " ")

    cpulist=""
    for e in $platform_cpulist; do
        # claim hyperthread siblings if SMT enabled
        SIBLINGS_CPULIST=$(cat /sys/devices/system/cpu/cpu${e}/topology/thread_siblings_list 2>/dev/null)
        siblings_cpulist=$(expand_sequence ${SIBLINGS_CPULIST} " ")
        for s in $siblings_cpulist; do
            in_list ${s} ${cpulist}
            if [ $? -eq 1 ]; then
                cpulist=$(append_list ${s} ${cpulist})
            fi
        done
    done

    echo "$cpulist"
    return 0
}

################################################################################
# Return list of CPUs based on cpu topology.  Select the socket, starting core
# within the socket, select number of cores, and SMT siblings.
################################################################################
function topology_to_cpulist {
    local SOCKET=$1
    local CORE_START=$2
    local NUM_CORES=$3
    local CPULIST
    CPULIST=$(cat /proc/cpuinfo 2>/dev/null | perl -sne \
'BEGIN { %T = {}; %H = {}; $L = $P = $C = $S = 0; }
{
    if (/processor\s+:\s+(\d+)/) { $L = $1; }
    if (/physical id\s+:\s+(\d+)/) { $P = $1; }
    if (/core id\s+:\s+(\d+)/) {
        $C = $1;
        $T{$P}{$C}++;
        $S = $T{$P}{$C};
        $H{$P}{$C}{$S} = $L;
    }
}
END {
    @cores = sort { $a <=> $b } keys $T{$socket};
    @sel_cores = splice @cores, $core_start, $num_cores;
    @lcpus = ();
    for $C (@sel_cores) {
        for $S (sort {$a <=> $b } keys %{ $H{$socket}{$C} }) {
            push @lcpus, $H{$socket}{$C}{$S};
        }
    }
    printf "%s\n", join(",", @lcpus);
}' -- -socket=${SOCKET} -core_start=${CORE_START} -num_cores=${NUM_CORES})
    echo ${CPULIST}
}
