#!/bin/bash

################################################################################
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################

#
#  Purpose of this script is to copy the puppet-built
#  ifcfg-* network config files from the puppet dir
#  to the /etc/sysconfig/network-scripts/.  Only files that
#  are detected as different are copied.
#
#  Then for each network puppet config files that are different
#  from /etc/sysconfig/network-scripts/ version of the same config file,  perform a
#  network restart on the related iface.
#
#  Please note:  function is_eq_ifcfg() is used to determine if
#                cfg files are different
#

export IFNAME_INCLUDE="ifcfg-*"
export RTNAME_INCLUDE="route-*"
ACQUIRE_LOCK=1
RELEASE_LOCK=0

if [ ! -d /var/run/network-scripts.puppet/ ] ; then
    # No puppet files? Nothing to do!
    exit 1
fi

function log_it {
    logger "${0} ${1}"
}

function do_if_up {
    local iface=$1
    log_it "Bringing $iface up"
    /sbin/ifup $iface
}

function do_if_down {
    local iface=$1
    log_it "Bringing $iface down"
    /sbin/ifdown $iface
}

function do_rm {
    local theFile=$1
    log_it "Removing $theFile"
    /bin/rm  $theFile
}

function do_cp {
    local srcFile=$1
    local dstFile=$2
    log_it "copying network cfg $srcFile to $dstFile"
    cp  $srcFile $dstFile
}

# Return items in list1 that are not in list2
array_diff () {
    list1=${!1}
    list2=${!2}

    result=()
    l2=" ${list2[*]} "
    for item in ${list1[@]}; do
        if [[ ! $l2 =~ " $item " ]] ; then
            result+=($item)
        fi
    done

    echo  ${result[@]}
}

function normalized_cfg_attr_value {
    local cfg=$1
    local attr_name=$2
    local attr_value
    attr_value=$(cat $cfg | grep $attr_name= | awk -F "=" {'print $2'})


    #
    # Special case BONDING_OPTS attribute.
    #
    # The BONDING_OPTS attribute contains '=' characters, so is not correctly
    # parsed by splitting on '=' as done above.  This results in changes to
    # BONDING_OPTS not causing the interface to be restarted, so the old
    # BONDING_OPTS still be used.  Because this is only checking for changes,
    # rather than actually using the returned value, we can return the whole
    # line.
    #
    if [[ "${attr_name}" == "BONDING_OPTS" ]]; then
        echo "$(cat $cfg | grep $attr_name=)"
        return $(true)
    fi

    if [[ "${attr_name}" != "BOOTPROTO" ]]; then
        echo "${attr_value}"
        return $(true)
    fi
    #
    # Special case BOOTPROTO attribute.
    #
    # The BOOTPROTO attribute is not populated consistently by various aspects
    # of the system.  Different values are used to indicate a manually
    # configured interfaces (i.e., one that does not expect to have an IP
    # address) and so to avoid reconfiguring an interface that has different
    # values with the same meaning we normalize them here before making any
    # decisions.
    #
    # From a user perspective the values "manual", "none", and "" all have the
    # same meaning - an interface without an IP address while "dhcp" and
    # "static" are distinct values with a separate meaning.  In practice
    # however, the only value that matters from a ifup/ifdown script point of
    # view is "dhcp".  All other values are ignored.
    #
    # In our system we set BOOTPROTO to "static" to indicate that IP address
    # attributes exist and to "manual"/"none" to indicate that no IP address
    # attributes exist.  These are not needed by ifup/ifdown as it looks for
    # the "IPADDR" attribute whenever BOOTPROTO is set to anything other than
    # "dhcp".
    #
    if [[ "${attr_value}" == "none" ]]; then
        attr_value="none"
    fi
    if [[ "${attr_value}" == "manual" ]]; then
        attr_value="none"
    fi
    if [[ "${attr_value}" == "" ]]; then
        attr_value="none"
    fi
    echo "${attr_value}"
    return $(true)
}

#
# returns $(true) if cfg file ( $1 ) has property propName ( $2 ) with a value of propValue ( $3 )
#
function cfg_has_property_with_value {
    local cfg=$1
    local propname=$2
    local propvalue=$3
    if [ -f $cfg ]; then
        if [[ "$(normalized_cfg_attr_value $cfg $propname)" == "${propvalue}" ]]; then
            return $(true)
        fi
    fi
    return $(false)
}

#
# returns $(true) if cfg file is configured as a slave
#
function is_slave {
    cfg_has_property_with_value $1 "SLAVE" "yes"
    return $?
}

#
# returns $(true) if cfg file is configured for DHCP
#
function is_dhcp {
    cfg_has_property_with_value $1 "BOOTPROTO" "dhcp"
}

#
# returns $(true) if cfg file is configured as a VLAN interface
#
function is_vlan {
    cfg_has_property_with_value $1 "VLAN" "yes"
    return $?
}

#
# returns $(true) if cfg file is configured as an ethernet interface.  For the
# purposes of this script "ethernet" is considered as any interface that is not
# a vlan or a slave.  This includes both regular ethernet interfaces and bonded
# interfaces.
#
function is_ethernet {
    if ! is_vlan $1; then
        if ! is_slave $1; then
            return $(true)
        fi
    fi
    return $(false)
}

#
# returns $(true) if cfg file represents an interface of the specified type.
#
function iftype_filter {
    local iftype=$1

    return $(is_$iftype $2)
}

#
# returns $(true) if ifcfg files have the same number of VFs
#
#
function is_eq_sriov_numvfs {
    local cfg_1=$1
    local cfg_2=$2
    local sriov_numvfs_1
    sriov_numvfs_1=$(grep -o 'echo *[1-9].*sriov_numvfs' $cfg_1 | awk {'print $2'})
    local sriov_numvfs_2
    sriov_numvfs_2=$(grep -o 'echo *[1-9].*sriov_numvfs' $cfg_2 | awk {'print $2'})

    sriov_numvfs_1=${sriov_numvfs_1:-0}
    sriov_numvfs_2=${sriov_numvfs_2:-0}

    if [[ "${sriov_numvfs_1}" != "${sriov_numvfs_2}" ]]; then
        log_it "$cfg_1 and $cfg_2 differ on attribute sriov_numvfs [${sriov_numvfs_1}:${sriov_numvfs_2}]"
        return $(false)
    fi

    return $(true)
}

#
# returns $(true) if ifcfg files are equal
#
# Warning:  Only compares against cfg file attributes:
#            BOOTPROTO DEVICE IPADDR NETMASK GATEWAY MTU BONDING_OPTS SRIOV_NUMVFS
#
function is_eq_ifcfg {
    local cfg_1=$1
    local cfg_2=$2

    for attr in BOOTPROTO DEVICE IPADDR NETMASK GATEWAY MTU BONDING_OPTS; do
        local attr_value1
        attr_value1=$(normalized_cfg_attr_value $cfg_1 $attr)
        local attr_value2
        attr_value2=$(normalized_cfg_attr_value $cfg_2 $attr)
        if [[ "${attr_value1}" != "${attr_value2}"  ]]; then
            log_it "$cfg_1 and $cfg_2 differ on attribute $attr"
            return $(false)
        fi
    done

    is_eq_sriov_numvfs $1 $2
    return $?
}

# Synchronize with sysinv-agent audit (ifup/down to query link speed).
function sysinv_agent_lock {
    case $1 in
    $ACQUIRE_LOCK)
        local lock_file="/var/run/apply_network_config.lock"
        # Lock file should be the same as defined in sysinv agent code
        local lock_timeout=5
        local max=15
        local n=1
        LOCK_FD=0
        exec {LOCK_FD}>$lock_file
        while [[ $n -le $max ]]; do

            flock -w $lock_timeout $LOCK_FD && break
            log_it "Failed to get lock($LOCK_FD) after $lock_timeout seconds ($n/$max), will retry"
            sleep 1
            n=$(($n+1))
        done
        if [[ $n -gt $max ]]; then
            log_it "Failed to acquire lock($LOCK_FD) even after $max retries"
            exit 1
        fi
        ;;
    $RELEASE_LOCK)
        [[ $LOCK_FD -gt 0 ]] && flock -u $LOCK_FD
        ;;
    esac
}

# First thing to do is deal with the case of there being no routes left on an interface.
# In this case, there will be no route-<if> in the puppet directory.
# We'll just create an empty one so that the below will loop will work in all cases.

for rt_path in $(find /etc/sysconfig/network-scripts/ -name "${RTNAME_INCLUDE}"); do
    rt=$(basename $rt_path)

    if [ ! -e /var/run/network-scripts.puppet/$rt ]; then
        touch /var/run/network-scripts.puppet/$rt
    fi
done

for rt_path in $(find /var/run/network-scripts.puppet/ -name "${RTNAME_INCLUDE}"); do
    rt=$(basename $rt_path)
    iface_rt=${rt#route-}

    if [ -e /etc/sysconfig/network-scripts/$rt ]; then
        # There is an existing route file.  Check if there are changes.
        diff -I ".*Last generated.*" -q /var/run/network-scripts.puppet/$rt \
                                        /etc/sysconfig/network-scripts/$rt >/dev/null 2>&1

        if [ $? -ne 0 ] ; then
            # We may need to perform some manual route deletes
            # Look for route lines that are present in the current netscripts route file,
            # but not in the new puppet version.  Need to manually delete these routes.
            grep -v HEADER /etc/sysconfig/network-scripts/$rt | while read oldRouteLine
            do
                grepCmd="grep -q '$oldRouteLine' $rt_path > /dev/null"
                eval $grepCmd
                if [ $? -ne 0 ] ; then
                    log_it "Removing route: $oldRouteLine"
                    $(/usr/sbin/ip route del $oldRouteLine)
                fi
            done
        fi
    fi


    if [ -s /var/run/network-scripts.puppet/$rt ] ; then
        # Whether this is a new routes file or there are changes, ultimately we will need
        # to ifup the file to add any potentially new routes.

        do_cp /var/run/network-scripts.puppet/$rt /etc/sysconfig/network-scripts/$rt
        /etc/sysconfig/network-scripts/ifup-routes $iface_rt

    else
        # Puppet routes file is empty, because we created an empty one due to absence of any routes
        # so that our check with the existing netscripts routes would work.
        # Just delete the netscripts file as there are no static routes left on this interface.
        do_rm /etc/sysconfig/network-scripts/$rt
    fi

    # Puppet redhat.rb file does not support removing routes from the same resource file.
    # Need to smoke the temp one so it will be properly recreated next time.

    do_cp /var/run/network-scripts.puppet/$rt /var/run/network-scripts.puppet/$iface_rt.back
    do_rm /var/run/network-scripts.puppet/$rt

done




upDown=()
changed=()
for cfg_path in $(find /var/run/network-scripts.puppet/ -name "${IFNAME_INCLUDE}"); do
    cfg=$(basename $cfg_path)

    diff -I ".*Last generated.*" -q /var/run/network-scripts.puppet/$cfg \
                                    /etc/sysconfig/network-scripts/$cfg >/dev/null 2>&1

    if [ $? -ne 0 ] ; then
        # puppet file needs to be copied to network dir because diff detected
        changed+=($cfg)
        # but do we need to actually start the iface?
        if is_dhcp /var/run/network-scripts.puppet/$cfg   || \
           is_dhcp /etc/sysconfig/network-scripts/$cfg  ; then
           # if dhcp type iface, then too many possible attr's to compare against, so
           # just add cfg to the upDown list because we know (from above) cfg file is changed
            log_it "dhcp detected for $cfg - adding to upDown list"
            upDown+=($cfg)
        else
            # not in dhcp situation so check if any significant
            # cfg attributes have changed to warrant an iface restart
            is_eq_ifcfg /var/run/network-scripts.puppet/$cfg \
                        /etc/sysconfig/network-scripts/$cfg
            if [ $? -ne 0 ] ; then
                log_it "$cfg changed - adding to upDown list"
                upDown+=($cfg)
            fi
        fi
    fi
done

current=()
for f in $(find /etc/sysconfig/network-scripts/ -name "${IFNAME_INCLUDE}"); do
    current+=($(basename $f))
done

active=()
for f in $(find /var/run/network-scripts.puppet/ -name "${IFNAME_INCLUDE}"); do
    active+=($(basename $f))
done

# synchronize with sysinv-agent audit
sysinv_agent_lock $ACQUIRE_LOCK

remove=$(array_diff current[@] active[@])
for r in ${remove[@]}; do
    # Bring down interface before we execute network restart, interfaces
    # that do not have an ifcfg are not managed by init script
    iface=${r#ifcfg-}
    do_if_down $iface
    do_rm /etc/sysconfig/network-scripts/$r
done

# now down the changed ifaces by dealing with vlan interfaces first so that
# they are brought down gracefully (i.e., without taking their dependencies
# away unexpectedly).
for iftype in vlan ethernet; do
    for cfg in ${upDown[@]}; do
        ifcfg=/etc/sysconfig/network-scripts/$cfg
        if iftype_filter $iftype $ifcfg; then
            do_if_down ${ifcfg#ifcfg-}
        fi
    done
done

# now copy the puppet changed interfaces to /etc/sysconfig/network-scripts
for cfg in ${changed[@]}; do
    do_cp /var/run/network-scripts.puppet/$cfg /etc/sysconfig/network-scripts/$cfg
done

# now ifup changed ifaces by dealing with vlan interfaces last so that their
# dependencies are met before they are configured.
for iftype in ethernet vlan; do
    for cfg in ${upDown[@]}; do
        ifcfg=/var/run/network-scripts.puppet/$cfg
        if iftype_filter $iftype $ifcfg; then
            do_if_up ${ifcfg#ifcfg-}
        fi
    done
done

# unlock: synchronize with sysinv-agent audit
sysinv_agent_lock $RELEASE_LOCK
