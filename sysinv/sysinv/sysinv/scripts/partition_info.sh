#!/bin/bash
# -*- encoding: utf-8 -*-
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Logging info.
LOG_PATH=/var/log/
LOG_FILE=$LOG_PATH/sysinv.log
LOG_LEVEL=NORMAL  # DEBUG
verbose=0

# Logging function.
wlog() {
    # Syntax: "wlog <name> <err_lvl> <log_msg> [print_trace]"
    # err_lvl should be INFO, WARN, ERROR or DEBUG
    #  o INFO - state transitions & normal messages
    #  o WARN - unexpected events (i.e. processes marked as down)
    #  o ERROR - hang messages and unexpected errors
    #  o DEBUG - print debug messages
    if [ -z "$LOG_FILE" ] || [ "$LOG_LEVEL" != "DEBUG" ] && [ "$2" = "DEBUG" ]; then
        # hide messages
        return
    fi

    local head
    head="$(date "+%Y-%m-%d %H:%M:%S.%3N") $0 $1"
    echo "$head $2: $3" >> $LOG_FILE
    if [ "$4" = "print_trace" ]; then
        # Print out the stack trace
        if [ ${#FUNCNAME[@]} -gt 1 ]; then
            echo "$head   Call trace:" >> $LOG_FILE
            for ((i=0;i<${#FUNCNAME[@]}-1;i++)); do
                echo "$head     $i: ${BASH_SOURCE[$i+1]}:${BASH_LINENO[$i]} ${FUNCNAME[$i]}(...)" >> $LOG_FILE
            done
        fi
    fi
}

device_path=$1 && shift
sfdisk_part_info=$(sfdisk -l $device_path)
part_numbers=( `echo "$sfdisk_part_info" | awk '$1 == "Device" {i=1; next}; i {print $1}' | grep -o '[0-9]\+'` )
sector_size=$(blockdev --getss $device_path)

for part_number in "${part_numbers[@]}"; do
    device="${device_path}${part_number}"
    # Parse the output and put it in the right return format.
    part_type_guid=$(sfdisk --part-type $device_path $part_number)
    part_type_name=$(echo "$sfdisk_part_info" | grep -w $device | awk '{print substr($0, index($0, $6))}' | tr ' ' '.')
    part_guid=$(sfdisk --part-uuid $device_path $part_number)
    part_start_mib=$(($(echo "$sfdisk_part_info" | grep -w $device | awk '{print $2}') * $sector_size / (1024*1024)))
    part_end_mib=$((($(echo "$sfdisk_part_info" | grep -w $device | awk '{print $3}') * $sector_size / (1024*1024)) + 1))
    part_size_mib=$((part_end_mib-part_start_mib))
    part_device_node=$(realpath $device_path)$part_number
    if [ "$part_type_name" == "unknown" ]; then
        part_type_name=$(sfdisk --part-label $device_path $part_number | tr ' ' '.')
    fi

    line+="$part_number $part_device_node $part_type_guid $part_type_name $part_guid $part_start_mib $part_end_mib $part_size_mib;"
done

echo $line
