#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

NAME=$(basename "$0")
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
SYSCTL_FILE="/etc/sysctl.conf"
LOG_FILE="/var/log/software.log"

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "$LOG_FILE" 2>&1
}

if [[ "${ACTION}" == "activate" ]]; then
    log "Ensure CIS Benchmark Standards are met from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

    # Ensure config is set correctly
    grep -q "^net.ipv4.conf.default.rp_filter" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter=1/" "$SYSCTL_FILE" || \
        echo "net.ipv4.conf.default.rp_filter=1" >> "$SYSCTL_FILE"

    grep -q "^net.ipv4.conf.all.rp_filter" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter=1/" "$SYSCTL_FILE" || \
        echo "net.ipv4.conf.all.rp_filter=1" >> "$SYSCTL_FILE"

    grep -q "net.ipv4.tcp_syncookies" "$SYSCTL_FILE" && \
        sed -i "s/^#*\s*net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/" "$SYSCTL_FILE" || \
        echo "net.ipv4.tcp_syncookies=1" >> "$SYSCTL_FILE"

    grep -q "net.ipv4.icmp_echo_ignore_broadcasts" "$SYSCTL_FILE" && \
        sed -i "s/^#*\s*net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts=1/" "$SYSCTL_FILE" || \
        echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> "$SYSCTL_FILE"

    grep -q "net.ipv4.conf.all.accept_source_route" "$SYSCTL_FILE" && \
        sed -i "s/^#*\s*net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route=0/" "$SYSCTL_FILE" || \
        echo "net.ipv4.conf.all.accept_source_route=0" >> "$SYSCTL_FILE"

    # Apply changes
    sysctl --system &>/dev/null
    log "Applied CIS Benchmark required config"

elif [[ "${ACTION}" == "activate-rollback" ]]; then
    log "Rolling back CIS Benchmark changes from release $FROM_RELEASE to $TO_RELEASE"

    # Reverse config
    grep -q "^net.ipv4.conf.default.rp_filter" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter=0/" "$SYSCTL_FILE"

    grep -q "^net.ipv4.conf.all.rp_filter" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter=0/" "$SYSCTL_FILE"

    grep -q "^net.ipv4.tcp_syncookies" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.tcp_syncookies.*/#net.ipv4.tcp_syncookies=1/" "$SYSCTL_FILE"

    grep -q "^net.ipv4.icmp_echo_ignore_broadcasts" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.icmp_echo_ignore_broadcasts.*/#net.ipv4.icmp_echo_ignore_broadcasts=1/" "$SYSCTL_FILE"

    grep -q "^net.ipv4.conf.all.accept_source_route" "$SYSCTL_FILE" && \
        sed -i "s/^net.ipv4.conf.all.accept_source_route.*/#net.ipv4.conf.all.accept_source_route=0/" "$SYSCTL_FILE"

    # Apply changes
    sysctl --system &>/dev/null
    log "Rollback applied: Restored previous values"

else
    exit 0
fi
