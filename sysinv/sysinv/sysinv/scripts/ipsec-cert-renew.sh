#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#

#
# This script checks validation of IPsec certificates, and call
# ipsec-client to renew them if necessary.
#

# Renew certificates 15 days before expiration
declare -r CUTOFF_DAYS=15
declare -r CUTOFF_DAYS_S=$((${CUTOFF_DAYS}*24*3600))

NAME=$(basename $0)
KUBE_CONFIG=/etc/kubernetes/admin.conf
IPSEC_CERT_DIR=/etc/swanctl/x509
IPSEC_CERT_PATH="$IPSEC_CERT_DIR/system-ipsec-certificate-${HOSTNAME}.crt"
ERR_CA=0
ERR_CERT=0
ERR_RENEW=0
RENEWAL_REQUIRED=0
RETRY_INTERVAL=15

# Log info message to /var/log/cron.log
function LOG_info {
    logger -p cron.info -t "${NAME}($$): " "${@}"
}

# Log warning message to /var/log/cron.log
function LOG_warn {
    logger -p cron.warn -t "${NAME}($$): " "${@}"
}

# Log error message to /var/log/cron.log
function LOG_error {
    logger -p cron.error -t "${NAME}($$): " "${@}"
}

# Retrieve a certificate's valid time by openssl
time_left_s_by_openssl() {
    local time_left_s=""
    local exp_date=""
    exp_date=$(openssl x509 -in "$1" -enddate -noout| awk -F"=" '{print $2}')
    if [ "x${exp_date}" != "x" ]; then
        exp_date_s=$(date -d "${exp_date}" +%s)
        current_date_s=$(date +%s)
        time_left_s=$((${exp_date_s}-${current_date_s}))
    fi
    echo $time_left_s
}

# Postpone random seconds within an hour, to avoid simultaneous cert renewal on all hosts.
# The algorithm guarantees the random seconds is unique per host.
seed=$(( $(hostname | cksum | awk '{print $1}') ^ $(date +%s) ))
RANDOM=$seed

delay=$(( RANDOM % 3600 ))

LOG_info "Sleeping for ${delay} seconds to avoid simultaneous certificate renewal among hosts."
sleep ${delay}

# Check if it's time to renew IPsec certificate.
if [ ${ERR_CERT} -eq 0 ]; then
    time_left_s=$(time_left_s_by_openssl "${IPSEC_CERT_PATH}")
    if [ "x${time_left_s}" = "x" ]; then
        LOG_error "Failed to retrieve expiry date from ${IPSEC_CERT_PATH}"
        ERR_CERT=1
    fi
fi

if [ ${ERR_CERT} -eq 0 ]; then
    if [ "${time_left_s}" -lt "${CUTOFF_DAYS_S}" ]; then
        LOG_info "IPsec certificate will expire in ${time_left_s}s, will be renewed."
        RENEWAL_REQUIRED=1
    fi
fi

# Call ipsec-client to renew IPsec certificates if trusted CA and/or
# IPsec cert renewal is required.
if [ $RENEWAL_REQUIRED -eq 1 ]; then
    # Try 3 times in case if fails
    ERR_RENEW=1
    for i in {1..3}; do
        ipsec-client -o 2 pxecontroller
        if [ $? -ne 0 ]; then
            LOG_warn "ipsec-client renew cert try ${i} failed, retry in ${RETRY_INTERVAL} seconds ..."
            sleep ${RETRY_INTERVAL}
        else
            ERR_RENEW=0
            break
        fi
    done
    if [ ${ERR_RENEW} -ne 0 ]; then
        LOG_error "ipsec-client failed to renew IPsec certificates."
    else
        LOG_info "IPsec certificate successfully renewed."
    fi
else
    if [ ${ERR_CA} -ne 0 ] || [ ${ERR_CERT} -ne 0 ]; then
        ERR_RENEW=1
    fi
fi

# Raise alarm if anyting goes wrong.
if [ ${ERR_RENEW} -ne 0 ]; then
    /usr/local/bin/fmClientCli -c "### ###250.004###set###host###host=${HOSTNAME}### ###major###IPsec certificates renewal failed.###operational-violation### ###Check cron.log and ipsec-auth.log, fix the issue and rerun $NAME.### ### ###"
else
    /usr/local/bin/fmClientCli -A "250.004" &> /dev/null
    if [ $? -eq 0 ]; then
        /usr/local/bin/fmClientCli -d "###250.004###host=${HOSTNAME}###"
    fi
fi
