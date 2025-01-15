#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
# Copyright (c) 2021-2025 Wind River Systems, Inc.
#

. /usr/bin/tsconfig

#
# This script is to rotate kubernetes cluster certificates automatically
#

source /etc/platform/openrc

# Check if a Kubernetes upgrade is in progress
check_upgrade_status() {
    local kube_upgrade_status
    kube_upgrade_status=$(system kube-upgrade-show)
    if [ "$kube_upgrade_status" != "A kubernetes upgrade is not in progress" ]; then
        return 1
    fi
    return 0
}

# Check for K8S upgrade in progress and wait an hour and recheck.
# Number of attempts to check upgrade status
MAX_ATTEMPTS=2
ATTEMPT=0
K8S_UPGRADE_WAITING_TIME=3600

while ! check_upgrade_status; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
        echo "Kubernetes upgrade is still in progress after $ATTEMPT attempts. Exiting script."
        # Exit here is OK since this will be called via cron next day.
        exit 1
    fi
    sleep $K8S_UPGRADE_WAITING_TIME
done

# Renew certificates 15 days before expiration
declare -r CUTOFF_DAYS=15
declare -r CUTOFF_DAYS_S=$((${CUTOFF_DAYS}*24*3600))

# Temporary working directory
TEMP_WORK_DIR="/tmp/kube_cert_rotation"

# Expiration date of k8s certs

# Tries ga command version, failing over to alpha command
kubeadm certs -h &> /dev/null
if [ $? -eq 0 ]; then
    CERT_CMD='certs'
else
    CERT_CMD='alpha certs'
fi

CERT_EXP_DATES=$(kubeadm $CERT_CMD check-expiration)
# After a long period offline all k8s certs may expire and kubeadm command will fail completely
# Here we save the return code so that it can be used later in the time_left_s function
RC_CERT_EXP_DATES=$?
if [ $RC_CERT_EXP_DATES -ne 0 ]; then
    echo "Failed to read certificates with 'kubeadm $CERT_CMD check-expiration. Will assume certs are expired."
fi

# Check if k8s certificate exist. Return 0 for no and 1 for yes.
k8s_cert_exists() {
    echo "${CERT_EXP_DATES}" | grep "^$1 " 1>/dev/null
    return $?
}

# Time left in seconds for a cert
time_left_s() {
    local time_left_s=""
    local exp_date=""
    exp_date=$(echo "${CERT_EXP_DATES}" | grep "^$1 " | grep -oE '[a-zA-Z]{3} [0-3][0-9], [0-9]{4} ([0-1][0-9]|2[0-3]):[0-5][0-9] UTC')
    if [ "x${exp_date}" != "x" ]; then
        exp_date_s=$(date -d "${exp_date}" +%s)
        current_date_s=$(date +%s)
        time_left_s=$((${exp_date_s}-${current_date_s}))
    fi
    echo ${time_left_s}
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
    echo ${time_left_s}
}

# Renew kubernetes certificates
# return value:
# 0: renewed successfully
# 255: no need to renew
# 1: renewal failed
renew_cert() {
    local ret=0
    local time_left_s=""

    # A bad return code from kubeadm means we can safely assume all k8s certs have expired
    if [ $RC_CERT_EXP_DATES -ne 0 ]; then
        kubeadm $CERT_CMD renew $1
        if [ $? -ne 0 ]; then
            ret=1
        fi
        return ${ret}
    fi

    k8s_cert_exists "$1"
    if [ $? -ne 0 ]; then
        echo "Skipping certificate ${1} as it does exist in 'kubeadm certs check-expiration'"
        return ${ret}
    fi

    time_left_s=$(time_left_s "$1")
    if [ "x${time_left_s}" != "x" ]; then
        if [ ${time_left_s} -lt ${CUTOFF_DAYS_S} ]; then
            kubeadm $CERT_CMD renew $1
            if [ $? -ne 0 ]; then
                ret=1
            fi
        else
            ret=255
        fi
    else
        ret=1
    fi
    return ${ret}
}

# Renew certificate using openssl
# return value:
# 0: renewed successfully
# 255: no need to renew
# 1: renewal failed
renew_cert_by_openssl() {
    local ret=0
    local time_left_s=""
    if [ ! -f "$1/$2.crt" ]; then
        return 255
    fi
    time_left_s=$(time_left_s_by_openssl "$1/$2.crt")
    if [ "x${time_left_s}" != "x" ]; then
        if [ ${time_left_s} -lt ${CUTOFF_DAYS_S} ]; then
            # Create csr config file
            echo "$3" > "${TEMP_WORK_DIR}/$2_csr.conf"
            if [ $? -ne 0 ]; then
                ret=1
            fi
            # generate private key
            if [ $ret -eq 0 ]; then
                openssl genpkey -out "${TEMP_WORK_DIR}/$2.key" -algorithm RSA -pkeyopt rsa_keygen_bits:4096
                if [ $? -ne 0 ]; then
                    ret=1
                fi
            fi
            # generate CSR
            if [ $ret -eq 0 ]; then
                openssl req -new -key "${TEMP_WORK_DIR}/$2.key" -out "${TEMP_WORK_DIR}/$2.csr" -config "${TEMP_WORK_DIR}/$2_csr.conf"
                if [ $? -ne 0 ]; then
                    ret=1
                fi
            fi
            # generate certificate
            if [ $ret -eq 0 ]; then
                openssl x509 -req -in "${TEMP_WORK_DIR}/$2.csr" -CA /etc/etcd/ca.crt -CAkey /etc/etcd/ca.key -CAcreateserial \
                -out "${TEMP_WORK_DIR}/$2.crt" -days 365 -extensions v3_req -extfile "${TEMP_WORK_DIR}/$2_csr.conf"
                if [ $? -ne 0 ]; then
                    ret=1
                fi
            fi
            # replace the existing cert file
            if [ $ret -eq 0 ]; then
                mv "${TEMP_WORK_DIR}/$2.crt" "$1/$2.crt"
                if [ $? -ne 0 ]; then
                    ret=1
                fi
            fi
            # replace the existing key file
            if [ $ret -eq 0 ]; then
                mv "${TEMP_WORK_DIR}/$2.key" "$1/$2.key"
                if [ $? -ne 0 ]; then
                    ret=1
                fi
            fi
        else
            ret=255
        fi
    else
        ret=1
    fi
    return ${ret}
}

# Get cluster host floating IP address
get_cluster_host_floating_ip() {
    local floating_ip=""
    floating_ip=$(cat /etc/kubernetes/admin.conf | grep "server:" | awk -F"//" '{print $2}' | tr -d "[]" | sed -e s/:6443//)
    echo ${floating_ip}
}

# Stops execution when sourced from other scripts. Only proceeds when called directly.
(return 0 2>/dev/null) && sourced=1 || sourced=0
if [[ "$sourced" -eq "1" ]]; then
    return 0
fi

ERR=0
ERR_REASON=""
RESTART_APISERVER=0
RESTART_CONTROLLER_MANAGER=0
RESTART_SCHEDULER=0
RESTART_SYSINV=0
RESTART_CERT_MON=0
RESTART_ETCD=0

# Fist check the validity of the Root CAs in /etc/kubernetes/pki/ca.crt and /etc/etcd/ca.crt
# If they are expired the process should not continue
for CA in /etc/kubernetes/pki/ca.crt /etc/etcd/ca.crt;
do
    sudo cat ${CA} | openssl x509 -checkend 0 >/dev/null
    RC=$?
    if [ ${RC} -eq 1 ]; then
        ERR_REASON="${CA} Root CA is expired. Leaf certificates renewal will not be attempted."
        ERR=1
    fi
done

# step 1, renew kubernetes certificates
# Renew apiserver certificate
if [ ${ERR} -eq 0 ]; then
    # The extra space in 'apiserver ' is to distinguish other names with apiserver in them.
    renew_cert 'apiserver '
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_APISERVER=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew apiserver certificate."
        ERR=1
    fi
fi
# Renew apiserver kubelet client certificate
if [ ${ERR} -eq 0 ]; then
    renew_cert 'apiserver-kubelet-client'
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_APISERVER=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew apiserver-kubelet-client certificate."
        ERR=1
    fi
fi
# Renew front proxy client certificate
if [ ${ERR} -eq 0 ]; then
    renew_cert 'front-proxy-client'
    if [ $? -eq 1 ]; then
        ERR_REASON="Failed to renew front-proxy-client certificate."
        ERR=1
    fi
fi
# Renew certs in admin.conf
if [ ${ERR} -eq 0 ]; then
    renew_cert 'admin.conf'
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_SYSINV=1
        RESTART_CERT_MON=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew admin.conf certificate."
        ERR=1
    fi
fi
# Renew cert super-admin.conf
if [ ${ERR} -eq 0 ]; then
    renew_cert 'super-admin.conf'
    result=$?
    if [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew super-admin.conf certificate."
        ERR=1
    fi
fi
# Renew certs in controller-manager.conf
if [ ${ERR} -eq 0 ]; then
    renew_cert 'controller-manager.conf'
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_CONTROLLER_MANAGER=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew controller-manager.conf certificate."
        ERR=1
    fi
fi
# Renew certs in scheduler.conf
if [ ${ERR} -eq 0 ]; then
    renew_cert 'scheduler.conf'
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_SCHEDULER=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew scheduler.conf certificate."
        ERR=1
    fi
fi

# Create temporary working directory
if [ ${ERR} -eq 0 ]; then
    mkdir -p ${TEMP_WORK_DIR}
    chmod 0600 ${TEMP_WORK_DIR}
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to create temporary working directory."
        ERR=1
    fi
fi

# Get cluster host floating IP address
if [ ${ERR} -eq 0 ]; then
    floating_ip=$(get_cluster_host_floating_ip)
    if [ "x${floating_ip}" == "x" ]; then
        ERR_REASON="Failed to retrieve cluster host floating IP address."
        ERR=1
    fi
fi

# Renew apiserver-etcd-client certificate
if [ ${ERR} -eq 0 ]; then
    config="
    [req]
    prompt = no
    x509_extensions = v3_req
    distinguished_name = dn
    [dn]
    CN = apiserver-etcd-client
    [v3_req]
    keyUsage = critical, Digital Signature, Key Encipherment
    extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
    subjectAltName = @alt_names
    [alt_names]
    IP.1 = ${floating_ip}
    IP.2 = 127.0.0.1
    "
    renew_cert_by_openssl "/etc/kubernetes/pki" "apiserver-etcd-client" "${config}"
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_APISERVER=1
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew apiserver-etcd-client certificate."
        ERR=1
    fi
fi
# Renew etcd-server certificate
if [ ${ERR} -eq 0 ]; then
    config="
    [req]
    prompt = no
    x509_extensions = v3_req
    distinguished_name = dn
    [dn]
    CN = etcd-server
    [v3_req]
    keyUsage = critical, Digital Signature, Key Encipherment
    extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
    subjectAltName = @alt_names
    [alt_names]
    IP.1 = ${floating_ip}
    IP.2 = 127.0.0.1
    "
    renew_cert_by_openssl "/etc/etcd" "etcd-server" "${config}"
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_ETCD=1
        # Update the cert and key shared with standby controller
        if [ -d ${CONFIG_PATH}/etcd ]; then
            cp "/etc/etcd/etcd-server.crt" ${CONFIG_PATH}/etcd
            cp "/etc/etcd/etcd-server.key" ${CONFIG_PATH}/etcd
        fi
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew etcd-server certificate."
        ERR=1
    fi
fi
# Renew etcd-client certificate
if [ ${ERR} -eq 0 ]; then
    config="
    [req]
    prompt = no
    x509_extensions = v3_req
    distinguished_name = dn
    [dn]
    CN = root
    [v3_req]
    keyUsage = critical, Digital Signature, Key Encipherment
    extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = root
    "
    renew_cert_by_openssl "/etc/etcd" "etcd-client" "${config}"
    result=$?
    if [ ${result} -eq 0 ]; then
        # Update the cert and key shared with standby controller
        if [ -d ${CONFIG_PATH}/etcd ]; then
            cp "/etc/etcd/etcd-client.crt" ${CONFIG_PATH}/etcd
            cp "/etc/etcd/etcd-client.key" ${CONFIG_PATH}/etcd
        fi
    elif [ ${result} -eq 1 ]; then
        ERR_REASON="Failed to renew etcd-client certificate."
        ERR=1
    fi
fi

# Remove temporary working directory
rm -rf ${TEMP_WORK_DIR}

# step 2, restart affected kubernetes components and system services
# Restart apiserver
if [ ${RESTART_APISERVER} -eq 1 ]; then
    crictl ps | awk '/kube-apiserver/{print$1}' | xargs crictl stop > /dev/null
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart kube-apiserver."
        ERR=2
    fi
fi
# Restart controller-manager
if [ ${RESTART_CONTROLLER_MANAGER} -eq 1 ]; then
    crictl ps | awk '/kube-controller-manager/{print$1}' | xargs crictl stop > /dev/null
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart kube-controller-manager."
        ERR=2
    fi
fi
# Restart scheduler
if [ ${RESTART_SCHEDULER} -eq 1 ]; then
    crictl ps | awk '/kube-scheduler/{print$1}' | xargs crictl stop > /dev/null
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart kube-scheduler."
        ERR=2
    fi
fi
# Restart sysinv services, both conductor and api, since both are using
# credentials from admin.conf. Command sm-restart-safe only restarts
# sysinv-conductor. Command sm-restart will restart sysinv-conductor
# and its dependencies, meaning all sysinv services.
if [ ${RESTART_SYSINV} -eq 1 ]; then
    sm-restart service sysinv-conductor
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart sysinv-conductor service."
        ERR=2
    fi
fi
# Restart cert-mon since it's using credentials from admin.conf
if [ ${RESTART_CERT_MON} -eq 1 ]; then
    sm-restart-safe service cert-mon
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart cert-mon service."
        ERR=2
    fi
fi
# Restart etcd server
if [ ${RESTART_ETCD} -eq 1 ]; then
    sm-restart-safe service etcd
    if [ $? -ne 0 ]; then
        ERR_REASON="Failed to restart etcd service."
        ERR=2
    fi
fi

if [ ${ERR} -eq 2 ]; then
    # Notify admin to lock and unlock this master node if restart k8s components failed
    /usr/local/bin/fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates have been renewed but not all services have been updated.###operational-violation### ###Lock and unlock the host to update services with new certificates (Manually renew kubernetes certificates first if renewal failed). Reason: ${ERR_REASON}### ### ###"
elif [ ${ERR} -eq 1 ]; then
    # Notify admin to renew kube cert manually and restart services by lock/unlock if cert renew or config failed
    /usr/local/bin/fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates renewal failed.###operational-violation### ###Lock and unlock the host to update services with new certificates (Manually renew kubernetes certificates first if renewal failed). Reason: ${ERR_REASON}### ### ###"
else
    # Clear the alarm if cert rotation completed
    # Check if alarm exist first before deleting. fmClientCli -A returns 0 when found and 255 when not found
    /usr/local/bin/fmClientCli -A "250.003" &> /dev/null
    if [ $? -eq 0 ]; then
        /usr/local/bin/fmClientCli -d "###250.003###host=${HOSTNAME}###"
    fi
fi
