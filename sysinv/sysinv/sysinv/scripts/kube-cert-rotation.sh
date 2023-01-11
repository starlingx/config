#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
# Copyright (c) 2021-2023 Wind River Systems, Inc.
#

#
# This script is to rotate kubernetes cluster certificates automatically
#

# Renew certificates 15 days before expiration
declare -r CUTOFF_DAYS=15
declare -r CUTOFF_DAYS_S=$((${CUTOFF_DAYS}*24*3600))

# Temporary working directory
TEMP_WORK_DIR="/tmp/kube_cert_rotation"

# Expiration date of k8s certs

# Tries ga command version, failing over to alpha command
kubeadm certs &> /dev/null
if [ $? -eq 0 ]; then
    CERT_CMD='certs'
else
    CERT_CMD='alpha certs'
fi

CERT_EXP_DATES=$(kubeadm $CERT_CMD check-expiration)
# Time left in seconds for a cert
time_left_s() {
    local time_left_s=""
    local exp_date=""
    exp_date=$(echo "${CERT_EXP_DATES}" | grep "$1" | grep -oE '[a-zA-Z]{3} [0-3][0-9], [0-9]{4} ([0-1][0-9]|2[0-3]):[0-5][0-9] UTC')
    if [ "x${exp_date}" != "x" ]; then
        exp_date_s=$(date -d "${exp_date}" +%s)
        current_date_s=$(date +%s)
        time_left_s=$((${exp_date_s}-${current_date_s}))
    fi
    echo ${time_left_s}
}

# Retrieve a certiticate's valid time by openssl
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

ERR=0
RESTART_APISERVER=0
RESTART_CONTROLLER_MANAGER=0
RESTART_SCHEDULER=0
RESTART_SYSINV=0
RESTART_CERT_MON=0
RESTART_ETCD=0

# step 1, renew kubernetes certificates
# Renew apiserver certificate
if [ ${ERR} -eq 0 ]; then
    # The extra space in 'apiserver ' is to distinguish other names with apiserver in them.
    renew_cert 'apiserver '
    result=$?
    if [ ${result} -eq 0 ]; then
        RESTART_APISERVER=1
    elif [ ${result} -eq 1 ]; then
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
        ERR=1
    fi
fi
# Renew front proxy client certificate
if [ ${ERR} -eq 0 ]; then
    renew_cert 'front-proxy-client'
    if [ $? -eq 1 ]; then
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
        ERR=1
    fi
fi

# Create temporary working directory
if [ ${ERR} -eq 0 ]; then
    mkdir -p ${TEMP_WORK_DIR}
    chmod 0600 ${TEMP_WORK_DIR}
    if [ $? -ne 0 ]; then
        ERR=1
    fi
fi

# Get cluster host floating IP address
if [ ${ERR} -eq 0 ]; then
    floating_ip=$(get_cluster_host_floating_ip)
    if [ "x${floating_ip}" == "x" ]; then
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
    elif [ ${result} -eq 1 ]; then
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
    if [ ${result} -eq 1 ]; then
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
        ERR=2
    fi
fi
# Restart controller-manager
if [ ${RESTART_CONTROLLER_MANAGER} -eq 1 ]; then
    crictl ps | awk '/kube-controller-manager/{print$1}' | xargs crictl stop > /dev/null
    if [ $? -ne 0 ]; then
        ERR=2
    fi
fi
# Restart scheduler
if [ ${RESTART_SCHEDULER} -eq 1 ]; then
    crictl ps | awk '/kube-scheduler/{print$1}' | xargs crictl stop > /dev/null
    if [ $? -ne 0 ]; then
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
        ERR=2
    fi
fi
# Restart cert-mon since it's using credentials from admin.conf
if [ ${RESTART_CERT_MON} -eq 1 ]; then
    sm-restart-safe service cert-mon
    if [ $? -ne 0 ]; then
        ERR=2
    fi
fi
# Restart etcd server
if [ ${RESTART_ETCD} -eq 1 ]; then
    sm-restart-safe service etcd
    if [ $? -ne 0 ]; then
        ERR=2
    fi
fi

if [ ${ERR} -eq 2 ]; then
    # Notify admin to lock and unlock this master node if restart k8s components failed
    /usr/local/bin/fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates have been renewed but not all services have been updated.###operational-violation### ###Lock and unlock the host to update services with new certificates (Manually renew kubernetes certificates first if renewal failed).### ### ###"
elif [ ${ERR} -eq 1 ]; then
    # Notify admin to renew kube cert manually and restart services by lock/unlock if cert renew or config failed
    /usr/local/bin/fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates renewal failed.###operational-violation### ###Lock and unlock the host to update services with new certificates (Manually renew kubernetes certificates first if renewal failed).### ### ###"
else
    # Clear the alarm if cert rotation completed
    # Check if alarm exist first before deleting. fmClientCli -A returns 0 when found and 255 when not found
    /usr/local/bin/fmClientCli -A "250.003" &> /dev/null
    if [ $? -eq 0 ]; then
        /usr/local/bin/fmClientCli -d "###250.003###host=${HOSTNAME}###"
    fi
fi
