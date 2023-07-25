#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# Restore the k8s cluster when it becomes unavailable because of
# kubelet related certs expiry after a long period of host being offline.
#

# Sources existing kube-cert-rotation.sh script to use 'time left for cert functions'
source /usr/bin/kube-cert-rotation.sh

KUBELET_CONF=/etc/kubernetes/kubelet.conf
KUBELET_CERT_PATH=/var/lib/kubelet/pki/kubelet-client-$(date "+%F-%H-%M-%S").pem
KUBELET_CSR_CONF_FILE=$(mktemp).kubelet_conf_csr
KUBELET_KEY_FILE=$(mktemp).kubelet_key
KUBELET_CERT_FILE=$(mktemp).kubelet_cert
KUBELET_CSR_FILE=$(mktemp).kubelet_csr

cat <<EOF > $KUBELET_CSR_CONF_FILE
[req]
prompt = no
x509_extensions = v3_req
distinguished_name = dn
[dn]
O = system:nodes
CN = system:node:$(hostname)
[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = critical, Digital Signature, Key Encipherment
extendedKeyUsage = TLS Web Client Authentication
EOF

KUBELET_CLIENT_CURRENT_PEM=$(cat $KUBELET_CONF | grep 'client-certificate' | awk '{print $2}')

time_left_s_kubelet_pem=$(time_left_s_by_openssl $KUBELET_CLIENT_CURRENT_PEM)
if [ "x${time_left_s_kubelet_pem}" != "x" ]; then
    if [ ${time_left_s_kubelet_pem} -lt ${CUTOFF_DAYS_S} ]; then

        openssl genrsa -out $KUBELET_KEY_FILE 2048
        openssl req -new -key $KUBELET_KEY_FILE -out $KUBELET_CSR_FILE \
        -config $KUBELET_CSR_CONF_FILE
        openssl x509 -req -in $KUBELET_CSR_FILE -CA /etc/kubernetes/pki/ca.crt \
        -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out $KUBELET_CERT_FILE \
        -days 365 -extensions v3_req -extfile $KUBELET_CSR_CONF_FILE

        cat $KUBELET_KEY_FILE  $KUBELET_CERT_FILE  > $KUBELET_CERT_PATH

        # overrides existing link pointing to newly generated certificate
        rm -f /var/lib/kubelet/pki/kubelet-client-current.pem
        ln -s $KUBELET_CERT_PATH /var/lib/kubelet/pki/kubelet-client-current.pem
        # delete kubelet ca and server certificates so they get regenerated in kubelet restart
        rm -f /var/lib/kubelet/pki/kubelet.crt
        rm -f /var/lib/kubelet/pki/kubelet.key

        # updates kubelet.conf with new version of k8s Root CA, in case it has changed
        bash -c 'KUBECONFIG=/etc/kubernetes/kubelet.conf kubectl config set-cluster kubernetes \
        --certificate-authority /etc/kubernetes/pki/ca.crt --embed-certs'

        systemctl restart kubelet
        echo "Service (kubelet) is restarting."
        sleep 2

        ATTEMPTS=5
        count=0
        while [ ${count} -lt ${ATTEMPTS} ]; do
            systemctl status kubelet | grep running
            RC=$?
            if [ $RC -eq 0 ]; then
                echo "Successfully restarted kubelet."
                break
            else
                sleep 2
                count=$(($count+1))
            fi
        done

        if [ $RC -ne 0 ]; then
            echo "ERROR - Failed to restart kubelet. (RETURNED: $RC)"
        fi
    fi
fi

rm -f $KUBELET_CSR_CONF_FILE
rm -f $KUBELET_KEY_FILE
rm -f $KUBELET_CERT_FILE
rm -f $KUBELET_CSR_FILE

exit $RC
