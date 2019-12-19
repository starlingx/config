#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#

#
# This script is to rotate kubernetes cluster certificates automatically
#

# Expiration date of k8s certs
CERT_LASTDATE=$(openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text | grep 'Not After' | awk -F ' : ' '{print $2}')

if [ "x${CERT_LASTDATE}" != "x" ]; then
    CERT_LASTDATE_S=$(date -d "${CERT_LASTDATE}" +%s)
    CURRENT_DATE_S=$(date +%s)
    DAY_LEFT_S=$((${CERT_LASTDATE_S}-${CURRENT_DATE_S}))
fi

# Renew certificates 90 days before expiration
ERR=0
declare -r NINETY_DAYS_S=$((90*24*3600))
if [ ${DAY_LEFT_S} -lt ${NINETY_DAYS_S} ]; then
    # Same expiration date of apiserver, apiserver-kubelet-client and front-proxy-client
    if [ ${ERR} -eq 0 ]; then
        kubeadm alpha certs renew apiserver
        if [ $? -ne 0 ]; then
            ERR=1
        fi
    fi

    if [ ${ERR} -eq 0 ]; then
        kubeadm alpha certs renew apiserver-kubelet-client
        if [ $? -ne 0 ]; then
            ERR=1
        fi
    fi

    if [ ${ERR} -eq 0 ]; then
        kubeadm alpha certs renew front-proxy-client
        if [ $? -ne 0 ]; then
            ERR=1
        fi
    fi

    # Update cluster configuration files using the renewed certificates

    if [ ${ERR} -eq 0 ]; then
        ADVERTISE_ADDR=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}')
    else
        ADVERTISE_ADDR=""
    fi

    if [ "x${ADVERTISE_ADDR}" != "x" ]; then
        # Update admin.conf
        if [ ${ERR} -eq 0 ]; then
            kubeadm alpha kubeconfig user --client-name=kubernetes-admin --apiserver-advertise-address=${ADVERTISE_ADDR} --org system:masters > /tmp/admin.conf
            if [ $? -eq 0 ]; then
                mv /tmp/admin.conf /etc/kubernetes/admin.conf
                if [ $? -ne 0 ]; then
                    ERR=1
                fi
            else
                ERR=1
            fi
        fi

        # Update controller-manager.conf
        if [ ${ERR} -eq 0 ]; then
            kubeadm alpha kubeconfig user --client-name=system:kube-controller-manager --apiserver-advertise-address=${ADVERTISE_ADDR} --cert-dir /etc/kubernetes/pki/ > /tmp/controller-manager.conf
            if [ $? -eq 0 ]; then
                mv /tmp/controller-manager.conf /etc/kubernetes/controller-manager.conf
                if [ $? -ne 0 ]; then
                    ERR=1
                fi
            else
                ERR=1
            fi
        fi

        # Update scheduler.conf
        if [ ${ERR} -eq 0 ]; then
            kubeadm alpha kubeconfig user --client-name=system:kube-scheduler --apiserver-advertise-address=${ADVERTISE_ADDR} --cert-dir /etc/kubernetes/pki/ > /tmp/scheduler.conf
            if [ $? -eq 0 ]; then
                mv /tmp/scheduler.conf /etc/kubernetes/scheduler.conf
                if [ $? -ne 0 ]; then
                    ERR=1
                fi
            else
                ERR=1
            fi
        fi

        # Update kubelet.conf
        # This block could be removed once this issue is resolved. https://github.com/kubernetes/kubeadm/issues/1753
        if [ ${ERR} -eq 0 ]; then
            kubeadm alpha kubeconfig user --client-name=system:node:${HOSTNAME} --apiserver-advertise-address=${ADVERTISE_ADDR} --org system:nodes > /tmp/kubelet.conf
            if [ $? -eq 0 ]; then
                mv /tmp/kubelet.conf /etc/kubernetes/kubelet.conf
                if [ $? -ne 0 ]; then
                    ERR=1
                fi
            else
                ERR=1
            fi
        fi
    else
        ERR=1
    fi

    # Restart docker container of k8s components to refresh the configurations within container
    if [ ${ERR} -eq 0 ]; then
        docker ps | awk '/k8s_kube-apiserver/{print$1}' | xargs docker restart > /dev/null
        if [ $? -ne 0 ]; then
            ERR=2
        fi
    fi

    if [ ${ERR} -eq 0 ]; then
        docker ps | awk '/k8s_kube-controller-manager/{print$1}' | xargs docker restart > /dev/null
        if [ $? -ne 0 ]; then
            ERR=2
        fi
    fi

    if [ ${ERR} -eq 0 ]; then
        docker ps | awk '/k8s_kube-scheduler/{print$1}' | xargs docker restart > /dev/null
        if [ $? -ne 0 ]; then
            ERR=2
        fi
    fi

    if [ ${ERR} -eq 0 ]; then
        systemctl daemon-reload
        systemctl restart kubelet
        if [ $? -ne 0 ]; then
            ERR=2
        fi
    fi

    if [ ${ERR} -eq 2 ]; then
        # Notify admin to lock and unlock this master node if restart k8s components failed
        fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates on host ${HOSTNAME} have been renewed but not updated.###operational-violation### ###Lock and unlock host ${HOSTNAME} to update config.### ### ###"
    elif [ ${ERR} -eq 1 ]; then
        # Notify admin to rotate kube cert manually if cert renew or config failed
        fmClientCli -c "### ###250.003###set###host###host=${HOSTNAME}### ###major###Kubernetes certificates automatic rotation failed on host ${HOSTNAME}###operational-violation### ###Rotate kubernetes certificates manually, lock and unlock host ${HOSTNAME} to update config.### ### ###"
    else
        # Clear the alarm if cert rotation completed
        fmClientCli -d "###250.003###host=${HOSTNAME}###"
    fi
fi
