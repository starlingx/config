#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Kubernetes Pod Operator."""

import datetime
import time

from dateutil import tz
from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import kubernetes

LOG = logging.getLogger(__name__)


class K8sPodOperator(object):

    def __init__(self, kube_op=None):
        self.kube_op = kube_op
        if not self.kube_op:
            self.kube_op = kubernetes.KubeOperator(None)

    def _get_all_pods(self):
        try:
            pods = self.kube_op.kube_get_all_pods()
        except Exception:
            pods = []
        return pods

    def _delete_pod(self, name, namespace, expect_removal=True):
        loop_timeout = 1
        timeout = 30
        try:
            LOG.info("Deleting Pod %s/%s ..." % (namespace, name))
            delete_requested = datetime.datetime.now(tz.tzlocal())
            if not self.kube_op.kube_delete_pod(name, namespace,
                                                grace_periods_seconds=0):
                LOG.warning("Pod %s/%s deletion unsuccessful..." % (namespace,
                                                                    name))
                return

            # Pod termination timeout: 30 seconds
            while(loop_timeout <= timeout):
                pod = self.kube_op.kube_get_pod(name, namespace)
                if not pod and not expect_removal:
                    # Pod has been unexpectedly terminated
                    raise exception.KubePodDeleteUnexpected(namespace=namespace,
                                                            name=name)
                elif not pod and expect_removal:
                    # Pod has been terminated
                    LOG.info("Pod %s/%s succesfully terminated" % (namespace,
                                                                   name))
                    break
                elif pod and not expect_removal:
                    if pod.status.phase == 'Pending':
                        # Pod is restarting.
                        LOG.info("Pod %s/%s restart pending" % (namespace, name))
                        break
                    elif pod.status.phase == 'Running':
                        if pod.metadata.creation_timestamp > delete_requested:
                            # Pod restarted quickly
                            LOG.info("Pod %s/%s recreated %ss ago" % (
                                namespace, name,
                                (delete_requested -
                                 pod.metadata.creation_timestamp).total_seconds()))
                            break
                        LOG.info("Pod %s/%s running" % (namespace, name))
                elif pod and expect_removal:
                    # Still around or missed the Pending state transition
                    LOG.info("Pod %s/%s (%s) waiting on removal." % (
                        namespace, name, pod.status.phase))
                loop_timeout += 1
                time.sleep(1)

            if loop_timeout > timeout:
                raise exception.KubePodDeleteTimeout(namespace=namespace, name=name)
            LOG.info("Pod %s/%s delete completed." % (namespace, name))
        except Exception as e:
            LOG.error(e)
            raise

    def get_failed_pods_by_reason(self, reason=None):
        failed_pods = []
        all_pods = self._get_all_pods()
        for pod in all_pods:
            if pod.status.phase == 'Failed':
                if reason:
                    if pod.status.reason == reason:
                        failed_pods.append(pod)
                else:
                    failed_pods.append(pod)
        return failed_pods

    def delete_failed_pods_by_reason(self, pods=None, reason=None):
        failed_pods = pods
        if not pods:
            failed_pods = self.get_failed_pods_by_reason(reason=reason)

        for pod in failed_pods:
            LOG.info("DELETING POD: %s/%s: found as %s/%s" % (
                pod.metadata.namespace, pod.metadata.name,
                pod.status.phase, pod.status.reason))
            try:
                self._delete_pod(pod.metadata.name, pod.metadata.namespace)
            except Exception:
                pass
