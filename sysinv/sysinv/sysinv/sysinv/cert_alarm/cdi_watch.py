#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import eventlet
from kubernetes import client
from kubernetes import config
from kubernetes import watch
import logging
from sysinv.common import kubernetes as sys_kube

# Constants for CDI resources
CDI_GROUP = 'cdi.kubevirt.io'
CDI_VERSION = 'v1beta1'
CDI_PLURAL = 'cdis'

LOG = logging.getLogger(__name__)


class CDIWatch(object):
    def __init__(self):
        self.current_version = None
        self.watch_thread = None
        self.watch_event = eventlet.event.Event()
        self.watch_cdi = watch.Watch()
        self.monitor_thread = False
        self.event_check = False
        self.ccObj = None

    def set_version(self, version):
        # Set the current version of the CDI resource
        self.current_version = version

    def get_version(self):
        # Get the current version of the CDI resource
        return self.current_version

    def is_monitor_thread_started(self):
        return self.monitor_thread

    def start_watching(self):
        config.load_kube_config(sys_kube.KUBERNETES_ADMIN_CONF)
        self.ccObj = client.CustomObjectsApi()
        if self.watch_thread and not self.watch_thread.dead:
            LOG.info("Thread is already running.")
            return
        self.watch_thread = eventlet.greenthread.spawn(self.watch_cdi_resources, self.watch_event)
        self.monitor_thread = True
        self.watch_event.wait()
        self.watch_event.reset()

    def __stop_watching(self, stop_event):
        # Set the stop event to signal the thread to stop
        if self.watch_thread:
            if not self.event_check:
                stop_event.send()
            self.current_version = None
            self.monitor_thread = False
            self.event_check = False
            self.watch_cdi.stop()
            self.watch_thread.kill()
            self.watch_thread.wait()

    def watch_cdi_resources(self, watch_event):
        '''
        Streams events for CDI resources and raises an exception if streaming fails.

        This method continuously monitors changes to CDI resources.
        It updates the current operator version on 'ADDED' or 'MODIFIED' events
        and signals through the provided watch_event.
        Raises:
            Exception: If an error occurs while streaming events.
        '''
        try:
            # Stream events for CDI resources
            for event in self.watch_cdi.stream(self.ccObj.list_cluster_custom_object,
                                          group=CDI_GROUP, version=CDI_VERSION, plural=CDI_PLURAL):
                event_type = event['type']
                if event_type in ['ADDED', 'MODIFIED']:
                    resource = event['object']
                    current_version = resource.get('status', {}).get('operatorVersion')
                    self.set_version(current_version)
                    if not self.event_check:
                        watch_event.send()
                        self.event_check = True
        except Exception as e:
            msg = "monitor action failed: %s" % str(e)
            LOG.error(msg)
            self.__stop_watching(watch_event)
