# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2023,2025 Wind River Systems, Inc.
#

"""
Client side of the agent RPC API.
"""

from oslo_log import log
from sysinv.objects import base as objects_base
import sysinv.openstack.common.rpc.proxy

LOG = log.getLogger(__name__)

MANAGER_TOPIC = 'sysinv.agent_manager'


class AgentAPI(sysinv.openstack.common.rpc.proxy.RpcProxy):
    """Client side of the agent RPC API.

    API version history:

        1.0 - Initial version.
    """

    RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        if topic is None:
            topic = MANAGER_TOPIC

        super(AgentAPI, self).__init__(
            topic=topic,
            serializer=objects_base.SysinvObjectSerializer(),
            default_version=self.RPC_API_VERSION)

    def configure_lldp_systemname(self, context, systemname):
        """Asynchronously, have the agent configure the systemname into the lldp agent

        :param context: request context.
        :param systemname: systemname
        :returns: none ... uses asynchronous cast().
        """
        # fanout / broadcast message to all inventory agents
        # to change systemname on all nodes ... standby controller and worker nodes
        LOG.debug("AgentApi.configure_systemname_into_lldp_agent: fanout_cast: sending systemname to agent")
        retval = self.fanout_cast(context, self.make_msg('configure_lldp_systemname',
                           systemname=systemname))

        return retval

    def iconfig_update_file(self, context, iconfig_uuid, iconfig_dict):
        """Asynchronously, have the agent configure the iiconfig_uuid,
           by updating file based upon iconfig_dict.

        :param context: request context.
        :param iconfig_uuid: iconfig_uuid,
        :param iconfig_dict: iconfig_dict dictionary of attributes:
        :          {personalities: list of ihost personalities
        :           file_names: list of full path file names
        :           file_content: file contents
        :           actions: put(full replacement), patch, update_applied
        :           action_key: match key (for patch only)
        :          }
        :returns: none ... uses asynchronous cast().
        """

        LOG.debug("AgentApi.iconfig_update_file: fanout_cast: sending"
                  " iconfig %s %s to agent" % (iconfig_uuid, iconfig_dict))

        # fanout / broadcast message to all inventory agents
        retval = self.fanout_cast(context, self.make_msg(
                           'iconfig_update_file',
                           iconfig_uuid=iconfig_uuid,
                           iconfig_dict=iconfig_dict))

        return retval

    def iconfig_update_install_uuid(self, context, host_uuids, install_uuid):
        """Asynchronously, have the agent update install_uuid in
           /etc/platform/platform.conf

        :param context: request context.
        :param host_uuids: The host uuid or list of host uuids to update
                           the install_uuid
        :param install_uuid: The updated install_uuid that will be
        :                    written into /etc/platform/platform.conf
        """

        LOG.debug("AgentApi.iconfig_update_install_uuid: fanout_cast: sending"
                  " install_uuid %s to agents: %s" % (install_uuid, host_uuids))

        retval = self.fanout_cast(context, self.make_msg(
                           'iconfig_update_install_uuid',
                           host_uuids=host_uuids,
                           install_uuid=install_uuid))

        return retval

    def config_apply_runtime_manifest(self, context, config_uuid, config_dict):
        """Asynchronously have the agent apply the specified
           manifest based upon the config_dict (including personalities).
        """

        LOG.info("config_apply_runtime_manifest: fanout_cast: sending"
                  " config %s %s to agent" % (config_uuid, config_dict))

        # fanout / broadcast message to all inventory agents
        retval = self.fanout_cast(context, self.make_msg(
                                  'config_apply_runtime_manifest',
                                  config_uuid=config_uuid,
                                  config_dict=config_dict))
        return retval

    def apply_tpm_config(self, context, tpm_context):
        """Asynchronously, have the agent apply the tpm config

        :param context: request context.
        :param tpm_context: the TPM configuration context
        :returns: none ... uses asynchronous cast().
        """
        # fanout / broadcast message to all inventory agents
        LOG.debug("AgentApi.apply_tpm_config: fanout_cast: sending "
                  "apply_tpm_config to agent")
        retval = self.fanout_cast(
            context, self.make_msg(
                'apply_tpm_config',
                tpm_context=tpm_context))

        return retval

    def execute_command(self, context, host_uuid, command):
        """Asynchronously, have the agent execute a command

        :param context: request context.
        :param host_uuid: the host uuid
        :param command: the command to execute
        :returns: none ... uses asynchronous cast().
        """
        # fanout / broadcast message to all inventory agents
        LOG.debug("AgentApi.execute_command: fanout_cast: sending "
                  "host uuid: (%s) " % host_uuid)
        retval = self.fanout_cast(
            context, self.make_msg(
                'execute_command',
                host_uuid=host_uuid,
                command=command))

        return retval

    def agent_update(self, context, host_uuid, force_updates, cinder_device=None):
        """
        Asynchronously, have the agent update partitions, ipv and ilvg state

        :param context: request context
        :param host_uuid: the host uuid
        :param force_updates: list of inventory objects to update
        :param cinder_device: device by path of cinder volumes
        :return:  none ... uses asynchronous cast().
        """

        # fanout / broadcast message to all inventory agents
        LOG.info("AgentApi.agent_update: fanout_cast: sending "
                 "update request to agent for: (%s)" %
                 (', '.join(force_updates)))
        retval = self.fanout_cast(
            context, self.make_msg(
                'agent_audit',
                host_uuid=host_uuid,
                force_updates=force_updates,
                cinder_device=cinder_device))

        return retval

    def disk_prepare(self, context, host_uuid, idisk_dict,
                     skip_format, is_cinder_device):
        """Asynchronously, prepare a disk for system use.

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :param idisk_dict: values for disk object
        :param skip_format: bool value tells if the idisk should be GPT formatted
        :param is_cinder_device: bool value tells if the idisk is for cinder
        :returns: pass or fail
        """

        return self.fanout_cast(
            context,
            self.make_msg('disk_prepare',
                          host_uuid=host_uuid,
                          idisk_dict=idisk_dict,
                          skip_format=skip_format,
                          is_cinder_device=is_cinder_device))

    def update_host_memory(self, context, host_uuid):
        """Asynchronously, have the agent to send host memory update

        :param context: request context.
        :param host_uuid: ihost uuid unique id
        :returns: pass or fail
        """
        return self.fanout_cast(context,
                                self.make_msg('update_host_memory',
                                              host_uuid=host_uuid))

    def refresh_helm_repo_information(self, context):
        """Asynchronously, refresh helm chart repository information

        :param context: request context.
        :returns: none ... uses asynchronous cast().
        """
        # fanout / broadcast message to all inventory agents
        LOG.debug("AgentApi.refresh_helm_repo_information: fanout_cast: "
                  "sending refresh_helm_repo_information to agent")
        retval = self.fanout_cast(context,
                                  self.make_msg(
                                      'refresh_helm_repo_information'))

        return retval

    def kube_upgrade_abort(self, context, current_kube_version, back_to_kube_version):
        """Asynchronously, abort kubernetes upgrade

        Kubernetes upgrade abort on controller hosts. This is currently supported only
        on AIO-SX and will be supported on all other deployment configurations in future
        releases.

        :param: context: context object
        :param: current_kube_version: current kubernetes version
        :param: back_to_kube_version: kubernetes version to be rolled back to
        """
        return self.fanout_cast(context,
                         self.make_msg("kube_upgrade_abort",
                                       current_kube_version=current_kube_version,
                                       back_to_kube_version=back_to_kube_version))

    def update_host_lvm(self, context, host_uuid):
        """Synchronously, update LVM physical volume

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('update_host_lvm',
                                       host_uuid=host_uuid))

    # handle firmware updates on FPGA devices
    def host_device_update_image(self, context, host_uuid, hostname, pci_addr,
                                 filename, transaction_id, retimer_included):
        LOG.info("sending device_update_image to host %s" % hostname)
        topic = '%s.%s' % (self.topic, hostname)
        return self.cast(context,
                         self.make_msg('device_update_image',
                                       host_uuid=host_uuid,
                                       pci_addr=pci_addr, filename=filename,
                                       transaction_id=transaction_id,
                                       retimer_included=retimer_included),
                         topic=topic)

    def report_initial_inventory(self, context, host_uuid):
        """ Synchronously, request the agent to re-report initial inventory
        """

        return self.call(context,
                         self.make_msg("report_initial_inventory",
                                       host_uuid=host_uuid))

    def pull_kubernetes_images(self, context, host_uuid, images):
        """Asynchronously, pull kubernetes images

        :param context: request context
        :param host_uuid: the host uuid
        :param images: list of images to be downloaded
        :return:  none ... uses asynchronous cast().
        """
        return self.cast(context,
                         self.make_msg("pull_kubernetes_images",
                                       host_uuid=host_uuid,
                                       images=images))
