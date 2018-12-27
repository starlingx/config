#
# Copyright (c) 2014-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
System Inventory Interactions
"""

import json
import openstack
import urllib2

from controllerconfig.common import log
from controllerconfig.common.exceptions import KeystoneFail

LOG = log.get_logger(__name__)

API_VERSION = 1

# Host Personality Constants
HOST_PERSONALITY_NOT_SET = ""
HOST_PERSONALITY_UNKNOWN = "unknown"
HOST_PERSONALITY_CONTROLLER = "controller"
HOST_PERSONALITY_WORKER = "worker"
HOST_PERSONALITY_STORAGE = "storage"

# Host Administrative State Constants
HOST_ADMIN_STATE_NOT_SET = ""
HOST_ADMIN_STATE_UNKNOWN = "unknown"
HOST_ADMIN_STATE_LOCKED = "locked"
HOST_ADMIN_STATE_UNLOCKED = "unlocked"

# Host Operational State Constants
HOST_OPERATIONAL_STATE_NOT_SET = ""
HOST_OPERATIONAL_STATE_UNKNOWN = "unknown"
HOST_OPERATIONAL_STATE_ENABLED = "enabled"
HOST_OPERATIONAL_STATE_DISABLED = "disabled"

# Host Availability State Constants
HOST_AVAIL_STATE_NOT_SET = ""
HOST_AVAIL_STATE_UNKNOWN = "unknown"
HOST_AVAIL_STATE_AVAILABLE = "available"
HOST_AVAIL_STATE_ONLINE = "online"
HOST_AVAIL_STATE_OFFLINE = "offline"
HOST_AVAIL_STATE_POWERED_OFF = "powered-off"
HOST_AVAIL_STATE_POWERED_ON = "powered-on"

# Host Board Management Constants
HOST_BM_TYPE_NOT_SET = ""
HOST_BM_TYPE_UNKNOWN = "unknown"
HOST_BM_TYPE_ILO3 = 'ilo3'
HOST_BM_TYPE_ILO4 = 'ilo4'

# Host invprovision state
HOST_PROVISIONING = "provisioning"
HOST_PROVISIONED = "provisioned"


class Host(object):
    def __init__(self, hostname, host_data=None):
        self.name = hostname
        self.personality = HOST_PERSONALITY_NOT_SET
        self.admin_state = HOST_ADMIN_STATE_NOT_SET
        self.operational_state = HOST_OPERATIONAL_STATE_NOT_SET
        self.avail_status = []
        self.bm_type = HOST_BM_TYPE_NOT_SET
        self.uuid = None
        self.config_status = None
        self.invprovision = None
        self.boot_device = None
        self.rootfs_device = None
        self.console = None
        self.tboot = None

        if host_data is not None:
            self.__host_set_state__(host_data)

    def __host_set_state__(self, host_data):
        if host_data is None:
            self.admin_state = HOST_ADMIN_STATE_UNKNOWN
            self.operational_state = HOST_OPERATIONAL_STATE_UNKNOWN
            self.avail_status = []
            self.bm_type = HOST_BM_TYPE_NOT_SET

        # Set personality
        if host_data['personality'] == "controller":
            self.personality = HOST_PERSONALITY_CONTROLLER
        elif host_data['personality'] == "worker":
            self.personality = HOST_PERSONALITY_WORKER
        elif host_data['personality'] == "storage":
            self.personality = HOST_PERSONALITY_STORAGE
        else:
            self.personality = HOST_PERSONALITY_UNKNOWN

        # Set administrative state
        if host_data['administrative'] == "locked":
            self.admin_state = HOST_ADMIN_STATE_LOCKED
        elif host_data['administrative'] == "unlocked":
            self.admin_state = HOST_ADMIN_STATE_UNLOCKED
        else:
            self.admin_state = HOST_ADMIN_STATE_UNKNOWN

        # Set operational state
        if host_data['operational'] == "enabled":
            self.operational_state = HOST_OPERATIONAL_STATE_ENABLED
        elif host_data['operational'] == "disabled":
            self.operational_state = HOST_OPERATIONAL_STATE_DISABLED
        else:
            self.operational_state = HOST_OPERATIONAL_STATE_UNKNOWN

        # Set availability status
        self.avail_status[:] = []
        if host_data['availability'] == "available":
            self.avail_status.append(HOST_AVAIL_STATE_AVAILABLE)
        elif host_data['availability'] == "online":
            self.avail_status.append(HOST_AVAIL_STATE_ONLINE)
        elif host_data['availability'] == "offline":
            self.avail_status.append(HOST_AVAIL_STATE_OFFLINE)
        elif host_data['availability'] == "power-on":
            self.avail_status.append(HOST_AVAIL_STATE_POWERED_ON)
        elif host_data['availability'] == "power-off":
            self.avail_status.append(HOST_AVAIL_STATE_POWERED_OFF)
        else:
            self.avail_status.append(HOST_AVAIL_STATE_AVAILABLE)

        # Set board management type
        if host_data['bm_type'] is None:
            self.bm_type = HOST_BM_TYPE_NOT_SET
        elif host_data['bm_type'] == 'ilo3':
            self.bm_type = HOST_BM_TYPE_ILO3
        elif host_data['bm_type'] == 'ilo4':
            self.bm_type = HOST_BM_TYPE_ILO4
        else:
            self.bm_type = HOST_BM_TYPE_UNKNOWN

        if host_data['invprovision'] == 'provisioned':
            self.invprovision = HOST_PROVISIONED
        else:
            self.invprovision = HOST_PROVISIONING

        self.uuid = host_data['uuid']
        self.config_status = host_data['config_status']
        self.boot_device = host_data['boot_device']
        self.rootfs_device = host_data['rootfs_device']
        self.console = host_data['console']
        self.tboot = host_data['tboot']

    def __host_update__(self, admin_token, region_name):
        try:
            url = admin_token.get_service_admin_url("platform", "sysinv",
                                                    region_name)
            url += "/ihosts/" + self.name

            request_info = urllib2.Request(url)
            request_info.add_header("X-Auth-Token", admin_token.get_id())
            request_info.add_header("Accept", "application/json")

            request = urllib2.urlopen(request_info)
            response = json.loads(request.read())
            request.close()
            return response

        except KeystoneFail as e:
            LOG.error("Keystone authentication failed:{} ".format(e))
            return None

        except urllib2.HTTPError as e:
            LOG.error("%s, %s" % (e.code, e.read()))
            if e.code == 401:
                admin_token.set_expired()
            return None

        except urllib2.URLError as e:
            LOG.error(e)
            return None

    def __host_action__(self, admin_token, action, region_name):
        try:
            url = admin_token.get_service_admin_url("platform", "sysinv",
                                                    region_name)
            url += "/ihosts/" + self.name

            request_info = urllib2.Request(url)
            request_info.get_method = lambda: 'PATCH'
            request_info.add_header("X-Auth-Token", admin_token.get_id())
            request_info.add_header("Content-type", "application/json")
            request_info.add_header("Accept", "application/json")
            request_info.add_data(action)

            request = urllib2.urlopen(request_info)
            request.close()
            return True

        except KeystoneFail as e:
            LOG.error("Keystone authentication failed:{} ".format(e))
            return False

        except urllib2.HTTPError as e:
            LOG.error("%s, %s" % (e.code, e.read()))
            if e.code == 401:
                admin_token.set_expired()
            return False

        except urllib2.URLError as e:
            LOG.error(e)
            return False

    def is_unlocked(self):
        return(self.admin_state == HOST_ADMIN_STATE_UNLOCKED)

    def is_locked(self):
        return(not self.is_unlocked())

    def is_enabled(self):
        return(self.admin_state == HOST_ADMIN_STATE_UNLOCKED and
               self.operational_state == HOST_OPERATIONAL_STATE_ENABLED)

    def is_controller_enabled_provisioned(self):
        return(self.admin_state == HOST_ADMIN_STATE_UNLOCKED and
               self.operational_state == HOST_OPERATIONAL_STATE_ENABLED and
               self.personality == HOST_PERSONALITY_CONTROLLER and
               self.invprovision == HOST_PROVISIONED)

    def is_disabled(self):
        return(not self.is_enabled())

    def support_power_off(self):
        return(HOST_BM_TYPE_NOT_SET != self.bm_type)

    def is_powered_off(self):
        for status in self.avail_status:
            if status == HOST_AVAIL_STATE_POWERED_OFF:
                return(self.admin_state == HOST_ADMIN_STATE_LOCKED and
                       self.operational_state ==
                       HOST_OPERATIONAL_STATE_DISABLED)
        return False

    def is_powered_on(self):
        return not self.is_powered_off()

    def refresh_data(self, admin_token, region_name):
        """ Ask the System Inventory for an update view of the host """

        host_data = self.__host_update__(admin_token, region_name)
        self.__host_set_state__(host_data)

    def lock(self, admin_token, region_name):
        """ Asks the Platform to perform a lock against a host """

        if self.is_unlocked():
            action = json.dumps([{"path": "/action",
                                  "value": "lock", "op": "replace"}])

            return self.__host_action__(admin_token, action, region_name)

        return True

    def force_lock(self, admin_token, region_name):
        """ Asks the Platform to perform a force lock against a host """

        if self.is_unlocked():
            action = json.dumps([{"path": "/action",
                                  "value": "force-lock", "op": "replace"}])

            return self.__host_action__(admin_token, action, region_name)

        return True

    def unlock(self, admin_token, region_name):
        """ Asks the Platform to perform an ulock against a host """

        if self.is_locked():
            action = json.dumps([{"path": "/action",
                                  "value": "unlock", "op": "replace"}])

            return self.__host_action__(admin_token, action, region_name)

        return True

    def power_off(self, admin_token, region_name):
        """ Asks the Platform to perform a power-off against a host """

        if self.is_powered_on():
            action = json.dumps([{"path": "/action",
                                  "value": "power-off", "op": "replace"}])

            return self.__host_action__(admin_token, action, region_name)

        return True

    def power_on(self, admin_token, region_name):
        """ Asks the Platform to perform a power-on against a host """

        if self.is_powered_off():
            action = json.dumps([{"path": "/action",
                                  "value": "power-on", "op": "replace"}])

            return self.__host_action__(admin_token, action, region_name)

        return True


def get_hosts(admin_token, region_name, personality=None,
              exclude_hostnames=None):
    """ Asks System Inventory for a list of hosts """

    if exclude_hostnames is None:
        exclude_hostnames = []

    try:
        url = admin_token.get_service_admin_url("platform", "sysinv",
                                                region_name)
        url += "/ihosts/"

        request_info = urllib2.Request(url)
        request_info.add_header("X-Auth-Token", admin_token.get_id())
        request_info.add_header("Accept", "application/json")

        request = urllib2.urlopen(request_info)
        response = json.loads(request.read())
        request.close()

        host_list = []
        if personality is None:
            for host in response['ihosts']:
                if host['hostname'] not in exclude_hostnames:
                    host_list.append(Host(host['hostname'], host))
        else:
            for host in response['ihosts']:
                if host['hostname'] not in exclude_hostnames:
                    if (host['personality'] == "controller" and
                            personality == HOST_PERSONALITY_CONTROLLER):
                        host_list.append(Host(host['hostname'], host))

                    elif (host['personality'] == "worker" and
                          personality == HOST_PERSONALITY_WORKER):
                        host_list.append(Host(host['hostname'], host))

                    elif (host['personality'] == "storage" and
                          personality == HOST_PERSONALITY_STORAGE):
                        host_list.append(Host(host['hostname'], host))

        return host_list

    except KeystoneFail as e:
        LOG.error("Keystone authentication failed:{} ".format(e))
        return []

    except urllib2.HTTPError as e:
        LOG.error("%s, %s" % (e.code, e.read()))
        if e.code == 401:
            admin_token.set_expired()
        return []

    except urllib2.URLError as e:
        LOG.error(e)
        return []


def dict_to_patch(values, install_action=False):
    # install default action
    if install_action:
        values.update({'action': 'install'})
    patch = []
    for key, value in values.items():
        path = '/' + key
        patch.append({'op': 'replace', 'path': path, 'value': value})
    return patch


def get_shared_services():
    try:
        services = ""
        with openstack.OpenStack() as client:
            systems = client.sysinv.isystem.list()
            if systems:
                services = systems[0].capabilities.get("shared_services", "")
    except Exception as e:
        LOG.exception("failed to get shared services")
        raise e

    return services


def get_alarms():
    """ get all alarms """
    alarm_list = []
    try:
        with openstack.OpenStack() as client:
            alarm_list = client.sysinv.ialarm.list()
    except Exception as e:
        LOG.exception("failed to get alarms")
        raise e
    return alarm_list


def controller_enabled_provisioned(hostname):
    """ check if host is enabled """
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if (hostname == host.name and
                        host.is_controller_enabled_provisioned()):
                    LOG.info("host %s is enabled/provisioned" % host.name)
                    return True
    except Exception as e:
        LOG.exception("failed to check if host is enabled/provisioned")
        raise e
    return False


def get_system_uuid():
    """ get system uuid """
    try:
        sysuuid = ""
        with openstack.OpenStack() as client:
            systems = client.sysinv.isystem.list()
            if systems:
                sysuuid = systems[0].uuid
    except Exception as e:
        LOG.exception("failed to get system uuid")
        raise e
    return sysuuid


def get_oam_ip():
    """ get OAM ip details """
    try:
        with openstack.OpenStack() as client:
            oam_list = client.sysinv.iextoam.list()
            if oam_list:
                return oam_list[0]
    except Exception as e:
        LOG.exception("failed to get OAM IP")
        raise e
    return None


def get_mac_addresses(hostname):
    """ get MAC addresses for the host """
    macs = {}
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    port_list = client.sysinv.ethernet_port.list(host.uuid)
                    macs = {port.name: port.mac for port in port_list}
    except Exception as e:
        LOG.exception("failed to get MAC addresses")
        raise e
    return macs


def get_disk_serial_ids(hostname):
    """ get disk serial ids for the host """
    disk_serial_ids = {}
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    disk_list = client.sysinv.idisk.list(host.uuid)
                    disk_serial_ids = {
                        disk.device_node: disk.serial_id for disk in disk_list}
    except Exception as e:
        LOG.exception("failed to get disks")
        raise e
    return disk_serial_ids


def update_clone_system(descr, hostname):
    """ update system parameters on clone installation """
    try:
        with openstack.OpenStack() as client:
            systems = client.sysinv.isystem.list()
            if not systems:
                return False
            values = {
                'name': "Cloned_system",
                'description': descr
            }
            patch = dict_to_patch(values)
            LOG.info("Updating system: {} [{}]".format(systems[0].name, patch))
            client.sysinv.isystem.update(systems[0].uuid, patch)

            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    values = {
                        'location': {},
                        'serialid': ""
                    }
                    patch = dict_to_patch(values)
                    client.sysinv.ihost.update(host.uuid, patch)
                    LOG.info("Updating host: {} [{}]".format(host, patch))
    except Exception as e:
        LOG.exception("failed to update system parameters")
        raise e
    return True


def get_config_status(hostname):
    """ get config status of the host """
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    return host.config_status
    except Exception as e:
        LOG.exception("failed to get config status")
        raise e
    return None


def get_host_data(hostname):
    """ get data for the specified host """
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    return host
    except Exception as e:
        LOG.exception("failed to get host data")
        raise e
    return None


def do_worker_config_complete(hostname):
    """ enable worker functionality """
    try:
        with openstack.OpenStack() as client:
            hosts = get_hosts(client.admin_token,
                              client.conf['region_name'])
            for host in hosts:
                if hostname == host.name:
                    # Create/apply worker manifests
                    values = {
                        'action': "subfunction_config"
                    }
                    patch = dict_to_patch(values)
                    LOG.info("Applying worker manifests: {} [{}]"
                             .format(host, patch))
                    client.sysinv.ihost.update(host.uuid, patch)
    except Exception as e:
        LOG.exception("worker_config_complete failed")
        raise e


def get_storage_backend_services():
    """ get all storage backends and their assigned services """
    backend_service_dict = {}
    try:
        with openstack.OpenStack() as client:
            backend_list = client.sysinv.storage_backend.list()
            for backend in backend_list:
                backend_service_dict.update(
                    {backend.backend: backend.services})

    except Exception as e:
        LOG.exception("failed to get storage backend services")
        raise e

    return backend_service_dict
