#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
from sysinv.api.controllers.v1.rest_api import rest_api_request

from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


def sensorgroup_add(token, address, port, isensorgroup_hwmon, timeout):
    """
    Sends a SensorGroup Add command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensorgroups/"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = isensorgroup_hwmon

    LOG.info("sensorgroup_add for %s cmd=%s hdr=%s payload=%s" %
             (isensorgroup_hwmon['sensorgroupname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def sensorgroup_modify(token, address, port, isensorgroup_hwmon, timeout):
    """
    Sends a SensorGroup Modify command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensorgroups/%s" % isensorgroup_hwmon['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = isensorgroup_hwmon

    LOG.info("sensorgroup_modify for %s cmd=%s hdr=%s payload=%s" %
             (isensorgroup_hwmon['sensorgroupname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    LOG.debug("sensorgroup modify response=%s" % response)

    return response


def sensorgroup_delete(token, address, port, isensorgroup_hwmon, timeout):
    """
    Sends a SensorGroup Delete command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensorgroups/%s" % isensorgroup_hwmon['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = None

    LOG.info("sensorgroup_delete for %s cmd=%s hdr=%s payload=%s" %
             (isensorgroup_hwmon['uuid'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "DELETE", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def sensorgroup_relearn(token, address, port, payload, timeout):
    """
    Sends a SensorGroup Relearn command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensorgroups/relearn"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = payload

    LOG.info("sensorgroup_relearn for %s cmd=%s hdr=%s payload=%s" %
             (payload['host_uuid'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def sensor_add(token, address, port, isensor_hwmon, timeout):
    """
    Sends a Sensor Add command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensors/"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = isensor_hwmon

    LOG.info("sensor_add for %s cmd=%s hdr=%s payload=%s" %
             (isensor_hwmon['sensorname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def sensor_modify(token, address, port, isensor_hwmon, timeout):
    """
    Sends a Sensor Modify command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensors/%s" % isensor_hwmon['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = isensor_hwmon

    LOG.info("sensor_modify for %s cmd=%s hdr=%s payload=%s" %
             (isensor_hwmon['sensorname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def sensor_delete(token, address, port, isensor_hwmon, timeout):
    """
    Sends a Sensor Delete command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/isensors/%s" % isensor_hwmon['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = None

    LOG.info("sensor_delete for %s cmd=%s hdr=%s payload=%s" %
             (isensor_hwmon['uuid'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "DELETE", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response
