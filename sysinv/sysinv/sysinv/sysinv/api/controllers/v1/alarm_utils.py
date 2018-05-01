#!/usr/bin/env python
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.openstack.common import log, uuidutils
from sysinv.common import exception
import pecan


LOG = log.getLogger(__name__)

ALARM_ENTITY_TYPES_USE_UUID = ['port']
ENTITY_SEP = '.'
KEY_VALUE_SEP = '='


def make_display_id(iid, replace=False):
    if replace:
        instance_id = replace_uuids(iid)
    else:
        instance_id = replace_name_with_uuid(iid)

    return instance_id


def replace_name_with_uuid(instance_id):
    hName = None
    port = None
    for keyvalue in instance_id.split(ENTITY_SEP):
        try:
            (key, value) = keyvalue.split(KEY_VALUE_SEP, 1)
        except ValueError:
            return instance_id

        if key == 'host':
            hName = value

        elif key == 'port':
            if hName and not uuidutils.is_uuid_like(value.strip()):
                try:
                    ihost = pecan.request.dbapi.ihost_get_by_hostname(hName)
                    port = pecan.request.dbapi.port_get(value,
                                                        hostid=ihost['id'])
                except exception.NodeNotFound:
                    LOG.error("Can't find the host by name %s", hName)
                    pass
                except exception.ServerNotFound:
                    LOG.error("Can't find the port for uuid %s", value)
                    pass

                if port:
                    new_id = key + KEY_VALUE_SEP + port.uuid
                    instance_id = instance_id.replace(keyvalue, new_id, 1)

    return instance_id


def replace_uuid_with_name(key, value):
    new_id = None
    if key == 'port':
        port = None
        try:
            port = pecan.request.dbapi.port_get(value)
        except exception.ServerNotFound:
            LOG.error("Can't find the port for uuid %s", value)
            pass

        if port is not None:
            new_id = key + KEY_VALUE_SEP + port.name

    return new_id


def replace_uuids(instance_id):
    for keyvalue in instance_id.split(ENTITY_SEP):
        try:
            (key, value) = keyvalue.split(KEY_VALUE_SEP, 1)
        except ValueError:
            return instance_id

        if key in ALARM_ENTITY_TYPES_USE_UUID:
            if uuidutils.is_uuid_like(value.strip()):
                new_id = replace_uuid_with_name(key, value)
            else:
                new_id = key + KEY_VALUE_SEP + value

            if new_id is not None:
                instance_id = instance_id.replace(keyvalue, new_id, 1)

    return instance_id
