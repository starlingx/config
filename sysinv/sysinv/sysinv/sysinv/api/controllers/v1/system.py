#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
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
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#

import jsonpatch
import os
import pecan
from pecan import rest
import re
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import host
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.api.controllers.v1 import controller_fs as controllerfs
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes as sys_kube
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class System(base.APIBase):
    """API representation of a system.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a isystem.
    """

    uuid = types.uuid
    "The UUID of the isystem"

    name = wtypes.text
    "The name of the isystem"

    system_type = wtypes.text
    "The type of the isystem"

    system_mode = wtypes.text
    "The mode of the isystem"

    description = wtypes.text
    "The name of the isystem"

    contact = wtypes.text
    "The contact of the isystem"

    location = wtypes.text
    "The location of the isystem"

    latitude = wtypes.text
    "The latitude GPS coordinate of the system"

    longitude = wtypes.text
    "The longitude GPS coordinate of the system"

    services = int
    "The services of the isystem"

    software_version = wtypes.text
    "A textual description of the entity"

    timezone = wtypes.text
    "The timezone of the isystem"

    links = [link.Link]
    "A list containing a self link and associated isystem links"

    ihosts = [link.Link]
    "Links to the collection of ihosts contained in this isystem"

    capabilities = {wtypes.text: api_utils.ValidTypes(wtypes.text, bool,
                                                      six.integer_types)}
    "System defined capabilities"

    region_name = wtypes.text
    "The region name of the isystem"

    distributed_cloud_role = wtypes.text
    "The distributed cloud role of the isystem"

    service_project_name = wtypes.text
    "The service project name of the isystem"

    security_feature = wtypes.text
    "Kernel arguments associated with exnabled spectre/meltdown fix features"

    def __init__(self, **kwargs):
        self.fields = list(objects.system.fields.keys())

        for k in self.fields:
            # Translate any special internal representation of data to its
            # customer facing form
            if k == 'security_feature':
                # look up which customer-facing-security-feature-string goes
                # with the kernel arguments tracked in sysinv
                kernel_args = kwargs.get(k)
                translated_string = kernel_args

                for user_string, args_string in \
                  constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_OPTS.items():
                    if args_string == kernel_args:
                        translated_string = user_string
                        break
                setattr(self, k, translated_string)
            else:
                # No translation required
                setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_isystem, expand=True):
        # isystem = isystem(**rpc_isystem.as_dict())
        minimum_fields = ['id', 'uuid', 'name', 'system_type', 'system_mode',
                          'description', 'capabilities', 'contact',
                          'location', 'latitude', 'longitude', 'software_version',
                          'created_at', 'updated_at', 'timezone',
                          'region_name', 'service_project_name',
                          'distributed_cloud_role', 'security_feature']

        fields = minimum_fields if not expand else None

        iSystem = System.from_rpc_object(rpc_isystem, fields)

        iSystem.links = [link.Link.make_link('self', pecan.request.host_url,
                                             'isystems', iSystem.uuid),
                         link.Link.make_link('bookmark',
                                             pecan.request.host_url,
                                             'isystems', iSystem.uuid,
                                             bookmark=True)
                         ]

        if expand:
            iSystem.ihosts = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'isystems',
                                        iSystem.uuid + "/ihosts"),
                              link.Link.make_link(
                                        'bookmark',
                                        pecan.request.host_url,
                                        'isystems',
                                        iSystem.uuid + "/ihosts",
                                        bookmark=True)
                              ]

        return iSystem


class SystemCollection(collection.Collection):
    """API representation of a collection of isystems."""

    isystems = [System]
    "A list containing isystem objects"

    def __init__(self, **kwargs):
        self._type = 'isystems'

    @classmethod
    def convert_with_links(cls, isystems, limit, url=None,
                           expand=False, **kwargs):
        collection = SystemCollection()
        collection.isystems = [System.convert_with_links(ch, expand)
                               for ch in isystems]
        # url = url or None
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'SystemController'


class SystemController(rest.RestController):
    """REST controller for isystem."""

    ihosts = host.HostController(from_isystem=True)
    "Expose ihosts as a sub-element of isystem"

    controller_fs = controllerfs.ControllerFsController()
    "Expose controller_fs as a sub-element of isystem"

    _custom_actions = {
        'detail': ['GET'],
        'mgmtvlan': ['GET'],
    }

    def __init__(self):
        self._bm_region = None
        self._kube_op = sys_kube.KubeOperator()

    def bm_region_get(self):
        if not self._bm_region:
            networks = pecan.request.dbapi.networks_get_by_type(
                constants.NETWORK_TYPE_BM)
            if networks:
                self._bm_region = constants.REGION_PRIMARY
            else:
                networks = pecan.request.dbapi.networks_get_by_type(
                    constants.NETWORK_TYPE_MGMT)
                # During initial system install no networks assigned yet
                if networks:
                    self._bm_region = constants.REGION_SECONDARY
        return self._bm_region

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    def _verify_sdn_disabled(self):
        # Check if SDN controller is configured
        sdn_controllers = pecan.request.dbapi.sdn_controller_get_list()
        if sdn_controllers:
            msg = _("SDN cannot be disabled when SDN controller is "
                    "configured.")
            raise wsme.exc.ClientSideError(msg)

    def _verify_sdn_enabled(self):
        # If SDN is enabled then OAM and Management network
        # must belong to the same Address Family
        oam_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_OAM)
        oam_address_pool = pecan.request.dbapi.address_pool_get(
            oam_network.pool_uuid)
        oam_ip_version = oam_address_pool.family
        mgmt_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        mgmt_address_pool = pecan.request.dbapi.address_pool_get(
            mgmt_network.pool_uuid)
        mgmt_ip_version = mgmt_address_pool.family

        if oam_ip_version != mgmt_ip_version:
            msg = _("Invalid network address - OAM and Management Network IP"
                    " Families must be the same when SDN is enabled.")
            raise wsme.exc.ClientSideError(msg)

    def _check_hosts(self):
        hosts = pecan.request.dbapi.ihost_get_list()
        for h in hosts:
            if api_utils.is_aio_simplex_host_unlocked(h):
                raise wsme.exc.ClientSideError(
                    _("Host {} must be locked.".format(h['hostname'])))
            elif (h['administrative'] != constants.ADMIN_LOCKED and
                  constants.WORKER in h['subfunctions'] and
                  not api_utils.is_host_active_controller(h) and
                  not api_utils.is_host_simplex_controller(h)):
                raise wsme.exc.ClientSideError(
                    _("Host {} must be locked.".format(h['hostname'])))

    def _check_interfaces(self, system_mode):
        iinterfaces = pecan.request.dbapi.iinterface_get_all()
        mgmt_if = None
        cluster_host_if = None

        for iif in iinterfaces:
            if iif.networktypelist:
                if constants.NETWORK_TYPE_MGMT in iif.networktypelist:
                    mgmt_if = iif
                if constants.NETWORK_TYPE_CLUSTER_HOST in iif.networktypelist:
                    cluster_host_if = iif
            if mgmt_if and cluster_host_if:
                break

        if mgmt_if is None:
            msg = _("Cannot modify system mode to %s "
                    "without configuring the management "
                    "interface." % system_mode)
            raise wsme.exc.ClientSideError(msg)
        if mgmt_if.ifname == constants.LOOPBACK_IFNAME:
            msg = _("Cannot modify system mode to %s "
                    "when the management interface is "
                    "configured on loopback. "
                    % system_mode)
            raise wsme.exc.ClientSideError(msg)
        if cluster_host_if is None:
            msg = _("Cannot modify system mode to %s "
                    "without configuring the cluster-host "
                    "interface." % system_mode)
            raise wsme.exc.ClientSideError(msg)
        if cluster_host_if.ifname == constants.LOOPBACK_IFNAME:
            msg = _("Cannot modify system mode to %s "
                    "when the cluster-host interface is "
                    "configured on loopback. "
                    % system_mode)
            raise wsme.exc.ClientSideError(msg)

    def _check_controller_locked(self):
        controller = api_utils.HostHelper.get_active_controller()
        if controller is None:
            return
        if controller.administrative != constants.ADMIN_LOCKED:
            msg = _("Cannot modify system mode if host '%s' is not "
                    "locked." % controller.hostname)
            raise wsme.exc.ClientSideError(msg)

    def _get_isystem_collection(self, marker, limit, sort_key, sort_dir,
                                expand=False, resource_url=None):
        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.system.get_by_uuid(pecan.request.context,
                                                    marker)
        isystem = pecan.request.dbapi.isystem_get_list(limit, marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)
        for i in isystem:
            i.capabilities['bm_region'] = self.bm_region_get()

        return SystemCollection.convert_with_links(isystem, limit,
                                                   url=resource_url,
                                                   expand=expand,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir)

    @wsme_pecan.wsexpose(SystemCollection, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of isystems.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        return self._get_isystem_collection(marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(SystemCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of isystem with detail.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        # /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "isystem":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['isystem', 'detail'])
        return self._get_isystem_collection(marker, limit, sort_key, sort_dir,
                                            expand, resource_url)

    @wsme_pecan.wsexpose(System, types.uuid)
    def get_one(self, isystem_uuid):
        """Retrieve information about the given isystem.

        :param isystem_uuid: UUID of a isystem.
        """
        rpc_isystem = objects.system.get_by_uuid(pecan.request.context,
                                                 isystem_uuid)
        rpc_isystem.capabilities['bm_region'] = self.bm_region_get()
        return System.convert_with_links(rpc_isystem)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(System, body=System)
    def post(self, isystem):
        """Create a new system."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(System, types.uuid, body=[six.text_type])
    def patch(self, isystem_uuid, patch):
        """Update an existing isystem.

        :param isystem_uuid: UUID of a isystem.
        :param patch: a json PATCH document to apply to this isystem.
        """
        rpc_isystem = objects.system.get_by_uuid(pecan.request.context,
                                                 isystem_uuid)
        system_dict = rpc_isystem.as_dict()
        updates = self._get_updates(patch)
        change_https = False
        change_sdn = False
        change_dc_role = False
        vswitch_type = None
        new_system_mode = None
        ALLOWED_CHARS = r"^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'\"|,.<>\/? ]*$"

        # prevent description field from being updated
        for p in jsonpatch.JsonPatch(patch):
            if p['value'] is not None and not re.match(ALLOWED_CHARS, p['value']):
                raise wsme.exc.ClientSideError(_("System values must not "
                                               "contain special characters."))

            if p['path'] == '/software_version':
                raise wsme.exc.ClientSideError(_("software_version field "
                                                 "cannot be modified."))

            if p['path'] == '/system_type':
                if rpc_isystem is not None:
                    if rpc_isystem.system_type is not None:
                        raise wsme.exc.ClientSideError(_("system_type field "
                                                         "cannot be "
                                                         "modified."))

            if (p['path'] == '/system_mode' and p.get('value') !=
               rpc_isystem.system_mode):
                if rpc_isystem is not None and \
                   rpc_isystem.system_mode is not None:
                    if rpc_isystem.system_type != constants.TIS_AIO_BUILD:
                        raise wsme.exc.ClientSideError(
                            "system_mode can only be modified on an "
                            "AIO system")
                    system_mode_options = [constants.SYSTEM_MODE_DUPLEX,
                                           constants.SYSTEM_MODE_DUPLEX_DIRECT]
                    new_system_mode = p['value']
                    # Allow modification to system mode during bootstrap. Once the
                    # initial configuration is complete, this type of request will
                    # be bound to the conditions below.
                    if cutils.is_initial_config_complete():
                        if rpc_isystem.system_mode == \
                                constants.SYSTEM_MODE_DUPLEX:
                            msg = _("Cannot modify system mode when it is "
                                    "set to %s." % rpc_isystem.system_mode)
                            raise wsme.exc.ClientSideError(msg)
                        elif new_system_mode != constants.SYSTEM_MODE_SIMPLEX:
                            self._check_controller_locked()
                            self._check_interfaces(new_system_mode)
                    else:
                        system_mode_options.append(constants.SYSTEM_MODE_SIMPLEX)

                    if new_system_mode not in system_mode_options:
                        raise wsme.exc.ClientSideError(
                            "Invalid value for system_mode, it can only"
                            " be modified to '%s' or '%s'" %
                            (constants.SYSTEM_MODE_DUPLEX,
                             constants.SYSTEM_MODE_DUPLEX_DIRECT))

            if p['path'] == '/timezone':
                timezone = p['value']
                if not os.path.isfile("/usr/share/zoneinfo/%s" % timezone):
                    raise wsme.exc.ClientSideError(_("Timezone file %s "
                                                     "does not exist." %
                                                     timezone))

            if (p['path'] == '/latitude' or p['path'] == '/longitude'):
                if p['value'] is not None:
                    if len(p['value']) > 30:
                        raise wsme.exc.ClientSideError("Geolocation coordinates can not be "
                                                       "longer than 30 characters")

            if p['path'] == '/sdn_enabled':
                sdn_enabled = p['value'].lower()
                patch.remove(p)

            if p['path'] == '/https_enabled':
                https_enabled = p['value'].lower()
                patch.remove(p)

            if p['path'] == '/distributed_cloud_role':
                distributed_cloud_role = p['value']
                patch.remove(p)

            if p['path'] == '/vswitch_type':
                vswitch_type = p['value']
                patch.remove(p)

            if p['path'] == '/security_feature':
                security_feature = p['value']
                patch.remove(p)

        try:
            patched_system = jsonpatch.apply_patch(system_dict,
                                                   jsonpatch.JsonPatch(patch))
        except api_utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        if 'system_mode' in updates:
            # Update capabilities if system mode is changed from simplex to
            # duplex after the initial config is complete
            if (cutils.is_initial_config_complete() and
                    rpc_isystem.system_mode == constants.SYSTEM_MODE_SIMPLEX and
                    new_system_mode == constants.SYSTEM_MODE_DUPLEX):
                patched_system['capabilities']['simplex_to_duplex_migration'] = True

        if 'sdn_enabled' in updates:
            if sdn_enabled != rpc_isystem['capabilities']['sdn_enabled']:
                self._check_hosts()
                change_sdn = True
                if sdn_enabled == 'true':
                    self._verify_sdn_enabled()
                    patched_system['capabilities']['sdn_enabled'] = True
                else:
                    self._verify_sdn_disabled()
                    patched_system['capabilities']['sdn_enabled'] = False

        if 'https_enabled' in updates:
            # Pre-check: if user is setting https_enabled to false
            # while 'ssl' cert is managed by cert-manager, return error
            # (Otherwise, cert-mon will turn https back on during cert-renewal process)
            managed_by_cm = self._kube_op.kube_get_secret(
                    constants.RESTAPI_CERT_SECRET_NAME,
                    constants.CERT_NAMESPACE_PLATFORM_CERTS)
            if https_enabled == 'false' and managed_by_cm is not None:
                msg = "Certificate is currently being managed by cert-manager. " \
                    "Remove %s Certificate and Secret before disabling https." % \
                    constants.RESTAPI_CERT_SECRET_NAME
                raise wsme.exc.ClientSideError(_(msg))

            if https_enabled != rpc_isystem['capabilities']['https_enabled']:
                change_https = True
                if https_enabled == 'true':
                    patched_system['capabilities']['https_enabled'] = True
                else:
                    patched_system['capabilities']['https_enabled'] = False
            else:
                raise wsme.exc.ClientSideError(_("https_enabled is already set"
                                                 " as %s" % https_enabled))

        if 'distributed_cloud_role' in updates:
            # At this point dc role cannot be changed after initial
            # configuration is complete
            if (rpc_isystem['distributed_cloud_role'] is not None and
                    cutils.is_initial_config_complete()):
                raise wsme.exc.ClientSideError(
                    _("distributed_cloud_role is already set "
                      " as %s" % rpc_isystem['distributed_cloud_role']))
            # allow set the role to None before the initial config
            # is complete
            elif ((distributed_cloud_role in
                  [constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
                   constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD] or
                   distributed_cloud_role is None) and not
                    cutils.is_initial_config_complete()):
                change_dc_role = True
                patched_system['distributed_cloud_role'] = distributed_cloud_role
            else:
                raise wsme.exc.ClientSideError(_("Unexpected value %s specified"
                                                 " for distributed_cloud_role"
                                                 % distributed_cloud_role))

        if 'vswitch_type' in updates:
            if vswitch_type == rpc_isystem['capabilities']['vswitch_type']:
                raise wsme.exc.ClientSideError(_("vswitch_type is already set"
                                                 " as %s" % vswitch_type))
            patched_system['capabilities']['vswitch_type'] = vswitch_type

        if 'security_feature' in updates:
            # Security feature string must be translated from user values to
            # kernel options
            if (security_feature in
                    constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_OPTS):
                security_feature_value = \
                    constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_OPTS[security_feature]
                patched_system['security_feature'] = security_feature_value
            else:
                raise wsme.exc.ClientSideError(_("Unexpected value %s specified for "
                                                 "security_feature" % security_feature))

        # Update only the fields that have changed
        name = ""
        contact = ""
        location = ""
        system_mode = ""
        timezone = ""
        capabilities = {}
        distributed_cloud_role = ""
        security_feature = ""
        delta_fields = {}

        for field in objects.system.fields:
            if rpc_isystem[field] != patched_system[field]:
                rpc_isystem[field] = patched_system[field]
                delta_fields[field] = patched_system[field]
                if field == 'name':
                    name = rpc_isystem[field]
                if field == 'contact':
                    contact = rpc_isystem[field]
                if field == 'location':
                    location = rpc_isystem[field]
                if field == 'system_mode':
                    system_mode = rpc_isystem[field]
                if field == 'timezone':
                    timezone = rpc_isystem[field]
                if field == 'capabilities':
                    capabilities = rpc_isystem[field]
                if field == 'distributed_cloud_role':
                    distributed_cloud_role = rpc_isystem[field]
                if field == 'security_feature':
                    security_feature = rpc_isystem[field]

        delta = rpc_isystem.obj_what_changed()
        delta_handle = list(delta)
        rpc_isystem.save()

        pecan.request.rpcapi.evaluate_apps_reapply(
            pecan.request.context,
            trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_SYSTEM_MODIFY,
                     'delta_fields': delta_fields})

        if name:
            LOG.info("update system name")
            pecan.request.rpcapi.configure_isystemname(pecan.request.context,
                                                       name)
        if name or location or contact:
            LOG.info("update SNMP config")
            pecan.request.rpcapi.update_snmp_config(pecan.request.context)
        if 'system_mode' in delta_handle:
            LOG.info("update system mode %s" % system_mode)
            pecan.request.rpcapi.update_system_mode_config(
                pecan.request.context)
        if timezone:
            LOG.info("update system timezone to %s" % timezone)
            pecan.request.rpcapi.configure_system_timezone(
                pecan.request.context)
        if capabilities:
            if change_sdn:
                LOG.info("update sdn to %s" % capabilities)
                pecan.request.rpcapi.update_sdn_enabled(pecan.request.context)
            if change_https:
                LOG.info("update https to %s" % capabilities)
                pecan.request.rpcapi.configure_system_https(
                    pecan.request.context)
            if vswitch_type:
                LOG.info("update vswitch_type to %s" % capabilities)
                pecan.request.rpcapi.update_vswitch_type(
                    pecan.request.context)

        if distributed_cloud_role and change_dc_role:
            LOG.info("update distributed cloud role to %s" % distributed_cloud_role)
            pecan.request.rpcapi.update_distributed_cloud_role(
                pecan.request.context)

        # check if we need to config the system controller database
        if (change_dc_role and distributed_cloud_role ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            hosts = pecan.request.dbapi.ihost_get_by_personality(
                constants.CONTROLLER)
            # this is a replay case after the first host has been created
            if len(hosts) == 1:
                pecan.request.rpcapi.configure_system_controller(
                    pecan.request.context, hosts[0])

        if 'security_feature' in delta_handle:
            LOG.info("update security_feature %s" % security_feature)
            pecan.request.rpcapi.update_security_feature_config(
                pecan.request.context)

        return System.convert_with_links(rpc_isystem)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, isystem_uuid):
        """Delete a isystem.

        :param isystem_uuid: UUID of a isystem.
        """
        raise exception.OperationNotPermitted

    @wsme_pecan.wsexpose(int)
    def mgmtvlan(self):
        local_hostname = cutils.get_local_controller_hostname()
        controller = pecan.request.dbapi.ihost_get(local_hostname)
        host_id = controller['id']
        interface_list = pecan.request.dbapi.iinterface_get_by_ihost(host_id)
        for interface in interface_list:
            if constants.NETWORK_TYPE_MGMT in interface['networktypelist']:
                if 'vlan_id' not in interface:
                    return 0
                else:
                    return interface['vlan_id']
        return None
