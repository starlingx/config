# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

import jsonpatch
import os

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import excutils
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

from fm_api import constants as fm_constants
from fm_api import fm_api

LOG = log.getLogger(__name__)


class TPMConfigPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class TPMConfig(base.APIBase):
    """API representation of TPM Configuration.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an tpmconfig.
    """

    uuid = types.uuid
    "Unique UUID for this tpmconfig"

    cert_path = wtypes.text
    "Represents the path of the SSL certificate to be stored in TPM"

    public_path = wtypes.text
    "Represents the path of the SSL public key"

    tpm_path = wtypes.text
    "Represents the path to store TPM certificate"

    state = types.MultiType({dict})
    "Represents the state of the TPM config"

    links = [link.Link]
    "A list containing a self link and associated tpmconfig links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.tpmconfig.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'cert_path' and 'public_path' are
        # not part of objects.tpmconfig.fields
        # (they are an API-only attribute)
        for fp in ['cert_path', 'public_path']:
            self.fields.append(fp)
            setattr(self, fp, kwargs.get(fp, None))

        # 'state' is not part of objects.tpmconfig.fields
        # (it is an API-only attribute)
        self.fields.append('state')
        setattr(self, 'state', kwargs.get('state', None))

    @classmethod
    def convert_with_links(cls, rpc_tpmconfig, expand=True):

        tpm = TPMConfig(**rpc_tpmconfig.as_dict())
        if not expand:
            tpm.unset_fields_except(['uuid',
                                     'cert_path',
                                     'public_path',
                                     'tpm_path',
                                     'state',
                                     'created_at',
                                     'updated_at'])
        # insert state
        tpm = _insert_tpmdevices_state(tpm)

        tpm.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'tpmconfigs', tpm.uuid),
                     link.Link.make_link('bookmark', pecan.request.host_url,
                                         'tpmconfigs', tpm.uuid,
                                          bookmark=True)]

        return tpm


class TPMConfigCollection(collection.Collection):
    """API representation of a collection of tpmconfigs."""

    tpmconfigs = [TPMConfig]
    "A list containing tpmconfig objects"

    def __init__(self, **kwargs):
        self._type = 'tpmconfigs'

    @classmethod
    def convert_with_links(cls, rpc_tpmconfigs, limit, url=None,
                           expand=False, **kwargs):
        collection = TPMConfigCollection()
        collection.tpmconfigs = [TPMConfig.convert_with_links(p, expand)
                                 for p in rpc_tpmconfigs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############

def _check_tpmconfig_data(tpmconfig):

    if not utils.get_https_enabled():
        raise wsme.exc.ClientSideError(
            _("Cannot configure TPM without HTTPS mode being enabled"))

    if not tpmconfig.get('cert_path', None):
        raise wsme.exc.ClientSideError(
            _("Cannot configure TPM without cert_path provided"))

    if not tpmconfig.get('public_path', None):
        raise wsme.exc.ClientSideError(
            _("Cannot configure TPM without public_path provided"))

    if not tpmconfig.get('tpm_path', None):
        raise wsme.exc.ClientSideError(
            _("Cannot configure TPM without tpm_path provided"))

    # validate the key paths
    values = [tpmconfig['cert_path'],
              tpmconfig['tpm_path'],
              tpmconfig['public_path']]

    for i, item in enumerate(values):
        # ensure valid paths
        if os.path.isabs(item):
            if i == 0:
                # ensure key exists
                if not os.path.isfile(item):
                    raise wsme.exc.ClientSideError(_(
                        "Cert path is not a valid existing file"))
        else:
            raise wsme.exc.ClientSideError(_(
                "TPM configuration arguments must be file paths"))
    return tpmconfig


def _clear_existing_tpmconfig_alarms():
    # Clear all existing TPM configuration alarms,
    # for one or both controller hosts
    obj = fm_api.FaultAPIs()

    alarms = obj.get_faults_by_id(
                fm_constants.FM_ALARM_ID_TPM_INIT)
    if not alarms:
        return
    for alarm in alarms:
        obj.clear_fault(
                fm_constants.FM_ALARM_ID_TPM_INIT,
                alarm.entity_instance_id)


def _insert_tpmdevices_state(tpmconfig):
    # update the tpmconfig state with the per host
    # tpmdevice state
    if not tpmconfig:
        return
    tpmdevices = pecan.request.dbapi.tpmdevice_get_list()
    tpmconfig.state = {}
    for device in tpmdevices:
        # extract the state info per host
        ihost = pecan.request.dbapi.ihost_get(device['host_id'])
        if ihost:
            tpmconfig.state[ihost.hostname] = device.state
    return tpmconfig


class TPMConfigController(rest.RestController):
    """REST controller for tpmconfigs."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_tpmconfigs_collection(self, uuid, marker, limit,
                                    sort_key, sort_dir, expand=False,
                                    resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.tpmconfig.get_by_uuid(pecan.request.context,
                                                       marker)

        tpms = pecan.request.dbapi.tpmconfig_get_list(limit,
                                                      marker_obj,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

        return TPMConfigCollection.convert_with_links(tpms, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @wsme_pecan.wsexpose(TPMConfigCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of tpmconfigs. Only one per system"""
        return self._get_tpmconfigs_collection(uuid, marker, limit,
                                               sort_key, sort_dir)

    @wsme_pecan.wsexpose(TPMConfig, types.uuid)
    def get_one(self, tpmconfig_uuid):
        """Retrieve information about the given tpmconfig."""
        rpc_tpmconfig = objects.tpmconfig.get_by_uuid(pecan.request.context,
                                                      tpmconfig_uuid)
        return TPMConfig.convert_with_links(rpc_tpmconfig)

    @wsme_pecan.wsexpose(TPMConfig, body=TPMConfig)
    def post(self, tpmconfig):
        """Create a new tpmconfig."""
        # There must not already be an existing tpm config
        try:
            tpm = pecan.request.dbapi.tpmconfig_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "tpmconfig rejected: A TPM configuration already exists."))

        _check_tpmconfig_data(tpmconfig.as_dict())
        try:
            new_tpmconfig = pecan.request.dbapi.tpmconfig_create(
                                                tpmconfig.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a tpm config record."))

        # apply TPM configuration via agent RPCs
        try:
            pecan.request.rpcapi.update_tpm_config(
                pecan.request.context,
                tpmconfig.as_dict())

            pecan.request.rpcapi.update_tpm_config_manifests(
                pecan.request.context)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        return tpmconfig.convert_with_links(new_tpmconfig)

    @wsme.validate(types.uuid, [TPMConfigPatchType])
    @wsme_pecan.wsexpose(TPMConfig, types.uuid,
                         body=[TPMConfigPatchType])
    def patch(self, tpmconfig_uuid, patch):
        """Update the current tpm configuration."""

        tpmconfig = objects.tpmconfig.get_by_uuid(pecan.request.context,
                                                  tpmconfig_uuid)
        tpmdevices = pecan.request.dbapi.tpmdevice_get_list()

        # if any of the tpm devices are in APPLYING state
        # then disallow a modification till previous config
        # either applies or fails
        for device in tpmdevices:
            if device.state == constants.TPMCONFIG_APPLYING:
                raise wsme.exc.ClientSideError(_("TPM Device %s is still "
                    "in APPLYING state. Wait for the configuration "
                    "to finish before attempting a modification." %
                    device.uuid))

        # get attributes to be updated
        updates = self._get_updates(patch)

        # before we can update we have do a quick semantic check
        if 'uuid' in updates:
            raise wsme.exc.ClientSideError(_("uuid cannot be modified"))

        _check_tpmconfig_data(updates)

        # update only DB fields that have changed
        # we cannot use the entire set of updates
        # since some of them are API updates only
        for field in objects.tpmconfig.fields:
            if updates.get(field, None):
                tpmconfig.field = updates[field]
        tpmconfig.save()

        new_tpmconfig = tpmconfig.as_dict()

        # for conductor and agent updates, consider the entire
        # set of incoming updates
        new_tpmconfig.update(updates)

        # set a modify flag within the tpmconfig, this will inform
        # the conductor as well as the agents that we are looking
        # to modify the TPM configuration, and not a creation
        new_tpmconfig['modify'] = True

        # apply TPM configuration via agent RPCs
        try:
            pecan.request.rpcapi.update_tpm_config(
                pecan.request.context,
                new_tpmconfig)

            pecan.request.rpcapi.update_tpm_config_manifests(
                pecan.request.context)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        return TPMConfig.convert_with_links(tpmconfig)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete a tpmconfig."""
        tpmconfig = objects.tpmconfig.get_by_uuid(pecan.request.context,
                                                  uuid)

        # clear all existing alarms for this TPM configuration
        _clear_existing_tpmconfig_alarms()

        # clear all tpmdevice configurations for all hosts
        tpmdevices = pecan.request.dbapi.tpmdevice_get_list()
        for device in tpmdevices:
            pecan.request.dbapi.tpmdevice_destroy(device.uuid)

        # need to cleanup the tpm file object
        tpm_file = tpmconfig.tpm_path

        pecan.request.dbapi.tpmconfig_destroy(uuid)
        pecan.request.rpcapi.update_tpm_config_manifests(
                pecan.request.context,
                delete_tpm_file=tpm_file)
