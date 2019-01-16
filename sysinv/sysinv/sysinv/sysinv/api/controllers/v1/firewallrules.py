# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import pecan
from pecan import expose
from pecan import rest
import wsme
import wsmeext.pecan as wsme_pecan
from wsme import types as wtypes
from sysinv import objects

from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


LOCK_NAME = 'FirewallRulesController'


class FirewallRules(base.APIBase):
    """API representation of oam custom firewall rules.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    oam custom firewall rules.
    """

    uuid = types.uuid
    "Unique UUID for the firewall rules"

    firewall_sig = wtypes.text
    "Represents the signature of the custom firewall rules"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = list(objects.firewallrules.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

        self.fields.append('firewall_sig')
        setattr(self, 'firewall_sig', kwargs.get('value', None))

    @classmethod
    def convert_with_links(cls, rpc_firewallrules, expand=True):
        parm = FirewallRules(**rpc_firewallrules.as_dict())
        if not expand:
            parm.unset_fields_except(['uuid', 'firewall_sig', 'updated_at'])

        parm.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'parameters', parm.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'parameters', parm.uuid,
                                          bookmark=True)
                      ]
        return parm


def firewallrules_as_dict(sp_firewallrules):
    sp_firewallrules_dict = sp_firewallrules.as_dict()
    keys = objects.firewallrules.fields.keys()
    for k, v in sp_firewallrules.as_dict().items():
        if k == 'value':
            sp_firewallrules_dict['firewall_sig'] = \
                sp_firewallrules_dict.pop('value')
        elif k not in keys:
            sp_firewallrules_dict.pop(k)
    return sp_firewallrules_dict


class FirewallRulesCollection(collection.Collection):
    """API representation of a collection of firewall rules."""

    firewallrules = [FirewallRules]
    "A list containing firewallrules objects"

    def __init__(self, **kwargs):
        self._type = 'firewallrules'

    @classmethod
    def convert_with_links(cls, rpc_firewallrules, limit, url=None,
                           expand=False,
                           **kwargs):
        collection = FirewallRulesCollection()
        collection.firewallrules = [FirewallRules.convert_with_links(p, expand)
                                    for p in rpc_firewallrules]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


class FirewallRulesController(rest.RestController):
    """REST controller for Custom Firewall Rules."""

    _custom_actions = {
        'import_firewall_rules': ['POST'],
    }

    def __init__(self):
        self._api_token = None

    @wsme_pecan.wsexpose(FirewallRules, types.uuid)
    def get_one(self, firewallrules_uuid):
        """Retrieve information about the given firewall rules."""

        try:
            sp_firewallrules = objects.firewallrules.get_by_uuid(
                pecan.request.context, firewallrules_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No firewall rules found for %s" % firewallrules_uuid))

        return FirewallRules.convert_with_links(sp_firewallrules)

    def _get_firewallrules_collection(self, marker, limit,
                                      sort_key, sort_dir, expand=False,
                                      resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        sp_firewallrules = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_SYSINV,
            name=constants.SERVICE_PARAM_NAME_SYSINV_FIREWALL_RULES_ID)
        sp_firewallrules.firewall_sig = sp_firewallrules.value

        sp_firewallrules = [sp_firewallrules]

        rules = FirewallRulesCollection.convert_with_links(
            sp_firewallrules,
            limit,
            url=resource_url,
            expand=expand,
            sort_key=sort_key,
            sort_dir=sort_dir)
        return rules

    @wsme_pecan.wsexpose(FirewallRulesCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of firewallrules. Only one per system"""

        sort_key = ['section', 'name']
        return self._get_firewallrules_collection(marker, limit,
                                                  sort_key, sort_dir)

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def import_firewall_rules(self, file):
        file = pecan.request.POST['file']
        if not file.filename:
            return dict(success="", error="Error: No firewall rules uploaded")

        # Check if the firewallrules_file size is large
        try:
            _check_firewall_rules_file_size(file)
        except Exception as e:
            LOG.exception(e)
            return dict(success="", error=e.message)

        file.file.seek(0, os.SEEK_SET)
        contents = file.file.read()

        # Get OAM network ip version
        oam_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_OAM)
        oam_address_pool = pecan.request.dbapi.address_pool_get(
            oam_network.pool_uuid)

        try:
            firewall_sig = pecan.request.rpcapi.update_firewall_config(
                pecan.request.context, oam_address_pool.family, contents)

            # push the updated firewall_sig into db
            sp_firewallrules = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_PLATFORM,
                section=constants.SERVICE_PARAM_SECTION_PLATFORM_SYSINV,
                name=constants.SERVICE_PARAM_NAME_SYSINV_FIREWALL_RULES_ID)

            sp_firewallrules = pecan.request.dbapi.service_parameter_update(
                sp_firewallrules.uuid,
                {'value': firewall_sig, 'personality': constants.CONTROLLER})

            sp_firewallrules_dict = firewallrules_as_dict(sp_firewallrules)

            LOG.info("import_firewallrules sp_firewallrules={}".format(
                sp_firewallrules_dict))

        except Exception as e:
            return dict(success="", error=e.value)

        return dict(success="", error="", body="",
                    firewallrules=sp_firewallrules_dict)


def _check_firewall_rules_file_size(firewallrules_file):
    firewallrules_file.file.seek(0, os.SEEK_END)
    size = firewallrules_file.file.tell()
    if size > constants.FIREWALL_RULES_MAX_FILE_SIZE:
        raise wsme.exc.ClientSideError(
            _("Firewall rules file size exceeded maximum supported"
              " size of %s bytes." % constants.FIREWALL_RULES_MAX_FILE_SIZE))
