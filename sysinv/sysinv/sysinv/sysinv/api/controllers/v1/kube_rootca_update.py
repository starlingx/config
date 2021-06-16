#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import os
import pecan
import six
import wsme
import wsmeext.pecan as wsme_pecan

from fm_api import fm_api
from fm_api import constants as fm_constants
from oslo_log import log
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from wsme import types as wtypes


LOG = log.getLogger(__name__)
LOCK_NAME = 'KubeRootCAUpdateController'


class KubeRootCAUpdate(base.APIBase):
    """API representation of a Kubernetes RootCA Update."""

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    from_rootca_cert = wtypes.text
    "The from certificate for the kubernetes rootCA update"

    to_rootca_cert = wtypes.text
    "The to certificate for the kubernetes rootCA update"

    state = wtypes.text
    "Kubernetes rootCA update state"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Additional properties to be used in kube_rootca_update operations"

    links = [link.Link]
    "A list containing a self link and associated kubernetes rootca update links"

    def __init__(self, **kwargs):
        self.fields = objects.kube_rootca_update.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_kube_rootca_update, expand=True):
        kube_rootca_update = KubeRootCAUpdate(**rpc_kube_rootca_update.as_dict())
        if not expand:
            kube_rootca_update.unset_fields_except(['uuid', 'from_rootca_cert',
                                                    'to_rootca_cert', 'state'])

        kube_rootca_update.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'kube_rootca_update', kube_rootca_update.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'kube_rootca_update', kube_rootca_update.uuid,
                                bookmark=True)
                         ]
        return kube_rootca_update


class KubeRootCAUpdateController(rest.RestController):
    """REST controller for kubernetes rootCA updates."""

    def __init__(self):
        self.fm_api = fm_api.FaultAPIs()

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeRootCAUpdate, body=six.text_type)
    def post(self, body):
        """Create a new Kubernetes RootCA Update and start update."""

        force = body.get('force', False) is True
        alarm_ignore_list = body.get('alarm_ignore_list')

        try:
            pecan.request.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError((
                "A kubernetes rootca update is already in progress"))

        # There must not be a platform upgrade in progress
        try:
            pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError((
                "A kubernetes rootca update cannot be done while a platform upgrade is in progress"))

        # There must not be a kubernetes upgrade in progress
        try:
            pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError((
                "A kubernetes rootca update cannot be done while a kube upgrade "
                "is in progress"))

        # The system must be healthy
        healthy, output = pecan.request.rpcapi.get_system_health(
            pecan.request.context,
            force=force,
            kube_rootca_update=True,
            alarm_ignore_list=alarm_ignore_list)
        if not healthy:
            LOG.info("Health query failure during kubernetes rootca update start: %s"
                     % output)
            if os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
                LOG.info("Running in lab, ignoring health errors.")
            else:
                raise wsme.exc.ClientSideError((
                    "System is not in a valid state for kubernetes rootca update. "
                    "Run system health-query for more details."))

        create_obj = {'state': kubernetes.KUBE_ROOTCA_UPDATE_STARTED}
        new_update = pecan.request.dbapi.kube_rootca_update_create(create_obj)

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="Kubernetes rootca update in progress",
                # environmental
                alarm_type=fm_constants.FM_ALARM_TYPE_5,
                # unspecified-reason
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                proposed_repair_action="Wait for kubernetes rootca procedure to complete",
                service_affecting=False)
        self.fm_api.set_fault(fault)
        LOG.info("Started kubernetes rootca update")

        return KubeRootCAUpdate.convert_with_links(new_update)

    @wsme_pecan.wsexpose(KubeRootCAUpdate, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given kubernetes rootca update."""

        rpc_kube_rootca_update = objects.kube_rootca_update.get_by_uuid(
            pecan.request.context, uuid)
        return KubeRootCAUpdate.convert_with_links(rpc_kube_rootca_update)
