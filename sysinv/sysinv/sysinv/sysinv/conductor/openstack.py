#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" System Inventory Openstack Utilities and helper functions."""

import keyring
from cinderclient.v2 import client as cinder_client_v2
from oslo_config import cfg
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.openstack.common import log as logging
from keystoneclient.v3 import client as keystone_client
from keystoneclient.auth.identity import v3
from keystoneclient import session
from barbicanclient.v1 import client as barbican_client_v1

LOG = logging.getLogger(__name__)

keystone_opts = [
    cfg.StrOpt('auth_host',
               default='controller',
               help=_("Authentication host server")),
    cfg.IntOpt('auth_port',
               default=5000,
               help=_("Authentication host port number")),
    cfg.StrOpt('auth_protocol',
               default='http',
               help=_("Authentication protocol")),
    cfg.StrOpt('admin_user',
               default='admin',
               help=_("Admin user")),
    cfg.StrOpt('admin_password',
               default='admin',   # this is usually some value
               help=_("Admin password"),
               secret=True),
    cfg.StrOpt('admin_tenant_name',
               default='services',
               help=_("Admin tenant name")),
    cfg.StrOpt('auth_uri',
               default='http://192.168.204.2:5000/',
               help=_("Authentication URI")),
    cfg.StrOpt('auth_url',
               default='http://127.0.0.1:5000/',
               help=_("Admin Authentication URI")),
    cfg.StrOpt('region_name',
               default='RegionOne',
               help=_("Region Name")),
    cfg.StrOpt('username',
               default='sysinv',
               help=_("Sysinv keystone user name")),
    cfg.StrOpt('password',
               default='sysinv',
               help=_("Sysinv keystone user password")),
    cfg.StrOpt('project_name',
               default='services',
               help=_("Sysinv keystone user project name")),
    cfg.StrOpt('user_domain_name',
               default='Default',
               help=_("Sysinv keystone user domain name")),
    cfg.StrOpt('project_domain_name',
               default='Default',
               help=_("Sysinv keystone user project domain name"))
]


openstack_keystone_opts = [
    cfg.StrOpt('keyring_service',
               default='CGCS',
               help=_("Keyring service")),
    cfg.StrOpt('auth_uri',
               default='http://192.168.204.2:5000/',
               help=_("Authentication URI")),
    cfg.StrOpt('auth_url',
               default='http://127.0.0.1:5000/',
               help=_("Admin Authentication URI")),
    cfg.StrOpt('region_name',
               default='RegionOne',
               help=_("Region Name")),
    cfg.StrOpt('username',
               default='admin',
               help=_("keystone user name")),
    cfg.StrOpt('neutron_region_name',
               default='RegionOne',
               help=_("Neutron Region Name")),
    cfg.StrOpt('cinder_region_name',
               default='RegionOne',
               help=_("Cinder Region Name")),
    cfg.StrOpt('nova_region_name',
               default='RegionOne',
               help=_("Nova Region Name")),
    cfg.StrOpt('barbican_region_name',
               default='RegionOne',
               help=_("Barbican Region Name")),
    cfg.StrOpt('project_name',
               default='admin',
               help=_("keystone user project name")),
    cfg.StrOpt('user_domain_name',
               default='Default',
               help=_("keystone user domain name")),
    cfg.StrOpt('project_domain_name',
               default='Default',
               help=_("keystone user project domain name"))
]

# Register the configuration options
PLATFORM_CONFIG = 'KEYSTONE_AUTHTOKEN'
OPENSTACK_CONFIG = 'OPENSTACK_KEYSTONE_AUTHTOKEN'

cfg.CONF.register_opts(keystone_opts, PLATFORM_CONFIG)
cfg.CONF.register_opts(openstack_keystone_opts, OPENSTACK_CONFIG)


class OpenStackOperator(object):
    """Class to encapsulate OpenStack operations for System Inventory"""

    def __init__(self, dbapi):
        self.dbapi = dbapi
        self.barbican_client = None
        self.openstack_barbican_client = None
        self.cinder_client = None
        self.keystone_client = None
        self.keystone_session = None
        self.openstack_keystone_client = None
        self.openstack_keystone_session = None
        self._auth_url = cfg.CONF[PLATFORM_CONFIG].auth_url + "/v3"
        self._openstack_auth_url = cfg.CONF[OPENSTACK_CONFIG].auth_url + "/v3"

    def _get_auth_url(self, service_config):
        if service_config == PLATFORM_CONFIG:
            return self._auth_url
        elif service_config == OPENSTACK_CONFIG:
            return self._openstack_auth_url
        else:
            LOG.error("Unrecognized keystone service configuration. "
                      "service_config=%s" % (service_config))
            raise exception.InvalidParameterValue(
                _("Unrecognized keystone service_config."))

    #################
    # Keystone
    #################
    def _get_keystone_password(self, service_config):
        if service_config == OPENSTACK_CONFIG:
            password = keyring.get_password(cfg.CONF[OPENSTACK_CONFIG].
                                            keyring_service,
                                            cfg.CONF[OPENSTACK_CONFIG].
                                            username)
        else:
            password = cfg.CONF[service_config].password
        return password

    def _get_new_keystone_session(self, service_config):
        auth = v3.Password(auth_url=self._get_auth_url(service_config),
                           username=cfg.CONF[service_config].username,
                           password=self._get_keystone_password(service_config),
                           user_domain_name=cfg.CONF[service_config].
                           user_domain_name,
                           project_name=cfg.CONF[service_config].
                           project_name,
                           project_domain_name=cfg.CONF[service_config].
                           project_domain_name)
        sess = session.Session(auth=auth)
        return sess

    def _get_cached_keystone_session(self, service_config):
        if service_config == OPENSTACK_CONFIG:
            return self.openstack_keystone_session
        else:
            return self.keystone_session

    def _set_cached_keystone_session(self, service_config, sess):
        if service_config == OPENSTACK_CONFIG:
            self.openstack_keystone_session = sess
        else:
            self.keystone_session = sess

    def _get_keystone_session(self, service_config):
        sess = self._get_cached_keystone_session(service_config)
        if not sess:
            sess = self._get_new_keystone_session(service_config)
            self._set_cached_keystone_session(service_config, sess)
        return sess

    def _get_new_keystone_client(self, service_config):
        client = keystone_client.Client(
            username=cfg.CONF[service_config].username,
            user_domain_name=cfg.CONF[service_config].user_domain_name,
            project_name=cfg.CONF[service_config].project_name,
            project_domain_name=cfg.CONF[service_config]
            .project_domain_name,
            password=self._get_keystone_password(service_config),
            auth_url=self._get_auth_url(service_config),
            region_name=cfg.CONF[service_config].region_name)
        return client

    def _get_cached_keystone_client(self, service_config):
        if service_config == OPENSTACK_CONFIG:
            return self.openstack_keystone_client
        else:
            return self.keystone_client

    def _set_cached_keystone_client(self, service_config, client):
        if service_config == OPENSTACK_CONFIG:
            self.openstack_keystone_client = client
        else:
            self.keystone_client = client

    def _get_keystone_client(self, service_config):
        client = self._get_cached_keystone_client(service_config)
        if not client:
            client = self._get_new_keystone_client(service_config)
            self._set_cached_keystone_client(service_config, client)
        return client

    #################
    # Cinder
    #################
    def _get_cinder_endpoints(self):
        endpoint_list = []
        try:
            # get region one name from platform.conf
            region1_name = get_region_name('region_1_name')
            if region1_name is None:
                region1_name = 'RegionOne'
            service_list = self._get_keystone_client(OPENSTACK_CONFIG).services.list()
            for s in service_list:
                if s.name.find(constants.SERVICE_TYPE_CINDER) != -1:
                    endpoint_list += self._get_keystone_client(OPENSTACK_CONFIG).endpoints.list(
                                     service=s, region=region1_name)
        except Exception:
            LOG.error("Failed to get keystone endpoints for cinder.")
        return endpoint_list

    def _get_cinderclient(self):
        if not self.cinder_client:
            self.cinder_client = cinder_client_v2.Client(
                session=self._get_keystone_session(OPENSTACK_CONFIG),
                auth_url=self._get_auth_url(OPENSTACK_CONFIG),
                endpoint_type='internalURL',
                region_name=cfg.CONF[OPENSTACK_CONFIG].cinder_region_name)

        return self.cinder_client

    def get_cinder_pools(self):
        pools = {}

        # Check to see if cinder is present
        # TODO(rchurch): Need to refactor with storage backend
        if ((StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_CEPH)) or
                (StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_LVM))):
            try:
                pools = self._get_cinderclient().pools.list(detailed=True)
            except Exception as e:
                LOG.error("get_cinder_pools: Failed to access Cinder client: %s" % e)

        return pools

    def get_cinder_volumes(self):
        volumes = []

        # Check to see if cinder is present
        # TODO(rchurch): Need to refactor with storage backend
        if ((StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_CEPH)) or
                (StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_LVM))):
            search_opts = {
                'all_tenants': 1
            }
            try:
                volumes = self._get_cinderclient().volumes.list(
                    search_opts=search_opts)
            except Exception as e:
                LOG.error("get_cinder_volumes: Failed to access Cinder client: %s" % e)

        return volumes

    def get_cinder_services(self):
        service_list = []

        # Check to see if cinder is present
        # TODO(rchurch): Need to refactor with storage backend
        if ((StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_CEPH)) or
                (StorageBackendConfig.has_backend_configured(self.dbapi, constants.CINDER_BACKEND_LVM))):
            try:
                service_list = self._get_cinderclient().services.list()
            except Exception as e:
                LOG.error("get_cinder_services:Failed to access Cinder client: %s" % e)

        return service_list

    def get_cinder_volume_types(self):
        """Obtain the current list of volume types."""
        volume_types_list = []

        if StorageBackendConfig.is_service_enabled(self.dbapi,
                                                   constants.SB_SVC_CINDER,
                                                   filter_shared=True):
            try:
                volume_types_list = self._get_cinderclient().volume_types.list()
            except Exception as e:
                LOG.error("get_cinder_volume_types: Failed to access Cinder client: %s" % e)

        return volume_types_list

    def cinder_prepare_db_for_volume_restore(self, context):
        """
        Make sure that Cinder's database is in the state required to restore all
        volumes.

        Instruct cinder to delete all of its volume snapshots and set all of its
        volume to the 'error' state.
        """
        LOG.debug("Prepare Cinder DB for volume Restore")
        try:
            # mark all volumes as 'error' state
            LOG.debug("Resetting all volumes to error state")
            all_tenant_volumes = self._get_cinderclient().volumes.list(
                search_opts={'all_tenants': 1})

            for vol in all_tenant_volumes:
                vol.reset_state('error')

            # delete all volume snapshots
            LOG.debug("Deleting all volume snapshots")
            all_tenant_snapshots = self._get_cinderclient().volume_snapshots.list(
                search_opts={'all_tenants': 1})

            for snap in all_tenant_snapshots:
                snap.delete()
        except Exception as e:
            LOG.exception("Cinder DB updates failed" % e)
            # Cinder cleanup is not critical, PV was already removed
            raise exception.SysinvException(
                _("Automated Cinder DB updates failed. Please manually set "
                  "all volumes to 'error' state and delete all volume "
                  "snapshots before restoring volumes."))
        LOG.debug("Cinder DB ready for volume Restore")

    #########################
    # Primary Region Sysinv
    # Region specific methods
    #########################
    def _get_primary_cgtsclient(self):
        # import the module in the function that uses it
        # as the cgtsclient is only installed on the controllers
        from cgtsclient.v1 import client as cgts_client
        # get region one name from platform.conf
        region1_name = get_region_name('region_1_name')
        if region1_name is None:
            region1_name = 'RegionOne'
        auth_ref = self._get_keystone_client(PLATFORM_CONFIG).auth_ref
        if auth_ref is None:
            raise exception.SysinvException(_("Unable to get auth ref "
                                            "from keystone client"))
        auth_token = auth_ref.service_catalog.get_token()
        endpoint = (auth_ref.service_catalog.
                    get_endpoints(service_type='platform',
                                  endpoint_type='internal',
                                  region_name=region1_name))
        endpoint = endpoint['platform'][0]
        version = 1
        return cgts_client.Client(version=version,
                                  endpoint=endpoint['url'],
                                  auth_url=self._get_auth_url(PLATFORM_CONFIG),
                                  token=auth_token['id'])

    def get_ceph_mon_info(self):
        ceph_mon_info = dict()
        try:
            cgtsclient = self._get_primary_cgtsclient()
            clusters = cgtsclient.cluster.list()
            if clusters:
                ceph_mon_info['cluster_id'] = clusters[0].cluster_uuid
            else:
                LOG.error("Unable to get the cluster from the primary region")
                return None
            ceph_mon_ips = cgtsclient.ceph_mon.ip_addresses()
            if ceph_mon_ips:
                ceph_mon_info['ceph-mon-0-ip'] = ceph_mon_ips.get(
                    'ceph-mon-0-ip', '')
                ceph_mon_info['ceph-mon-1-ip'] = ceph_mon_ips.get(
                    'ceph-mon-1-ip', '')
                ceph_mon_info['ceph-mon-2-ip'] = ceph_mon_ips.get(
                    'ceph-mon-2-ip', '')
            else:
                LOG.error("Unable to get the ceph mon IPs from the primary "
                          "region")
                return None
        except Exception as e:
            LOG.error("Unable to get ceph info from the primary region: %s" % e)
            return None
        return ceph_mon_info

    def region_has_ceph_backend(self):
        ceph_present = False
        try:
            backend_list = self._get_primary_cgtsclient().storage_backend.list()
            for backend in backend_list:
                if backend.backend == constants.CINDER_BACKEND_CEPH:
                    ceph_present = True
                    break
        except Exception as e:
            LOG.error("Unable to get storage backend list from the primary "
                      "region: %s" % e)
        return ceph_present

    #################
    # Barbican
    #################
    def _get_cached_barbican_client(self, service_config):
        if service_config == PLATFORM_CONFIG:
            return self.barbican_client
        else:
            return self.openstack_barbican_client

    def _set_cached_barbican_client(self, service_config, client):
        if service_config == PLATFORM_CONFIG:
            self.barbican_client = client
        else:
            self.openstack_barbican_client = client

    def _get_barbicanclient(self, service_config=PLATFORM_CONFIG):
        client = self._get_cached_barbican_client(service_config)
        if not client:
            client = barbican_client_v1.Client(
                session=self._get_keystone_session(service_config),
                interface='internalURL',
                region_name=cfg.CONF[OPENSTACK_CONFIG].barbican_region_name)
            self._set_cached_barbican_client(service_config, client)
        return client

    def get_barbican_secret_payload(self, secret_ref):
        try:
            client = self._get_barbicanclient(
                service_config=OPENSTACK_CONFIG)
            secret = client.secrets.get(secret_ref)
            payload = secret.payload
            return payload
        except Exception:
            LOG.error("Unable to find Barbican secret %s or secret does not "
                      "have payload", secret_ref)
            return None

    def get_barbican_secret_by_name(self, context, name):
        try:
            client = self._get_barbicanclient()
            secret_list = client.secrets.list(name=name)
            secret = next(iter(secret_list), None)
            return secret
        except Exception:
            LOG.error("Unable to find Barbican secret %s", name)
            return None

    def create_barbican_secret(self, context, name, payload):
        if not payload:
            LOG.error("Empty password is passed to Barbican %s" % name)
            return None
        try:
            client = self._get_barbicanclient()
            secret = self.get_barbican_secret_by_name(context, name)
            if secret:
                client.secrets.delete(secret.secret_ref)
            secret = client.secrets.create(name, payload)
            secret.store()
            return secret.secret_ref
        except Exception:
            LOG.error("Unable to create Barbican secret %s" % name)
            return None

    def delete_barbican_secret(self, context, name):
        try:
            client = self._get_barbicanclient()
            secret = self.get_barbican_secret_by_name(context=context, name=name)
            if not secret:
                LOG.error("Unable to delete unknown Barbican secret %s" % name)
                return False
            client.secrets.delete(secret_ref=secret.secret_ref)
            return True
        except Exception:
            LOG.error("Unable to delete Barbican secret %s" % name)
            return False


def get_region_name(region):
    # get region name from platform.conf
    lines = [line.rstrip('\n') for line in
             open('/etc/platform/platform.conf')]
    for line in lines:
        values = line.split('=')
        if values[0] == region:
            return values[1]
    LOG.error("Unable to get %s from the platform.conf." % region)
    return None
