# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory Armada manifest operator."""

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import manifest_base as base
from sysinv.helm.aodh import AodhHelm
from sysinv.helm.barbican import BarbicanHelm
from sysinv.helm.ceilometer import CeilometerHelm
from sysinv.helm.cinder import CinderHelm
from sysinv.helm.dcdbsync import DcdbsyncHelm
from sysinv.helm.fm_rest_api import FmRestApiHelm
from sysinv.helm.garbd import GarbdHelm
from sysinv.helm.glance import GlanceHelm
from sysinv.helm.gnocchi import GnocchiHelm
from sysinv.helm.heat import HeatHelm
from sysinv.helm.horizon import HorizonHelm
from sysinv.helm.ingress import IngressHelm
from sysinv.helm.ironic import IronicHelm
from sysinv.helm.keystone import KeystoneHelm
from sysinv.helm.keystone_api_proxy import KeystoneApiProxyHelm
from sysinv.helm.libvirt import LibvirtHelm
from sysinv.helm.magnum import MagnumHelm
from sysinv.helm.mariadb import MariadbHelm
from sysinv.helm.memcached import MemcachedHelm
from sysinv.helm.neutron import NeutronHelm
from sysinv.helm.nginx_ports_control import NginxPortsControlHelm
from sysinv.helm.nova import NovaHelm
from sysinv.helm.nova_api_proxy import NovaApiProxyHelm
from sysinv.helm.openvswitch import OpenvswitchHelm
from sysinv.helm.panko import PankoHelm
from sysinv.helm.placement import PlacementHelm
from sysinv.helm.rabbitmq import RabbitmqHelm
from sysinv.helm.swift import SwiftHelm

LOG = logging.getLogger(__name__)


class OpenstackArmadaManifestOperator(base.ArmadaManifestOperator):

    APP = constants.HELM_APP_OPENSTACK
    ARMADA_MANIFEST = 'armada-manifest'

    CHART_INGRESS_KS = CHART_GROUP_INGRESS_KS = 'kube-system-ingress'

    CHART_GROUP_INGRESS_OS = 'openstack-ingress'
    CHART_GROUP_MAGNUM = 'openstack-magnum'
    CHART_GROUP_MARIADB = 'openstack-mariadb'
    CHART_GROUP_MEMCACHED = 'openstack-memcached'
    CHART_GROUP_RABBITMQ = 'openstack-rabbitmq'
    CHART_GROUP_KEYSTONE = 'openstack-keystone'
    CHART_GROUP_KS_API_PROXY = 'openstack-keystone-api-proxy'
    CHART_GROUP_BARBICAN = 'openstack-barbican'
    CHART_GROUP_GLANCE = 'openstack-glance'
    CHART_GROUP_SWIFT = 'openstack-ceph-rgw'
    CHART_GROUP_CINDER = 'openstack-cinder'
    CHART_GROUP_FM_REST_API = 'openstack-fm-rest-api'
    CHART_GROUP_COMPUTE_KIT = 'openstack-compute-kit'
    CHART_GROUP_HEAT = 'openstack-heat'
    CHART_GROUP_HORIZON = 'openstack-horizon'
    CHART_GROUP_TELEMETRY = 'openstack-telemetry'
    CHART_GROUP_DCDBSYNC = 'openstack-dcdbsync'

    CHART_GROUPS_LUT = {
        AodhHelm.CHART: CHART_GROUP_TELEMETRY,
        BarbicanHelm.CHART: CHART_GROUP_BARBICAN,
        CeilometerHelm.CHART: CHART_GROUP_TELEMETRY,
        CinderHelm.CHART: CHART_GROUP_CINDER,
        FmRestApiHelm.CHART: CHART_GROUP_FM_REST_API,
        GarbdHelm.CHART: CHART_GROUP_MARIADB,
        GlanceHelm.CHART: CHART_GROUP_GLANCE,
        GnocchiHelm.CHART: CHART_GROUP_TELEMETRY,
        HeatHelm.CHART: CHART_GROUP_HEAT,
        HorizonHelm.CHART: CHART_GROUP_HORIZON,
        IngressHelm.CHART: CHART_GROUP_INGRESS_OS,
        IronicHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        KeystoneHelm.CHART: CHART_GROUP_KEYSTONE,
        KeystoneApiProxyHelm.CHART: CHART_GROUP_KS_API_PROXY,
        LibvirtHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        MagnumHelm.CHART: CHART_GROUP_MAGNUM,
        MariadbHelm.CHART: CHART_GROUP_MARIADB,
        MemcachedHelm.CHART: CHART_GROUP_MEMCACHED,
        NeutronHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        NginxPortsControlHelm.CHART: CHART_GROUP_INGRESS_OS,
        NovaHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        NovaApiProxyHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        OpenvswitchHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        PankoHelm.CHART: CHART_GROUP_TELEMETRY,
        PlacementHelm.CHART: CHART_GROUP_COMPUTE_KIT,
        RabbitmqHelm.CHART: CHART_GROUP_RABBITMQ,
        SwiftHelm.CHART: CHART_GROUP_SWIFT,
        DcdbsyncHelm.CHART: CHART_GROUP_DCDBSYNC,
    }

    CHARTS_LUT = {
        AodhHelm.CHART: 'openstack-aodh',
        BarbicanHelm.CHART: 'openstack-barbican',
        CeilometerHelm.CHART: 'openstack-ceilometer',
        CinderHelm.CHART: 'openstack-cinder',
        GarbdHelm.CHART: 'openstack-garbd',
        FmRestApiHelm.CHART: 'openstack-fm-rest-api',
        GlanceHelm.CHART: 'openstack-glance',
        GnocchiHelm.CHART: 'openstack-gnocchi',
        HeatHelm.CHART: 'openstack-heat',
        HorizonHelm.CHART: 'openstack-horizon',
        IngressHelm.CHART: 'openstack-ingress',
        IronicHelm.CHART: 'openstack-ironic',
        KeystoneHelm.CHART: 'openstack-keystone',
        KeystoneApiProxyHelm.CHART: 'openstack-keystone-api-proxy',
        LibvirtHelm.CHART: 'openstack-libvirt',
        MagnumHelm.CHART: 'openstack-magnum',
        MariadbHelm.CHART: 'openstack-mariadb',
        MemcachedHelm.CHART: 'openstack-memcached',
        NeutronHelm.CHART: 'openstack-neutron',
        NginxPortsControlHelm.CHART: 'openstack-nginx-ports-control',
        NovaHelm.CHART: 'openstack-nova',
        NovaApiProxyHelm.CHART: 'openstack-nova-api-proxy',
        OpenvswitchHelm.CHART: 'openstack-openvswitch',
        PankoHelm.CHART: 'openstack-panko',
        PlacementHelm.CHART: 'openstack-placement',
        RabbitmqHelm.CHART: 'openstack-rabbitmq',
        SwiftHelm.CHART: 'openstack-ceph-rgw',
        DcdbsyncHelm.CHART: 'openstack-dcdbsync',
    }

    def platform_mode_manifest_updates(self, dbapi, mode):
        """ Update the application manifest based on the platform

        This is used for

        :param dbapi: DB api object
        :param mode: mode to control how to apply the application manifest
        """

        if mode == constants.OPENSTACK_RESTORE_DB:
            # During application restore, first bring up
            # MariaDB service.
            self.manifest_chart_groups_set(
                self.ARMADA_MANIFEST,
                [self.CHART_GROUP_INGRESS_KS,
                 self.CHART_GROUP_INGRESS_OS,
                 self.CHART_GROUP_MARIADB])

        elif mode == constants.OPENSTACK_RESTORE_STORAGE:
            # After MariaDB data is restored, restore Keystone,
            # Glance and Cinder.
            self.manifest_chart_groups_set(
                self.ARMADA_MANIFEST,
                [self.CHART_GROUP_INGRESS_KS,
                 self.CHART_GROUP_INGRESS_OS,
                 self.CHART_GROUP_MARIADB,
                 self.CHART_GROUP_MEMCACHED,
                 self.CHART_GROUP_RABBITMQ,
                 self.CHART_GROUP_KEYSTONE,
                 self.CHART_GROUP_GLANCE,
                 self.CHART_GROUP_CINDER])

        else:
            # When mode is OPENSTACK_RESTORE_NORMAL or None,
            # bring up all the openstack services.
            try:
                system = dbapi.isystem_get_one()
            except exception.NotFound:
                LOG.exception("System %s not found.")
                raise

            if (system.distributed_cloud_role ==
                    constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
                # remove the chart_groups not needed in this configuration
                self.manifest_chart_groups_delete(
                    self.ARMADA_MANIFEST, self.CHART_GROUP_SWIFT)
                self.manifest_chart_groups_delete(
                    self.ARMADA_MANIFEST, self.CHART_GROUP_COMPUTE_KIT)
                self.manifest_chart_groups_delete(
                    self.ARMADA_MANIFEST, self.CHART_GROUP_HEAT)
                self.manifest_chart_groups_delete(
                    self.ARMADA_MANIFEST, self.CHART_GROUP_TELEMETRY)
