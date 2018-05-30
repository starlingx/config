#
# Copyright (c) 2014-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Cluster XML
"""

CLUSTER_DATA = """
    <cluster-mappings>
        <services>
            <service id="Cloud Services">
                <migration timeout="120"/>
                <activity>
                    <follows id="management_ip"/>
                </activity>
                <resources>
                    <resource id="keystone"/>
                    <resource id="glance-reg"/>
                    <resource id="glance-api"/>
                    <resource id="neutron-svr"/>
                    <resource id="nova-api"/>
                    <resource id="nova-sched"/>
                    <resource id="nova-conductor"/>
                    <resource id="nova-conauth"/>
                    <resource id="nova-novnc"/>
                    <resource id="cinder-api"/>
                    <resource id="cinder-schedule"/>
                    <resource id="cinder-volume"/>
                    <resource id="ceilometer-agent-central"/>
                    <resource id="ceilometer-collector"/>
                    <resource id="ceilometer-api"/>
                    <resource id="ceilometer-alarm-evaluator"/>
                    <resource id="ceilometer-alarm-notifier"/>
                </resources>
            </service>
            <service id="Platform Services">
                <migration timeout="120"/>
                <activity>
                    <follows id="management_ip"/>
                </activity>
                <resources>
                    <resource id="sysinv-inv"/>
                    <resource id="sysinv-conductor"/>
                    <resource id="mtcAgent"/>
                    <resource id="hbsAgent"/>
                    <resource id="dnsmasq"/>
                    <resource id="platform_fs"/>
                    <resource id="p_export_platform_fs"/>
                </resources>
            </service>
            <service id="Messaging Services">
                <migration timeout="120"/>
                <activity>
                    <follows id="management_ip"/>
                </activity>
                <resources>
                    <resource id="rabbit_fs"/>
                    <resource id="rabbit_ocf"/>
                </resources>
            </service>
            <service id="Database Services">
                <migration timeout="120"/>
                <activity>
                    <follows id="management_ip"/>
                </activity>
                <resources>
                    <resource id="pg_fs"/>
                    <resource id="pg_ocf"/>
                </resources>
            </service>
        </services>
    </cluster-mappings>
"""
