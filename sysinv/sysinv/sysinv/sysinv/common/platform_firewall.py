#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# the ports below are configured via service-parameter, they cannot be statically set
# 8080: "horizon https",
# 8443: "horizon https",

# list of ports to be open in the system controller side
SYSTEMCONTROLLER = \
    {"tcp":
        {
            22: "ssh",
            389: "openLDAP",
            636: "openLDAP",
            4546: "stx-nfv",
            5001: "keystone-api",
            5492: "patching-api",
            6386: "sysinv-api",
            6443: "K8s API server",
            8220: "dcdbsync-api",
            9001: "Docker registry",
            9002: "Registry token server",
            9312: "barbican-api",
            18003: "stx-fault",
            31001: "Elastic Dashboard and API",
            31090: "Kafka Brokers (NodePort)",
            31091: "Kafka Brokers (NodePort)",
            31092: "Kafka Brokers (NodePort)",
            31093: "Kafka Brokers (NodePort)",
            31094: "Kafka Brokers (NodePort)",
            31095: "Kafka Brokers (NodePort)",
            31096: "Kafka Brokers (NodePort)",
            31097: "Kafka Brokers (NodePort)",
            31098: "Kafka Brokers (NodePort)",
            31099: "Kafka Brokers (NodePort)"
        },
     "udp":
        {
            162: "snmp trap"
        }}

# list of ports to be open in the subcloud side
SUBCLOUD = \
    {"tcp":
        {
            22: "ssh",
            4546: "stx-nfv",
            5001: "keystone-api",
            5492: "patching-api",
            6386: "sysinv-api",
            8220: "dcdbsync-api",
            9001: "Docker registry",
            9002: "Registry token server",
            9312: "barbican-api",
            18003: "stx-fault",
            31001: "Elastic Dashboard and API"
        },
     "udp":
        {
            162: "snmp trap"
        }}
