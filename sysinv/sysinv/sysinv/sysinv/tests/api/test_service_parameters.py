#
# Copyright (c) 2019-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / service_parameter / methods.
"""

from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class ApiServiceParameterTestCaseMixin(object):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test',
                   'Content-Type': 'application/json',
                   'Accept': 'application/json'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/service_parameter'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'parameters'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'service',
                           'section',
                           'name',
                           'value',
                           'resource',
                           'personality'
                           ]

    required_post_fields = [
        'service',
        'section',
        'parameters'
        'resource',
        'personality'
    ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = []

    service_parameter_data = [
        {
            'service': constants.SERVICE_TYPE_HTTP,
            'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            'name': constants.SERVICE_PARAM_HTTP_PORT_HTTP,
            'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        },
        {
            'service': constants.SERVICE_TYPE_HTTP,
            'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            'name': constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
            'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT)
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES,
            'name': constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST,
            'value': 'localurl'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL,
            'value': 'https://10.10.10.3:30556/dex'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '2G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '0.02T'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '4MB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '4.0MB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '4'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '4g'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '-4'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '4,0G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '1M'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_AUTOVACUUM_WORKERS,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_AUTOVACUUM_WORKERS,
            'value': '2'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_WORKER_PROCESSES,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_WORKER_PROCESSES,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_MAINTENANCE_WORKERS,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_MAINTENANCE_WORKERS,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS_PER_GATHER,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL,
            'name': constants.SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS_PER_GATHER,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_FILES,
            'value': '-1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_FILES,
            'value': '2a'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_FILES,
            'value': 'one'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '1GB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '1,G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '500m'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '20GB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '10gb'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '10,5GB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '20GB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '10gb'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '10,5GB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '3.2Gi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_FILES,
            'value': '5'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '6,2G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '486.5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '2Gi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '850M'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '850,5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': '850.5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '4Gi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '900M'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '900,5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': '900.5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '3G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '2Gi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '400M'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': '400,5Mi'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MIN_AVAILABLE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_FILES,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_USED,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_CRASHDUMP,
            'name': constants.SERVICE_PARAM_CRASHDUMP_MAX_SIZE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name0',
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name1',
            'value': 'value1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name2',
            'value': 'value1,1.1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name3',
            'value': 'value1,1.1.1.1.1,1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name4',
            'value': '_value,1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name5',
            'value': '_value,1.1.1.1,1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name6',
            'value': 'value1,1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name7',
            'value': 'value1,1.1.1.1,1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name8',
            'value': 'value1,1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name9',
            'value': 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkk.com,\
                1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name10',
            'value': (
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.comm'
            )
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name11',
            'value': 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com,\
                1.1.1.1'
        },
        {
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD,
            'name': 'name12',
            'value': (
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                    'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com'
                    ',1.1.1.1'
            )
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_OVERFLOW_SIZE,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_OVERFLOW_SIZE,
            'value': '10'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_POOL_SIZE,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_POOL_SIZE,
            'value': '10'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_POOL_TIMEOUT,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_FM,
            'name': constants.SERVICE_PARAM_NAME_FM_DATABASE_MAX_POOL_TIMEOUT,
            'value': '10'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_OVERFLOW_SIZE,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_OVERFLOW_SIZE,
            'value': '10'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_POOL_SIZE,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_POOL_SIZE,
            'value': '10'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_POOL_TIMEOUT,
            'value': '1'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_SYSINV_DATABASE_MAX_POOL_TIMEOUT,
            'value': '10'
        },
        {
            # invalid empty
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_empty',
            'value': ''
        },
        {
            # invalid starting with dash
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_starting_with_dash',
            'value': '-value'
        },
        {
            # invalid finishing with dash
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_finishing_with_dash',
            'value': 'value-'
        },
        {
            # invalid underscore
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_undescore',
            'value': 'val_ue'
        },
        {
            # invalid finishing with dash 2 labels
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_finishing_with_dash_2_labels',
            'value': 'value_.avf'
        },
        {
            # invalid char comma
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_char_comma',
            'value': 'value,1'
        },
        {
            # invalid char %
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_char_%',
            'value': 'value%.abc'
        },
        {
            # invalid double dots
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_double_dots',
            'value': 'value..1'
        },
        {
            # invalid numeric
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_double dots',
            'value': '123'
        },
        {
            # invalid numeric dot numeric
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid double_numbers',
            'value': '123.123'
        },
        {
            # invalid IPv4
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_ipv4',
            'value': '1.1.1.1'
        },
        {
            # invalid IPv6
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_ipv6',
            'value': 'ffa::'
        },
        {
            # invalid bigger than 253
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_dommain_bigger_than_253',
            'value': 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh.abc'

        },
        {
            # invalid label bigger than 63
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'invalid_label_bigger_than_63',
            'value': 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijki.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde'
        },
        {
            # valid 253 domain with 63 and dash ) dots
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_253_domain_with_labels',
            'value': 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
                     'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi'
        },
        {
            # valid simple domain
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_simple_domain',
            'value': 'local'
        },
        {
            # valid simple domain with dot
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_simple_domain_with_dot',
            'value': 'registry.central'
        },
        {
            # valid with dash
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_using_dash',
            'value': 'regi-stry.central'
        },
        {
            # valid IDN punycode (münich.local)
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_idn_punicode',
            'value': 'xn--mnich-kva.local'
        },
        {
            # valid IDN punycode (пример.рф)
            'service': constants.SERVICE_TYPE_DNS,
            'section': constants.SERVICE_PARAM_SECTION_DNS_LOCAL,
            'name': 'valid_idn_punicode2',
            'value': 'xn--e1afmkfd.xn--p1ai'
        },

    ]
    service_parameter_wildcard = {
        'service': constants.SERVICE_TYPE_PTP,
        'section': constants.SERVICE_PARAM_SECTION_PTP_GLOBAL,
        'name': 'network_transport',
        'value': 'L2'
    }

    def setUp(self):
        super(ApiServiceParameterTestCaseMixin, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    # These methods have generic names and are overridden here
    # Future activity: Redo the subclasses to use mixins
    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def _create_db_object(self, parameter_data=None):
        if not parameter_data:
            parameter_data = self.service_parameter_data[0]
        return dbutils.create_test_service_parameter(**parameter_data)

    def _create_db_objects(self, data_set=None):
        if not data_set:
            data_set = self.service_parameter_data
        data = []
        for parameter_data in data_set:
            data.append(self._create_db_object(parameter_data))

        return data

    def get_one(self, uuid, expect_errors=False, error_message=None):
        response = self.get_json(self.get_single_url(uuid), headers=self.API_HEADERS)
        self.validate_response(response, expect_errors, error_message, json_response=True)
        return response

    def get_list(self):
        response = self.get_json(self.API_PREFIX, headers=self.API_HEADERS)
        return response[self.RESULT_KEY]

    def patch(self, uuid, data, expect_errors=False, error_message=None):
        response = self.patch_dict(self.get_single_url(uuid),
                                   data=data,
                                   expect_errors=expect_errors,
                                   headers=self.API_HEADERS)
        self.validate_response(response, expect_errors, error_message)
        if expect_errors:
            return response
        else:
            return response.json

    def post(self, data, expect_errors=False, error_message=None):
        formatted_data = self.format_data(data)
        response = self.post_json(self.API_PREFIX,
                                  params=formatted_data,
                                  expect_errors=expect_errors,
                                  headers=self.API_HEADERS)

        self.validate_response(response, expect_errors, error_message)
        if expect_errors:
            return response
        else:
            return response.json[self.RESULT_KEY][0]

    def apply(self, service, expect_errors=False):
        data = {}
        data['service'] = service
        response = self.post_json(self.API_PREFIX + "/apply",
                                  params=data,
                                  expect_errors=expect_errors,
                                  headers=self.API_HEADERS)
        return response

    def validate_response(self, response, expect_errors, error_message, json_response=False):
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        elif not json_response:
            self.assertEqual(http_client.OK, response.status_int)

    def validate_data(self, input_data, response_data):
        self.assert_fields(response_data)
        for key, value in input_data.items():
            if key in self.expected_api_fields:
                self.assertEqual(value, response_data[key])

    def format_data(self, data):
        formatted_data = dict(data)
        formatted_data.update({'parameters': {data['name']: data['value']}})
        for field in self.required_post_fields:
            if field not in formatted_data:
                formatted_data[field] = None

        return formatted_data


class CLIConfirmationTestHelper(object):
    def __init__(self, test_case):
        self.test_case = test_case
        self.invalid_msg = (
            "Parameter '%s' value must be either '%s' or '%s'" %
            (
                constants.SERVICE_PARAM_NAME_PLATFORM_CLI_CONFIRMATIONS,
                constants.SERVICE_PARAM_DISABLED,
                constants.SERVICE_PARAM_ENABLED
            )
        )
        self.cli_confirmations_service_param_test_cases = {
            "valid_enabled": {
                "value": "enabled",
                "expect_error": False
            },
            "invalid_yes": {
                "value": "yes",
                "expect_error": True,
                "error_message": self.invalid_msg
            },
            "invalid_capital_enabled": {
                "value": "ENABLED",
                "expect_error": True,
                "error_message": self.invalid_msg
            },
            "invalid_numeric": {
                "value": "123",
                "expect_error": True,
                "error_message": self.invalid_msg
            }
        }

        self.cli_confirmation_base_object = {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CLIENT,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_CLI_CONFIRMATIONS,
        }

    def _create_cli_confirmation_object(self, value="enabled"):
        obj = dict(self.cli_confirmation_base_object)
        obj["value"] = value
        return self.test_case._create_db_object(obj)

    def validate_post(self):
        sorted_cases = sorted(
             self.cli_confirmations_service_param_test_cases.items(),
             key=lambda item: not item[1]["expect_error"]
        )
        for name, case in sorted_cases:
            post_object = dict(self.cli_confirmation_base_object)
            post_object['value'] = case["value"]

            if case["expect_error"]:
                self.test_case.post(post_object, expect_errors=True,
                     error_message=case["error_message"])
            else:
                self.test_case.post(post_object, expect_errors=False)

    def validate_delete(self):
        del_obj = self._create_cli_confirmation_object("enabled")
        uuid = del_obj.uuid
        response = self.test_case.delete(self.test_case.get_single_url(uuid),
                   headers=self.test_case.API_HEADERS)
        self.test_case.assertEqual(response.status_code, http_client.NO_CONTENT)

    def validate_patch(self):
        self.patch_object = self._create_cli_confirmation_object("enabled")
        for name, case in self.cli_confirmations_service_param_test_cases.items():
            patch_data = {'value': case["value"]}
            if case["expect_error"]:
                self.test_case.patch(self.patch_object.uuid,
                    patch_data,
                    expect_errors=True,
                    error_message=case["error_message"])
            else:
                response = self.test_case.patch(self.patch_object.uuid, patch_data)
                self.patch_object.update(patch_data)
                self.test_case.validate_data(self.patch_object, response)


class ApiServiceParameterPostTestSuiteMixin(ApiServiceParameterTestCaseMixin):

    def setUp(self):
        super(ApiServiceParameterPostTestSuiteMixin, self).setUp()

    def test_create_success(self):
        # Test creation of object
        post_object = self.service_parameter_data[0]
        response = self.post(post_object)
        self.validate_data(post_object, response)

    def test_create_invalid_service(self):
        # Test creation with an invalid service name
        post_object = dict(self.service_parameter_data[0])
        post_object.update({'service': 'not_valid'})
        self.post(post_object, expect_errors=True, error_message="Invalid service name")

    def test_create_wildcard_deprecated(self):
        # Test creation of a section that allows wildcard parameter names
        post_object = self.service_parameter_wildcard
        self.post(post_object,
                  expect_errors=True,
                  error_message="ptp service is deprecated")

    def test_apply_kubernetes_apiserver_oidc_parameters_semantic(self):
        # applying kubernetes service parameters with no OIDC parameters
        # this is a valid configuration
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

        # set SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM. this is an invalid config
        # valid configs are (none)
        # (oidc_issuer_url, oidc_client_id, oidc_username_claim)
        # (the previous 3 plus oidc_groups_claim)
        post_object = self.service_parameter_data[3]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes', expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

        # the other 2 valid configs
        post_object = self.service_parameter_data[4]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        post_object = self.service_parameter_data[5]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

        post_object = self.service_parameter_data[6]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

    def test_coredump_values_and_formats(self):
        # test invalid value format
        for param in range(11, 17):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] + "' has invalid value format.")

        # test empty value
        for param in range(17, 21):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True,
                error_message="The service parameter value is mandatory")

        # test minimum value greater than or equal to 0
        for param in range(21, 24):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must be greater than or equal to 0.")

        # test minimum value greater than or equal to 1G
        for param in range(24, 27):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must be greater than or equal to 1G.")

        # test valid values
        for param in range(7, 11):
            post_object = self.service_parameter_data[param]
            response = self.post(post_object)
            self.validate_data(post_object, response)

    def test_crashdump_formats(self):
        # Test invalid max_files format
        post_object = self.service_parameter_data[37]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[37]['name'] +
            "' must be positive integer.")

        for param in range(38, 40):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must be an integer value.")

        # Test invalid max_size, max_used and min_available format
        for param in range(40, 49):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' value must be written in human readable format, " +
                "e.g., '100M', '2.5Gi', '500K', etc.")

        # test empty value
        for param in range(65, 69):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True,
                error_message="The service parameter value is mandatory")

        # Test valid max_files, max_size, max_used and min_available format
        for param in range(49, 53):
            post_object = self.service_parameter_data[param]
            response = self.post(post_object)
            self.validate_data(post_object, response)

    def test_dns_host_records(self):
        dns_index = 69
        # Test empty value host-record value
        post_object = self.service_parameter_data[dns_index]
        self.post(post_object, expect_errors=True,
            error_message="The service parameter value is mandatory")

        # Test invalid host-record value
        post_object = self.service_parameter_data[dns_index + 1]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_index + 1]['name'] +
            "' must contain valid ip address and host name.")

        # Test invalid IP address in host-record value
        for param in range(dns_index + 2, dns_index + 4):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must contain valid ip address and host name.")

        # Test invalid domain name in host-record value
        for param in range(dns_index + 4, dns_index + 6):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' includes an invalid domain name \'_value\'.")

        # Test valid dns host record
        for param in range(dns_index + 6, dns_index + 8):
            post_object = self.service_parameter_data[param]
            response = self.post(post_object)
            self.validate_data(post_object, response)

        # test duplicate value
        post_object = self.service_parameter_data[dns_index + 8]
        msg = (
            'Service parameter add failed: Value already exists: service=dns '
            'section=host-record name=name8 value=value1,1.1.1.1'
        )
        self.post(post_object, expect_errors=True,
            error_message=msg)

        # Test invalid domain name with more than 63 chars for label
        post_object = self.service_parameter_data[dns_index + 9]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_index + 9]['name'] +
            "' includes an invalid domain name " +
            "\'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkk.com\'.")

        # Test invalid domain name with more than 253 chars total length
        post_object = self.service_parameter_data[dns_index + 10]
        msg = (
            'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.'
            'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
            'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.'
            'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.comm'
        )
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_index + 10]['name'] +
            "' includes an invalid domain name \'" + msg + "\'.")

        # Test valid dns host record with label length 63 & total length 253
        for param in range(dns_index + 11, dns_index + 12):
            post_object = self.service_parameter_data[param]
            response = self.post(post_object)
            self.validate_data(post_object, response)

    def test_dns_local_invalid_domains(self):
        dns_local_index = 94
        # Test empty value
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True,
            error_message="The service parameter value is mandatory")

        # invalid starting with dash
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid finishing with dash
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid undescore
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid finishing with dash 2 labels
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid char comma
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid char %
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid double dots
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid numeric
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid numeric dot numeric
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid IPv4
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid IPv6
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid bigger than 253
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

        # invalid label bigger than 63
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        self.post(post_object, expect_errors=True, error_message="Parameter '" +
            self.service_parameter_data[dns_local_index]['name'] +
            "' includes an invalid domain \'" +
            self.service_parameter_data[dns_local_index]['value'] + "\'.")

    def test_dns_local_valid_domains(self):
        dns_local_index = 108

        # valid 253 domain with 63 and dash
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # valid simple domain
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # valid simple domain with dot
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # valid with dash
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # valid IDN punycode (münich.local)
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # valid IDN punycode (пример.рф)
        dns_local_index += 1
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

    def test_dns_local_invalid_duplicate_domains(self):
        dns_local_index = 109

        # valid simple domain
        post_object = self.service_parameter_data[dns_local_index]
        response = self.post(post_object)
        self.validate_data(post_object, response)

        # add another DNS entry with same name but different value
        post_object = self.service_parameter_data[dns_local_index]
        msg = (
            'Service parameter add failed: Parameter already exists: service=dns '
            'section=local name=valid_simple_domain'
        )
        self.post(post_object, expect_errors=True,
            error_message=msg)

        # add another DNS entry with different name but same value
        post_object = self.service_parameter_data[dns_local_index]
        post_object['name'] = "other_name"
        msg = (
            'Service parameter add failed: Value already exists: service=dns '
            'section=local name=other_name value=local'
        )
        self.post(post_object, expect_errors=True,
            error_message=msg)

    def test_cli_confirmations_post(self):
        self.cli_helper = CLIConfirmationTestHelper(self)
        self.cli_helper.validate_post()


class ApiServiceParameterDeleteTestSuiteMixin(ApiServiceParameterTestCaseMixin):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(ApiServiceParameterDeleteTestSuiteMixin, self).setUp()
        self.delete_object = self._create_db_object()

    # Delete an object and ensure it is removed
    def test_delete(self):
        # Delete the API object
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify the object is no longer returned
        results = self.get_list()
        returned_uuids = (result.uuid for result in results)
        self.assertNotIn(uuid, returned_uuids)

    def test_cli_confirmations_delete(self):
        self.cli_helper = CLIConfirmationTestHelper(self)
        self.cli_helper.validate_delete()


class ApiServiceParameterListTestSuiteMixin(ApiServiceParameterTestCaseMixin):
    """ list operations """

    def test_empty_list(self):
        results = self.get_list()
        self.assertEqual([], results)

    def test_single_entry(self):
        # create a single object
        single_object = self._create_db_object()
        uuid = single_object.uuid
        response = self.get_json(self.get_single_url(uuid))
        self.validate_data(single_object, response)

    def test_many_entries_in_list(self):
        db_obj_list = self._create_db_objects()

        response = self.get_list()
        # Verify that the input data is found in the result
        response_map = {}
        for api_object in response:
            response_map[api_object['uuid']] = api_object
        for db_oject in db_obj_list:
            self.validate_data(db_oject, response_map[db_oject.uuid])


class ApiServiceParameterPatchTestSuiteMixin(ApiServiceParameterTestCaseMixin):

    def setUp(self):
        super(ApiServiceParameterPatchTestSuiteMixin, self).setUp()
        self.patch_object = self._create_db_object()

    def test_patch_valid(self):
        # Update value of patchable field
        new_data = {'value': '8077'}
        response = self.patch(self.patch_object.uuid, new_data)
        # Verify that the attribute was updated
        self.patch_object.update(new_data)
        self.validate_data(self.patch_object, response)

    def test_patch_invalid_value(self):
        # Pass a value that fails a semantic check when patched by the API
        new_data = {'value': 'a_string'}
        self.patch(self.patch_object.uuid, new_data, expect_errors=True,
                   error_message="must be an integer value")

    def test_cli_confirmations_patch(self):
        self.cli_helper = CLIConfirmationTestHelper(self)
        self.cli_helper.validate_patch()


class PlatformIPv4ControllerApiServiceParameterDeleteTestCase(ApiServiceParameterDeleteTestSuiteMixin,
                                                              base.FunctionalTest,
                                                              dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterListTestCase(ApiServiceParameterListTestSuiteMixin,
                                                            base.FunctionalTest,
                                                            dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterPostTestCase(ApiServiceParameterPostTestSuiteMixin,
                                                            base.FunctionalTest,
                                                            dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterPatchTestCase(ApiServiceParameterPatchTestSuiteMixin,
                                                             base.FunctionalTest,
                                                             dbbase.ProvisionedControllerHostTestCase):
    pass
