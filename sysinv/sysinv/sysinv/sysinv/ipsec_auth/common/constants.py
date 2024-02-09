#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from enum import Enum


class State(Enum):
    STAGE_1 = 1
    STAGE_2 = 2
    STAGE_3 = 3
    STAGE_4 = 4
    STAGE_5 = 5


PROCESS_ID = '/var/run/ipsec-server.pid'

DEFAULT_BIND_ADDR = "0.0.0.0"
DEFAULT_LISTEN_PORT = 54724
TCP_SERVER = (DEFAULT_BIND_ADDR, DEFAULT_LISTEN_PORT)

PLATAFORM_CONF_FILE = '/etc/platform/platform.conf'

SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

API_VERSION_CERT_MANAGER = 'cert-manager.io/v1'
CERTIFICATE_REQUEST_DURATION = '2160h'
CERTIFICATE_REQUEST_RESOURCE = 'certificaterequests.cert-manager.io'
GROUP_CERT_MANAGER = 'cert-manager.io'
NAMESPACE_CERT_MANAGER = 'cert-manager'
NAMESPACE_DEPLOYMENT = 'deployment'

CLUSTER_ISSUER_SYSTEM_LOCAL_CA = 'system-local-ca'
SECRET_SYSTEM_LOCAL_CA = 'system-local-ca'

TRUSTED_CA_CERT_FILE = 'system-local-ca.crt'
TRUSTED_CA_CERT_DIR = '/etc/swanctl/x509ca/'
TRUSTED_CA_CERT_PATH = TRUSTED_CA_CERT_DIR + TRUSTED_CA_CERT_FILE

CERT_SYSTEM_LOCAL_DIR = '/etc/swanctl/x509/'
CERT_SYSTEM_LOCAL_PRIVATE_DIR = '/etc/swanctl/private/'
CERT_NAME_PREFIX = 'system-ipsec-certificate-'

TMP_DIR_IPSEC = '/tmp/ipsec/'
TMP_DIR_IPSEC_KEYS = TMP_DIR_IPSEC + 'keys/'
TMP_FILE_IPSEC_PUK1 = 'puk1.crt'
TMP_FILE_IPSEC_AK1_KEY = 'ak1.key'
TMP_PUK1_FILE = TMP_DIR_IPSEC + TMP_FILE_IPSEC_PUK1
TMP_AK1_FILE = TMP_DIR_IPSEC_KEYS + TMP_FILE_IPSEC_AK1_KEY

UNIT_HOSTNAME = 'unit_hostname'
FLOATING_UNIT_HOSTNAME = 'floating_unit_hostname'

CONTROLLER = 'controller'

REGION_NAME = 'SystemController'
PXECONTROLLER_URL = 'http://pxecontroller:6385'

OP_CODE_INITIAL_AUTH = 1
OP_CODE_CERT_RENEWAL = 2
OP_CODE_PATCHING = 3
SUPPORTED_OP_CODES = [OP_CODE_INITIAL_AUTH,
                      OP_CODE_CERT_RENEWAL]

MGMT_IPSEC_ENABLING = 'enabling'
MGMT_IPSEC_ENABLED = 'enabled'
