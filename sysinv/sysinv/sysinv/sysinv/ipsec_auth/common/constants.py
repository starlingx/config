#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
PROCESS_ID = '/var/run/ipsec-server.pid'

DEFAULT_BIND_ADDR = "0.0.0.0"
DEFAULT_LISTEN_PORT = 54724
TCP_SERVER = (DEFAULT_BIND_ADDR, DEFAULT_LISTEN_PORT)

PLATAFORM_CONF_FILE = '/etc/platform/platform.conf'

SIOCGIFHWADDR = 0x8927

API_VERSION_CERT_MANAGER = 'cert-manager.io/v1'
CERTIFICATE_REQUEST_DURATION = '2160h'
CERTIFICATE_REQUEST_RESOURCE = 'certificaterequests.cert-manager.io'
GROUP_CERT_MANAGER = 'cert-manager.io'
NAMESPACE_CERT_MANAGER = 'cert-manager'
NAMESPACE_DEPLOYMENT = 'deployment'

CLUSTER_ISSUER_SYSTEM_LOCAL_CA = 'system-local-ca'
SECRET_SYSTEM_LOCAL_CA = 'system-local-ca'

# The system-local-ca certificates are stored by IPsec client
# named w/ 0 or 1 in their names. The system-local-ca-0.crt file represents
# the last tls certificate associated with system-local-ca,
# while system-local-ca-1.crt file is the current certificate
# associated with system-local-ca.
TRUSTED_ROOT_CA_CERT_FILE_0 = 'system-root-ca-0.crt'
TRUSTED_ROOT_CA_CERT_FILE_1 = 'system-root-ca-1.crt'
TRUSTED_CA_CERT_FILE_0 = 'system-local-ca-0.crt'
TRUSTED_CA_CERT_FILE_1 = 'system-local-ca-1.crt'
TRUSTED_CA_CERT_FILES = TRUSTED_CA_CERT_FILE_0 + ',' + TRUSTED_CA_CERT_FILE_1
TRUSTED_CA_CERT_DIR = '/etc/swanctl/x509ca/'
TRUSTED_ROOT_CA_CERT_0_PATH = TRUSTED_CA_CERT_DIR + TRUSTED_ROOT_CA_CERT_FILE_0
TRUSTED_ROOT_CA_CERT_1_PATH = TRUSTED_CA_CERT_DIR + TRUSTED_ROOT_CA_CERT_FILE_1
TRUSTED_CA_CERT_0_PATH = TRUSTED_CA_CERT_DIR + TRUSTED_CA_CERT_FILE_0
TRUSTED_CA_CERT_1_PATH = TRUSTED_CA_CERT_DIR + TRUSTED_CA_CERT_FILE_1

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

OP_CODE_INITIAL_AUTH = "1"
OP_CODE_CERT_RENEWAL = "2"
SUPPORTED_OP_CODES = [OP_CODE_INITIAL_AUTH,
                      OP_CODE_CERT_RENEWAL]

MGMT_IPSEC_ENABLING = 'enabling'
MGMT_IPSEC_ENABLED = 'enabled'
MGMT_IPSEC_DISABLED = 'disabled'

CHILD_SA_NAME = 'node'
IKE_SA_NAME = 'system-nodes'
