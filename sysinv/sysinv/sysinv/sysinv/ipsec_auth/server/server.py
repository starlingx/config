#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import base64
import json
import os
import selectors
import socket

from oslo_log import log as logging

from sysinv.common import kubernetes
from sysinv.common import rest_api
from sysinv.ipsec_auth.common import constants
from sysinv.ipsec_auth.common import utils
from sysinv.ipsec_auth.common.objects import State
from sysinv.ipsec_auth.common.objects import StatusCode
from sysinv.ipsec_auth.common.objects import Token

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOG = logging.getLogger(__name__)


class IPsecServer(object):

    sel = selectors.DefaultSelector()

    def __init__(self, port=constants.DEFAULT_LISTEN_PORT):
        self.port = port

    def run(self):
        '''Start accepting connections in TCP server'''
        try:
            ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ssocket.setblocking(False)
            ssocket.bind(constants.TCP_SERVER)
            ssocket.listen()

            self._create_pid_file()

            LOG.info("---- IPSec Auth Server started ----")

            self.sel.register(ssocket, selectors.EVENT_READ, None)

            while True:
                for key, _ in self.sel.select(timeout=1):
                    if key.data is None:
                        self._accept(key.fileobj)
                    else:
                        sock = key.fileobj
                        connection = key.data
                        connection.handle_messaging(sock, self.sel)
        except KeyboardInterrupt:
            LOG.exception('Server interrupted')
        except OSError:
            LOG.exception('System Error')
        except Exception:
            LOG.exception('An unknown exception occurred')
        self.sel.close()

    def _accept(self, sock):
        '''Callback for new connections'''
        connection, addr = sock.accept()
        connection.setblocking(False)
        LOG.info("Accept: {}".format(addr))
        events = selectors.EVENT_READ
        self.sel.register(connection, events, IPsecConnection())

    def _create_pid_file(self):
        '''Create PID file.'''
        pid = str(os.getpid())
        pidfile = constants.PROCESS_ID

        with open(pidfile, 'w') as f:
            f.write(pid)

        LOG.debug("PID file created: %s" % pidfile)


class IPsecConnection(object):

    kubeapi = kubernetes.KubeOperator()
    keep_connection = True
    CA_KEY = 'tls.key'
    CA_CRT = 'tls.crt'
    ROOT_CA_CRT = 'ca.crt'

    def __init__(self):
        self.hostname = None
        self.mgmt_ipsec = None
        self.mgmt_subnet = None
        self.op_code = None
        self.signed_cert = None
        self.tmp_pub_key = None
        self.tmp_priv_key = None
        self.uuid = None

        self.state = State.STAGE_1
        self.status_code = None
        self.ots_token = Token()

        self.ca_key = self._get_system_local_ca_secret_info(self.CA_KEY)
        self.ca_crt = self._get_system_local_ca_secret_info(self.CA_CRT)
        self.root_ca_crt = self._get_system_local_ca_secret_info(self.ROOT_CA_CRT)

        if not self.ca_key or not self.ca_crt or not self.root_ca_crt:
            raise ValueError('Failed to retrieve system-local-ca information')

    def handle_messaging(self, sock, sel):
        '''Callback for read events'''
        try:
            client_address = sock.getpeername()
            LOG.debug("Read({})".format(client_address))
            data = utils.socket_recv_all_json(sock, 8192)
            if data and self.state != State.END_STAGE:
                # A readable client socket has data and it is not on END_STAGE
                LOG.debug("Received {!r}".format(data))
                self.state = State.get_next_state(self.state, self.op_code)

                LOG.debug("Preparing payload")
                msg = self._handle_write(data)
                sock.sendall(msg)

                if self.state == State.STAGE_2:
                    self.ots_token.activate()
                self.state = State.get_next_state(self.state, self.op_code)
            else:
                # Interpret empty result or END_STAGE as closed connection
                if not data and self.state != State.END_STAGE:
                    LOG.warn('No data received from client or empty buffer provided.')
                self.keep_connection = False
                LOG.info("Closing connection with {}".format(client_address))
        except Exception as e:
            # Exceptions should be handled below
            # TODO (mbenedit): Log, handle and send failure status code to IPsec
            # client. Additionally, create different types of failure statuses
            # for each type of exception raised during IPsec server execution.
            self.status_code = StatusCode.IPSEC_OP_FAILURE_GENERAL
            LOG.exception("%s" % (e))
            self.keep_connection = False
        finally:
            if not self.keep_connection:
                self._cleanup_connection_data()
                sock.close()
                sel.unregister(sock)
                LOG.info("Connection closed.")
            LOG.debug("state: {}, status_code: {}".format(self.state, self.status_code))

    def _handle_write(self, recv_message: bytes):
        '''Validate received message and generate response message payload to be
        sent to the client.'''
        try:
            data = json.loads(recv_message.decode('utf-8'))
            payload = {}

            if self.state == State.STAGE_2:
                LOG.info("Received IPSec Auth request")
                self.op_code = data["op"]
                mac_addr = data["mac_addr"]

                if not self._validate_client_connection(data):
                    msg = ("Connection refused with client due to invalid info "
                           "received in payload.")
                    raise ConnectionRefusedError(msg)

                if self.op_code == constants.OP_CODE_INITIAL_AUTH and \
                   self.mgmt_ipsec == constants.MGMT_IPSEC_ENABLED:
                    # Initial Auth operation w/ MGMT_IPSEC_ENABLED
                    # This should return a payload with only IPSEC_OP_ENABLED
                    # code and move IPsec Connection state to END_STAGE.
                    LOG.info("Host is already IPsec enabled.")
                    self.state = State.END_STAGE
                    self.status_code = StatusCode.IPSEC_OP_ENABLED

                    payload['status_code'] = self.status_code.value
                elif self.op_code == constants.OP_CODE_CERT_VALIDATION:
                    # Cert Validation operation
                    cert = x509.load_pem_x509_certificate(base64.b64decode(self.ca_crt))
                    LOG.debug("Cert Serial: {}".format(cert.serial_number))
                    self.status_code = StatusCode.IPSEC_OP_SUCCESS

                    payload["ca_cert_serial"] = cert.serial_number
                    payload['status_code'] = self.status_code.value
                else:
                    # Initial Auth and Cert Renewal operations
                    client_data = utils.get_client_host_info_by_mac(mac_addr)
                    self.hostname = client_data['hostname']
                    self.mgmt_subnet = client_data['mgmt_subnet']
                    self.unit_ip = client_data['unit_ip']
                    self.floating_ip = client_data['floating_ip']
                    self.status_code = StatusCode.IPSEC_OP_IN_PROGRESS

                    pub_key = self._generate_tmp_key_pair()
                    token = self.ots_token.get_content()
                    hash_payload = utils.hash_and_sign_payload(self.ca_key, token + pub_key)

                    payload["token"] = repr(self.ots_token)
                    payload["hostname"] = self.hostname
                    payload["pub_key"] = pub_key.decode("utf-8")
                    payload["ca_cert"] = self.ca_crt.decode("utf-8")
                    payload["root_ca_cert"] = self.root_ca_crt.decode("utf-8")
                    payload["hash"] = hash_payload.decode("utf-8")
                    payload['status_code'] = self.status_code.value

                LOG.info("Sending IPSec Auth response")

            elif self.state == State.STAGE_4:
                LOG.info("Received IPSec Auth CSR request")
                token = data["token"]
                eiv = base64.b64decode(data["eiv"])
                eak1 = base64.b64decode(data['eak1'])
                ecsr = base64.b64decode(data['ecsr'])
                ehash = base64.b64decode(data['ehash'])

                if self.ots_token.compare_tokens(token):
                    if self.ots_token.is_valid():
                        self.ots_token.set_as_used()
                    else:
                        raise ValueError("Token expired or already used.")
                else:
                    raise ValueError("Invalid token received.")

                token = self.ots_token.get_content()

                if not utils.verify_encrypted_hash(self.ca_key, ehash,
                                                   token, eak1, ecsr):
                    raise ValueError('Hash validation failed.')

                iv = utils.asymmetric_decrypt_data(self.tmp_priv_key, eiv)
                aes_key = utils.asymmetric_decrypt_data(self.tmp_priv_key, eak1)
                cert_request = utils.symmetric_decrypt_data(aes_key, iv, ecsr)

                self.signed_cert = self._sign_cert_request(cert_request)
                if not self.signed_cert:
                    raise ValueError('Unable to sign certificate request')

                data = bytes(self.signed_cert, 'utf-8')
                if self.op_code == constants.OP_CODE_INITIAL_AUTH:
                    payload["network"] = self.mgmt_subnet
                    payload["unit_ip"] = self.unit_ip
                    payload["floating_ip"] = self.floating_ip
                    data = data + bytes(self.mgmt_subnet +
                                        self.unit_ip +
                                        self.floating_ip, 'utf-8')

                hash_payload = utils.hash_and_sign_payload(self.ca_key, data)
                self.status_code = StatusCode.IPSEC_OP_SUCCESS

                payload["cert"] = self.signed_cert
                payload["hash"] = hash_payload.decode("utf-8")
                payload['status_code'] = self.status_code.value

                LOG.info("Sending IPSec Auth CSR response")
            payload = json.dumps(payload)
            LOG.debug("Payload: %s" % payload)
        except AttributeError as e:
            raise Exception('Failed to read attribute from payload. Error: %s' % e)
        except ConnectionRefusedError as e:
            raise Exception('IPsec Server stage failed. Error: %s' % e)
        except ValueError as e:
            raise Exception('Failed to decode message or inappropriate '
                            'argument value. Error: %s' % e)
        except TypeError as e:
            raise Exception('Failed to read values from payload. '
                            'Values of attributes must be str. Error: %s' % e)
        except Exception as e:
            raise Exception('An unknown exception occurred. Error: %s' % e)

        return bytes(payload, "utf-8")

    def _validate_client_connection(self, message):
        hashed_item = message.pop('hash')
        hashed_payload = utils.hash_payload(message)
        if hashed_item != hashed_payload:
            LOG.error("Inconsistent hash of payload.")
            return False

        if self.op_code not in constants.SUPPORTED_OP_CODES:
            LOG.error("Operation not supported.")
            return False

        token = rest_api.get_token(constants.REGION_NAME)
        sysinv_ihost_url = constants.PXECONTROLLER_URL + '/v1/ihosts/'
        hosts_info = rest_api.rest_api_request(token, 'GET', sysinv_ihost_url)
        if not hosts_info:
            LOG.error("Failed to retrieve hosts list.")
            return False

        mgmt_mac = None
        personality = None
        for h in hosts_info['ihosts']:
            if message["mac_addr"] == h.get('mgmt_mac'):
                self.uuid = h.get('uuid')
                capabilities = h.get('capabilities')
                self.mgmt_ipsec = capabilities.get('mgmt_ipsec') if capabilities else None
                mgmt_mac = h.get('mgmt_mac')
                personality = h.get('personality')
                break

        LOG.info("Request op:{}, host uuid:{}, mgmt_ipsec:{}, mgmt_mac:{}, personality:{}"
                .format(self.op_code, self.uuid, self.mgmt_ipsec, mgmt_mac, personality))

        # Initial auth request
        if self.op_code == constants.OP_CODE_INITIAL_AUTH:
            if self.uuid and mgmt_mac:
                if self.mgmt_ipsec is None:
                    return self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_ENABLING)
                elif self.mgmt_ipsec == constants.MGMT_IPSEC_ENABLED:
                    # Host is already enabled, do nothing and prepare payload
                    # w/ IPSEC_OP_ENABLED.
                    pass
            else:
                LOG.error("Invalid request for operation: %s" % self.op_code)
                return False

        # Certificate renewal or Certificate Validation requests
        elif (self.op_code == constants.OP_CODE_CERT_RENEWAL or
                self.op_code == constants.OP_CODE_CERT_VALIDATION):
            if self.uuid and self.mgmt_ipsec == constants.MGMT_IPSEC_ENABLED and mgmt_mac:
                # Valid so do nothing
                pass
            else:
                LOG.error("Invalid request for operation: %s" % self.op_code)
                return False

        return True

    def _cleanup_connection_data(self):
        '''Clean up or update remaining data created during the execution of
        IPsec operations.'''
        if self.ots_token:
            self.ots_token.purge()

        if self.op_code != constants.OP_CODE_CERT_VALIDATION and \
           self.status_code == StatusCode.IPSEC_OP_SUCCESS and \
           self.state == State.END_STAGE:
            return self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_ENABLED)
        elif self.op_code == constants.OP_CODE_INITIAL_AUTH and \
             self.mgmt_ipsec and \
             self.mgmt_ipsec != constants.MGMT_IPSEC_ENABLED and \
             self.mgmt_ipsec != constants.MGMT_IPSEC_UPGRADING:
            return self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_DISABLED)

        return True

    def _update_mgmt_ipsec_state(self, ipsec_state):
        if not self.uuid:
            LOG.error("Invalid host uuid")
            return False

        if not utils.update_host_mgmt_ipsec_state(self.uuid, ipsec_state):
            LOG.error("Failed to update mgmt IPSec state to : {}".format(ipsec_state))
            return False

        self.mgmt_ipsec = ipsec_state

        return True

    def _generate_tmp_key_pair(self):
        '''Generate a temporary key pair to encrypt and decrypt exchanged data.'''
        self.tmp_priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.tmp_pub_key = self.tmp_priv_key.public_key()
        pub_key_bytes = self.tmp_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.b64encode(pub_key_bytes)

    def _get_system_local_ca_secret_info(self, attr):
        '''Retrieve system-local-ca's private key.'''
        secret = self.kubeapi.kube_get_secret(constants.SECRET_SYSTEM_LOCAL_CA,
                                              constants.NAMESPACE_CERT_MANAGER)
        if not secret:
            LOG.error("TLS secret is unreachable.")
            return

        data = secret.data.get(attr, None)
        if not data and attr == self.ROOT_CA_CRT:
            data = secret.data.get(self.CA_CRT, None)

        if data is None:
            LOG.error("Failed to retrieve %s info." % attr)
            return data

        data = bytes(data, "utf-8")

        if attr == self.CA_KEY:
            data = base64.b64decode(data)

        return data

    def _sign_cert_request(self, request):
        '''Create CertificateRequest related to a specific host's CSR and retrieve
        the signed certificate.'''
        csr_name = constants.CERT_NAME_PREFIX + self.hostname[constants.UNIT_HOSTNAME]
        csr_request = base64.b64encode(request).decode("utf-8")
        csr_body = {
            "apiVersion": constants.API_VERSION_CERT_MANAGER,
            "kind": "CertificateRequest",
            "metadata": {
                "name": csr_name,
                "namespace": constants.NAMESPACE_DEPLOYMENT,
            },
            "spec": {
                "request": csr_request,
                "isCA": False,
                "usages": ["signing", "digital signature", "server auth"],
                "duration": constants.CERTIFICATE_REQUEST_DURATION,
                "issuerRef": {
                    "name": constants.CLUSTER_ISSUER_SYSTEM_LOCAL_CA,
                    "kind": "ClusterIssuer",
                    "group": constants.GROUP_CERT_MANAGER,
                },
            },
        }

        return utils.kube_apply_certificate_request(csr_body)
