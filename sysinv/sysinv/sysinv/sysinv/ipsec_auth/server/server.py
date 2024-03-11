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
from sysinv.ipsec_auth.common.objects import Token

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOG = logging.getLogger(__name__)


class IPsecServer(object):

    sel = selectors.DefaultSelector()

    def __init__(self, port=constants.DEFAULT_LISTEN_PORT):
        self.port = port
        self.keep_running = True

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

            while self.keep_running:
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
    CA_KEY = 'tls.key'
    CA_CRT = 'tls.crt'

    def __init__(self):
        self.op_code = None
        self.hostname = None
        self.mgmt_subnet = None
        self.signed_cert = None
        self.tmp_pub_key = None
        self.tmp_priv_key = None
        self.uuid = None
        self.op_code = None
        self.mgmt_ipsec = None
        self.ots_token = Token()
        self.ca_key = self._get_system_local_ca_secret_info(self.CA_KEY)
        self.ca_crt = self._get_system_local_ca_secret_info(self.CA_CRT)
        self.state = State.STAGE_1

    def handle_messaging(self, sock, sel):
        '''Callback for read events'''
        try:
            client_address = sock.getpeername()
            data = sock.recv(4096)
            LOG.debug("Read({})".format(client_address))
            if data:
                # A readable client socket has data
                LOG.debug("Received {!r}".format(data))
                self.state = State.get_next_state(self.state)

                LOG.debug("Preparing payload")
                msg = self._handle_write(data)
                sock.sendall(msg)

                if self.state == State.STAGE_2:
                    self.ots_token.activate()
                self.state = State.get_next_state(self.state)
            elif self.state == State.STAGE_5 or not data:
                self.ots_token.purge()
                self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_ENABLED)

                # Interpret empty result as closed connection
                LOG.info("Closing connection with {}".format(client_address))
                sock.close()
                sel.unregister(sock)
        except Exception as e:
            self._cleanup_connection_data()
            LOG.exception("%s" % (e))
            LOG.error("Closing. {}".format(sock.getpeername()))
            sock.close()
            sel.unregister(sock)

    def _handle_write(self, recv_message: bytes):
        '''Validate received message and generate response message payload to be
        sent to the client.'''
        try:
            data = json.loads(recv_message.decode('utf-8'))
            payload = {}

            if not self.ca_key or not self.ca_crt:
                raise ValueError('Failed to retrieve system-local-ca information')

            if self.state == State.STAGE_2:
                LOG.info("Received IPSec Auth request")
                self.op_code = data["op"]
                mac_addr = data["mac_addr"]

                if not self._validate_client_connection(data):
                    msg = ("Connection refused with client due to invalid info "
                           "received in payload.")
                    raise ConnectionRefusedError(msg)

                client_data = utils.get_client_hostname_and_mgmt_subnet(mac_addr)
                self.hostname = client_data['hostname']
                self.mgmt_subnet = client_data['mgmt_subnet']

                pub_key = self._generate_tmp_key_pair()
                token = self.ots_token.get_content()
                hash_payload = utils.hash_and_sign_payload(self.ca_key, token + pub_key)

                payload["token"] = repr(self.ots_token)
                payload["hostname"] = self.hostname
                payload["pub_key"] = pub_key.decode("utf-8")
                payload["ca_cert"] = self.ca_crt.decode("utf-8")
                payload["hash"] = hash_payload.decode("utf-8")

                LOG.info("Sending IPSec Auth Response")

            if self.state == State.STAGE_4:
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
                    data = data + bytes(self.mgmt_subnet, 'utf-8')

                hash_payload = utils.hash_and_sign_payload(self.ca_key, data)

                payload["cert"] = self.signed_cert
                payload["hash"] = hash_payload.decode("utf-8")

                LOG.info("Sending IPSec Auth CSR Response")

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
            if self.uuid and self.mgmt_ipsec is None and mgmt_mac:
                if not self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_ENABLING):
                    return False
            else:
                LOG.error("Invalid request for operation: %s" % self.op_code)
                return False

        # Certificate renewal request
        elif self.op_code == constants.OP_CODE_CERT_RENEWAL:
            if self.uuid and self.mgmt_ipsec == constants.MGMT_IPSEC_ENABLED and mgmt_mac:
                # Valid so do nothing
                pass
            else:
                LOG.error("Invalid request for operation: %s" % self.op_code)
                return False

        return True

    def _cleanup_connection_data(self):
        # Interpret empty result as closed connection
        if self.ots_token:
            self.ots_token.purge()

        if (self.op_code == constants.OP_CODE_INITIAL_AUTH and
             self.mgmt_ipsec != constants.MGMT_IPSEC_ENABLED and not
             self._update_mgmt_ipsec_state(constants.MGMT_IPSEC_DISABLED)):
            return False

        return True

    def _update_mgmt_ipsec_state(self, ipsec_state):
        if not self.uuid:
            LOG.error("Invalid host uuid")
            return False

        if not utils.update_host_mgmt_ipsec_state(self.uuid, ipsec_state):
            LOG.error("Failed to update mgmt IPSec state to : {}".format(ipsec_state))
            return False

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

        data = bytes(secret.data.get(attr, None), "utf-8")
        if not data:
            LOG.error("Failed to retrieve %s info." % attr)
            return

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
