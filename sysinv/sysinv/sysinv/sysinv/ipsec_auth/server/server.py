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

from sysinv.common import kubernetes
from sysinv.common import rest_api
from sysinv.ipsec_auth.common import constants
from sysinv.ipsec_auth.common import utils
from sysinv.ipsec_auth.common.constants import State

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class IPsecServer(object):

    sel = selectors.DefaultSelector()

    def __init__(self, port=constants.DEFAULT_LISTEN_PORT):
        self.port = port
        self.keep_running = True

    def run(self):
        '''Start accepting connections in TCP server'''
        self._create_pid_file()

        ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssocket.setblocking(False)
        ssocket.bind(constants.TCP_SERVER)
        ssocket.listen()
        self.sel.register(ssocket, selectors.EVENT_READ, None)

        try:
            while self.keep_running:
                print("waiting for connection...")
                for key, _ in self.sel.select(timeout=1):
                    if key.data is None:
                        self._accept(key.fileobj)
                    else:
                        sock = key.fileobj
                        connection = key.data
                        connection.handle_messaging(sock, self.sel)
        except KeyboardInterrupt:
            print('Server interrupted.')
        finally:
            print('Shutting down.')
            self.sel.close()

    def _accept(self, sock):
        '''Callback for new connections'''
        connection, addr = sock.accept()
        connection.setblocking(False)
        print(f'accept({addr})')
        events = selectors.EVENT_READ
        self.sel.register(connection, events, IPsecConnection())

    def _create_pid_file(self):
        '''Create PID file.'''
        pid = str(os.getpid())
        pidfile = constants.PROCESS_ID

        with open(pidfile, 'w') as f:
            f.write(pid)

        print(f"PID file created: {pidfile}")


class IPsecConnection(object):

    kubeapi = kubernetes.KubeOperator()
    CA_KEY = 'tls.key'
    CA_CRT = 'tls.crt'

    def __init__(self):
        self.hostname = None
        self.mgmt_subnet = None
        self.signed_cert = None
        self.tmp_pub_key = None
        self.tmp_priv_key = None
        self.ots_token = None
        self.ca_key = self._get_system_local_ca_secret_info(self.CA_KEY)
        self.ca_crt = self._get_system_local_ca_secret_info(self.CA_CRT)
        self.state = State.STAGE_1

    def handle_messaging(self, sock, sel):
        '''Callback for read events'''
        try:
            client_address = sock.getpeername()
            data = sock.recv(4096)
            print(' state: %s' % (self.state))
            print(f' read({client_address})')
            if data:
                # A readable client socket has data
                print('  received {!r}'.format(data))
                self.state = utils.get_next_state(self.state)
                print('  changing to state: %s' % (self.state))
                print('  preparing payload')
                msg = self._handle_write(data)
                print('  sending payload')
                sock.sendall(msg)
                self.state = utils.get_next_state(self.state)
                print('  changing to state: %s' % (self.state))
            elif self.state == State.STAGE_5 or not data:
                # Interpret empty result as closed connection
                print(f'  closing connection with {client_address}')
                sock.close()
                sel.unregister(sock)
        except Exception as e:
            # Interpret empty result as closed connection
            print('  %s' % (e))
            print('  closing.')
            sock.close()
            sel.unregister(sock)

    def _handle_write(self, recv_message: bytes):
        '''Validate received message and generate response message payload to be
        sent to the client.'''
        try:
            data = json.loads(recv_message.decode('utf-8'))
            payload = {}

            if self.state == State.STAGE_2:
                if not self._validate_client_connection(data):
                    msg = "Connection refused with client due to invalid info " \
                          "received in payload."
                    raise ConnectionAbortedError(msg)

                mac_addr = data["mac_addr"]
                client_data = utils.get_client_hostname_and_mgmt_subnet(mac_addr)

                self.hostname = client_data['hostname']
                self.mgmt_subnet = client_data['mgmt_subnet']

                pub_key = self._generate_tmp_key_pair()
                self.ots_token = utils.generate_ots_token()
                hash_payload = utils.hash_and_sign_payload(self.ca_key, self.ots_token + pub_key)

                payload["token"] = self.ots_token.hex()
                payload["hostname"] = self.hostname
                payload["pub_key"] = pub_key.decode("utf-8")
                payload["ca_cert"] = self.ca_crt.decode("utf-8")
                payload["hash"] = hash_payload.decode("utf-8")

            if self.state == State.STAGE_4:
                eiv = base64.b64decode(data["eiv"])
                eak1 = base64.b64decode(data['eak1'])
                ecsr = base64.b64decode(data['ecsr'])
                ehash = base64.b64decode(data['ehash'])

                iv = utils.asymmetric_decrypt_data(self.tmp_priv_key, eiv)
                aes_key = utils.asymmetric_decrypt_data(self.tmp_priv_key, eak1)
                cert_request = utils.symmetric_decrypt_data(aes_key, iv, ecsr)

                if not utils.verify_encrypted_hash(self.ca_key, ehash,
                                                    self.ots_token, eak1, ecsr):
                    msg = "Hash validation failed."
                    raise ConnectionAbortedError(msg)

                self.signed_cert = self._sign_cert_request(cert_request)
                cert = bytes(self.signed_cert, 'utf-8')
                network = bytes(self.mgmt_subnet, 'utf-8')
                hash_payload = utils.hash_and_sign_payload(self.ca_key, cert + network)

                payload["cert"] = self.signed_cert
                payload["network"] = self.mgmt_subnet
                payload["hash"] = hash_payload.decode("utf-8")

            payload = json.dumps(payload)
            print(f"   payload: {payload}")
        except AttributeError as e:
            raise Exception('Failed to read attribute from payload. Error: %s' % e)
        except ConnectionAbortedError as e:
            raise Exception('IPsec Server stage failed. Error: %s' % e)
        except ValueError as e:
            raise Exception('Failed to decode message. Error: %s' % e)
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
            print('  Inconsistent hash of payload.')
            return False

        op_code = int(message["op"])
        if op_code not in constants.SUPPORTED_OP_CODES:
            print('  Operation not supported.')
            return False

        token = rest_api.get_token(constants.REGION_NAME)
        sysinv_ihost_url = constants.PXECONTROLLER_URL + '/v1/ihosts/'
        hosts_info = rest_api.rest_api_request(token, 'GET', sysinv_ihost_url)
        if not hosts_info:
            print('  Failed to retrieve hosts list.')
            return False

        uuid = None
        inv_state = None
        mgmt_mac = None
        personality = None
        for h in hosts_info['ihosts']:
            if message["mac_addr"] == h['mgmt_mac']:
                uuid = h['uuid']
                inv_state = h['inv_state']
                mgmt_mac = h['mgmt_mac']
                personality = h['personality']
                break

        if not uuid or not mgmt_mac or not personality or \
            op_code == constants.OP_CODE_INITIAL_AUTH and inv_state != '' or \
            op_code == constants.OP_CODE_CERT_RENEWAL and \
                inv_state != constants.INV_STATE_INVENTORIED:
            print('  Invalid host information.')
            return False

        if op_code == constants.OP_CODE_INITIAL_AUTH and inv_state == '':
            api_cmd = sysinv_ihost_url + uuid + '/update_inv_state'

            api_cmd_payload = '"{}"'.format(constants.INV_STATE_INVENTORYING)

            api_cmd_headers = dict()
            api_cmd_headers['Content-type'] = "application/json"
            api_cmd_headers['User-Agent'] = "sysinv/1.0"
            if not rest_api.rest_api_request(token, "POST", api_cmd,
                                                api_cmd_headers=api_cmd_headers,
                                                api_cmd_payload=api_cmd_payload):
                print('  Failed to update host inventory state.')
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
            raise Exception("TLS secret is unreachable.")

        data = bytes(secret.data.get(attr, None), "utf-8")
        if not data:
            raise Exception(f"Failed to retrieve system-local-ca's {attr} info.")

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
