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
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from oslo_log import log as logging

from sysinv.ipsec_auth.client import config
from sysinv.ipsec_auth.common import constants
from sysinv.ipsec_auth.common import utils
from sysinv.ipsec_auth.common.objects import State

LOG = logging.getLogger(__name__)


class Client(object):

    def __init__(self, host, port, op_code):
        self.host = host
        self.port = port
        self.op_code = str(op_code)
        self.state = State.STAGE_1
        self.ifname = utils.get_management_interface()
        self.personality = utils.get_personality()
        self.mac_addr = utils.get_hw_addr(self.ifname)
        self.hostname = None
        self.data = None
        self.ots_token = None
        self.local_addr = None

    # Generate message 1 - OP/MAC/HASH
    def _generate_message_1(self):
        message = {}
        message['op'] = self.op_code
        message['mac_addr'] = self.mac_addr
        message['hash'] = utils.hash_payload(message)

        return json.dumps(message)

    # Generate IPsec prk2 (RSA - PRK2)
    def _generate_prk2(self):
        prk2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        prk2_bytes = prk2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # TODO: Save PRK2 in LUKS Filesystem
        prk2_file = constants.CERT_NAME_PREFIX + \
                        self.hostname[constants.UNIT_HOSTNAME] + '.key'
        prk2_path = constants.CERT_SYSTEM_LOCAL_PRIVATE_DIR + prk2_file
        utils.save_data(prk2_path, prk2_bytes)

        return prk2

    # Generate AK1
    def _generate_ak1(self, puk1_data):
        ak1 = os.urandom(32)

        # TODO: Save AK1 in LUKS Filesystem
        utils.save_data(constants.TMP_AK1_FILE, ak1)

        return ak1

    # Generate CSR w/ PRK2
    def _create_csr(self, prk2):
        common_name = 'ipsec-' + self.hostname[constants.UNIT_HOSTNAME]

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        builder = builder.sign(prk2, hashes.SHA256())

        return builder.public_bytes(serialization.Encoding.PEM)

    # Generate message 3 PRK2/AK1/CSR/HASH
    def _generate_message_3(self):
        message = {}

        puk1_data = utils.load_data(constants.TMP_PUK1_FILE)
        puc_data = utils.load_data(constants.TRUSTED_CA_CERT_1_PATH)

        LOG.info("Generate RSA Private Key (PRK2).")
        prk2 = self._generate_prk2()

        LOG.info("Generate AES Key (AK1).")
        ak1 = self._generate_ak1(puk1_data)

        LOG.info("Generate Certificate Request (CSR).")
        csr = self._create_csr(prk2)

        LOG.info("Encrypt CSR w/ AK1.")
        iv, ecsr = utils.symmetric_encrypt_data(csr, ak1)

        LOG.info("Encrypt AK1 and IV w/ PUK1")
        eak1 = utils.asymmetric_encrypt_data(puk1_data, ak1)
        eiv = utils.asymmetric_encrypt_data(puk1_data, iv)

        LOG.info("Hash OTS Token, eAK1 and eCSR.")
        hash_algorithm = hashes.SHA256()
        hasher = hashes.Hash(hash_algorithm)
        hasher.update(bytes(self.ots_token, 'utf-8'))
        hasher.update(eak1)
        hasher.update(ecsr)
        hash_value = hasher.finalize()

        ehash_data = utils.asymmetric_encrypt_data(puc_data, hash_value, True)

        message['token'] = self.ots_token
        message['eiv'] = base64.b64encode(eiv).decode('utf-8')
        message['eak1'] = base64.b64encode(eak1).decode('utf-8')
        message['ecsr'] = base64.b64encode(ecsr).decode('utf-8')
        message['ehash'] = base64.b64encode(ehash_data).decode('utf-8')

        return json.dumps(message)

    def _handle_rcvd_data(self, data):

        LOG.debug("Received {!r})".format(data))
        msg = json.loads(data.decode('utf-8'))

        if self.state == State.STAGE_2:
            LOG.info("Received IPSec Auth Response")
            self.ots_token = msg['token']
            self.hostname = msg['hostname']
            key = base64.b64decode(msg['pub_key'])
            root_ca_cert = base64.b64decode(msg['root_ca_cert'])
            ca_cert = base64.b64decode(msg['ca_cert'])
            digest = base64.b64decode(msg['hash'])

            data = bytes.fromhex(self.ots_token) + msg['pub_key'].encode('utf-8')
            if not utils.verify_signed_hash(ca_cert, digest, data):
                msg = "Hash validation failed"
                LOG.exception("%s" % msg)
                return False

            utils.save_data(constants.TMP_PUK1_FILE, key)
            utils.save_data(constants.TRUSTED_ROOT_CA_CERT_1_PATH, root_ca_cert)
            utils.save_data(constants.TRUSTED_CA_CERT_1_PATH, ca_cert)
            if self.op_code == constants.OP_CODE_INITIAL_AUTH:
                utils.save_data(constants.TRUSTED_ROOT_CA_CERT_0_PATH, root_ca_cert)
                utils.save_data(constants.TRUSTED_CA_CERT_0_PATH, ca_cert)

        if self.state == State.STAGE_4:
            LOG.info("Received IPSec Auth CSR Response")
            cert = base64.b64decode(msg['cert'])
            digest = base64.b64decode(msg['hash'])

            ca_cert = utils.load_data(constants.TRUSTED_CA_CERT_1_PATH)

            data = msg['cert'].encode('utf-8')
            if self.op_code == constants.OP_CODE_INITIAL_AUTH:
                network = msg['network']
                unit_ip = msg['unit_ip']
                floating_ip = msg['floating_ip']
                data = data + (network + unit_ip + floating_ip).encode('utf-8')

            if not utils.verify_signed_hash(ca_cert, digest, data):
                msg = "Hash validation failed"
                LOG.exception("Hash validation failed")
                return False

            cert_file = constants.CERT_NAME_PREFIX + \
                self.hostname[constants.UNIT_HOSTNAME] + '.crt'

            cert_path = constants.CERT_SYSTEM_LOCAL_DIR + cert_file
            utils.save_data(cert_path, cert)

            if self.op_code == constants.OP_CODE_INITIAL_AUTH:
                if self.personality == constants.CONTROLLER:
                    self.local_addr = self.hostname[constants.UNIT_HOSTNAME] + ', ' \
                                    + self.hostname[constants.FLOATING_UNIT_HOSTNAME]
                else:
                    self.local_addr = utils.get_ip_addr(self.ifname)

                LOG.info("Generating config files and restart ipsec")
                strong = config.StrongswanPuppet(self.hostname[constants.UNIT_HOSTNAME],
                                                self.local_addr, network,
                                                unit_ip, floating_ip)
                strong.generate_file()
                puppet_cf = subprocess.run(['puppet', 'apply', '-e',
                                            'include ::platform::strongswan'],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            check=False)

                if puppet_cf.returncode != 0:
                    err = "Error: %s" % (puppet_cf.stderr.decode("utf-8"))
                    LOG.exception("Failed to create StrongSwan config files: %s" % err)
                    return False

            elif self.op_code == constants.OP_CODE_CERT_RENEWAL:
                load_creds = subprocess.run(['swanctl', '--load-creds'], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)

                if load_creds.returncode != 0:
                    err = "Error: %s" % (load_creds.stderr.decode("utf-8"))
                    LOG.exception("Failed to load StrongSwan credentials: %s" % err)
                    return False

                rekey = subprocess.run(['swanctl', '--rekey', '--ike', constants.IKE_SA_NAME,
                                        '--reauth'], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, check=False)

                if rekey.returncode != 0:
                    err = "Error: %s" % (rekey.stderr.decode("utf-8"))
                    LOG.exception("Failed to rekey IKE SA with StrongSwan: %s" % err)
                    return False

                LOG.info('IPsec certificate renewed successfully')

        return True

    def _handle_send_data(self, data):
        payload = None
        if self.state == State.STAGE_1:
            payload = self._generate_message_1()
            LOG.info("Sending IPSec Auth Request")
        elif self.state == State.STAGE_3:
            payload = self._generate_message_3()
            LOG.info("Sending IPSec Auth CSR Request")

        LOG.debug("Sending {!r})".format(payload))

        return payload

    def run(self):
        LOG.info("Connecting to %s port %s" % (self.host, self.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        sock.setblocking(False)

        sel = selectors.DefaultSelector()

        # Set up the selector to watch for when the socket is ready
        # to send data as well as when there is data to read.
        sel.register(
            sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
        )

        keep_running = True
        while keep_running:
            for key, mask in sel.select(timeout=1):
                connection = key.fileobj

                LOG.debug("State{}".format(self.state))
                if mask & selectors.EVENT_READ:
                    self.data = connection.recv(8192)
                    if not self._handle_rcvd_data(self.data):
                        raise ConnectionAbortedError("Error receiving data from server")
                    sel.modify(sock, selectors.EVENT_WRITE)
                    self.state = State.get_next_state(self.state)

                if mask & selectors.EVENT_WRITE:
                    msg = self._handle_send_data(self.data)
                    sock.sendall(bytes(msg, 'utf-8'))
                    sel.modify(sock, selectors.EVENT_READ)
                    self.state = State.get_next_state(self.state)

                if self.state == State.STAGE_5:
                    keep_running = False

        LOG.info("Shutting down")
        sel.unregister(connection)
        connection.close()
        sel.close()
