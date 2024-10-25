#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.common import rest_api
from sysinv.common import utils as sys_utils
from sysinv.ipsec_auth.common import constants
from sysinv.common.kubernetes import KUBERNETES_ADMIN_CONF

import base64
import fcntl
import os
import socket
import struct
import subprocess
import yaml

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_plataform_conf(param):
    value = None
    path = constants.PLATAFORM_CONF_FILE

    with open(path) as fp:
        lines = fp.readlines()
        for line in lines:
            if line.find(param) != -1:
                value = line.split('=')[1]
                value = value.replace('\n', '')

    return value


def get_personality():
    return get_plataform_conf('nodetype')


def get_management_interface():
    return get_plataform_conf('management_interface')


def get_hw_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifstruct = struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        info = fcntl.ioctl(s.fileno(), constants.SIOCGIFHWADDR, ifstruct)
        return ':'.join('%02x' % b for b in info[18:24])
    except Exception as e:
        LOG.exception("Error getting mac address: %s" % (e))


def get_client_host_info_by_mac(mac_addr):
    token = rest_api.get_token(constants.REGION_NAME)
    sysinv_ihost_url = constants.PXECONTROLLER_URL + '/v1/ihosts/'
    api_cmd = sysinv_ihost_url + mac_addr + '/mgmt_ip'
    mgmt_info = rest_api.rest_api_request(token, 'GET', api_cmd)
    response = {}
    if mgmt_info:
        hosts = rest_api.rest_api_request(token, 'GET', sysinv_ihost_url)
        if not hosts:
            raise Exception('Failed to retrieve hosts list.')

        personality = None
        for h in hosts['ihosts']:
            if mac_addr == h['mgmt_mac']:
                personality = h['personality']
                break

        hostname = {}
        hostname[constants.UNIT_HOSTNAME] = mgmt_info['hostname']
        if personality in constants.CONTROLLER:
            hostname[constants.FLOATING_UNIT_HOSTNAME] = constants.CONTROLLER

        response['hostname'] = hostname
        response['mgmt_subnet'] = mgmt_info['subnet']
        response['unit_ip'] = mgmt_info['address']
        response['floating_ip'] = mgmt_info['floating']
    return response


def update_host_mgmt_ipsec_state(uuid, state):
    token = rest_api.get_token(constants.REGION_NAME)
    sysinv_ihost_url = constants.PXECONTROLLER_URL + '/v1/ihosts/'

    api_cmd = sysinv_ihost_url + uuid + '/update_mgmt_ipsec_state'
    api_cmd_payload = '"{}"'.format(state)
    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    if not rest_api.rest_api_request(token, "POST", api_cmd,
                                        api_cmd_headers=api_cmd_headers,
                                        api_cmd_payload=api_cmd_payload):
        return False
    return True


def load_data(path):
    data = None
    with open(path, 'rb') as f:
        data = f.read()

    return data


def save_data(path, data, owner_only=False):
    with open(path, 'wb') as f:
        f.write(data)

    if owner_only:
        os.chmod(path, 0o600)


def symmetric_encrypt_data(binary_data, key):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
    binary_data = padder.update(binary_data) + padder.finalize()

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(binary_data) + encryptor.finalize()

    return iv, encrypted_data


def symmetric_decrypt_data(aes_key, iv, data):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), default_backend())

    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES(aes_key).block_size).unpadder()
    decrypted_data = unpadder.update(data) + unpadder.finalize()

    return decrypted_data


def asymmetric_encrypt_data(key_data, data, is_cert=False):
    if is_cert:
        cert = x509.load_pem_x509_certificate(key_data)
        key = cert.public_key()
    else:
        key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )

    return key.encrypt(
        data,
        pad.OAEP(
            mgf=pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def asymmetric_decrypt_data(key, data):
    if not isinstance(key, rsa.RSAPrivateKey):
        key = serialization.load_pem_private_key(key, None, default_backend())

    return key.decrypt(
        data,
        pad.OAEP(
            mgf=pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def socket_recv_all_json(socket, buff_size):
    buffer = b''
    delimiter = b'}'
    iter = 0
    while delimiter not in buffer and \
          len(buffer) < buff_size and \
          iter < 10:
        data = socket.recv(buff_size)
        if not data:
            return None
        buffer += data
        iter = iter + 1
    if delimiter not in buffer:
        return None
    return buffer


def hash_payload(payload: dict):
    hash_algorithm = hashes.SHA256()
    hasher = hashes.Hash(hash_algorithm)
    for item in payload.keys():
        hasher.update(bytes(payload[item], 'utf-8'))
    digest = hasher.finalize()
    return digest.hex()


def hash_and_sign_payload(signer, data: bytes):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    digest = hasher.finalize()

    key = signer

    if not isinstance(key, rsa.RSAPrivateKey):
        key = serialization.load_pem_private_key(key, None, default_backend())

    data = key.sign(
        digest,
        pad.PSS(
            mgf=pad.MGF1(hashes.SHA256()),
            salt_length=pad.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )

    return base64.b64encode(data)


def verify_signed_hash(cert_data, signed_hash, data: bytes):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    digest = hasher.finalize()

    cert = x509.load_pem_x509_certificate(cert_data)
    key = cert.public_key()

    try:
        key.verify(
            signed_hash,
            digest,
            pad.PSS(
                mgf=pad.MGF1(hashes.SHA256()),
                salt_length=pad.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
    except exceptions.InvalidSignature:
        return False

    return True


def verify_encrypted_hash(key, ehash, token, eak1, ecsr):
    digest = asymmetric_decrypt_data(key, ehash)

    hash_algorithm = hashes.SHA256()
    hasher = hashes.Hash(hash_algorithm)
    hasher.update(bytes(token.hex(), 'utf-8'))
    hasher.update(eak1)
    hasher.update(ecsr)
    hash_value = hasher.finalize()

    if digest != hash_value:
        return False

    return True


def kube_apply_certificate_request(body):
    name = body["metadata"]["name"]

    # Verify if a CertificateRequest is already created
    # for this specific host and delete if it is true
    if sys_utils.is_certificate_request_created(name):
        LOG.debug(f"Deleting previously created {name} CertificateRequest.")
        sys_utils.delete_certificate_request(name)

    try:
        cr_body = yaml.safe_dump(body, default_flow_style=False)
        cmd = ['kubectl', '--kubeconfig', KUBERNETES_ADMIN_CONF,
               'apply', '-f', '-']

        create_cr = subprocess.run(cmd, input=cr_body.encode(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False)

        if create_cr.returncode != 0:
            LOG.error(f"Failed to create CertificateRequest resource. {create_cr.stderr}")
            return None

    except Exception as e:
        LOG.error(f"Error trying to create CertificateRequest resource, reason: {e}")
        return None

    return sys_utils.get_certificate_request(name)


def remove_ca_certificates(prefix):
    for file in os.listdir(constants.TRUSTED_CA_CERT_DIR):
        path = os.path.join(constants.TRUSTED_CA_CERT_DIR, file)
        if os.path.isfile(path) and file.startswith(prefix):
            try:
                os.remove(path)
            except Exception:
                LOG.exception("Error removing file: %s" % path)
                return False
    return True


def get_ca_certificate_path(prefix, index):
    if index == 0:
        return constants.TRUSTED_CA_CERT_DIR + prefix + '.crt'

    return constants.TRUSTED_CA_CERT_DIR + prefix + '_l' + str(index) + '.crt'


def save_cert_bundle(cert_data, cert_prefix):
    index = 0

    certs = sys_utils.extract_certs_from_pem(cert_data)
    for cert in certs:
        cert_path = get_ca_certificate_path(cert_prefix, index)
        save_data(cert_path, cert.public_bytes(encoding=serialization.Encoding.PEM))
        index += 1


def create_symlink(src, dst):
    if not os.path.exists(src):
        return False

    if os.path.exists(dst):
        if src == dst:
            return False
        os.unlink(dst)

    os.symlink(src, dst)

    return os.path.exists(dst)
