#!/usr/bin/python
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is required to keep a copy of the last CA
# certificates when the CA certificates are being updated
# to avoid lost of connections during cert renewal process.
# Because IPsec use these certificates to establish the
# Security Associations.
#
import os
import sys
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

BEGIN_CERTIFICATE = b"-----BEGIN CERTIFICATE-----\n"
END_CERTIFICATE = b"\n-----END CERTIFICATE-----\n"

IPSEC_CA_CERT_DIR = '/etc/swanctl/x509ca/'
TMP_ROOT_CA_CERT = '/tmp/system-root-ca.crt'
TMP_LOCA_CA_CERT = '/tmp/system-local-ca.crt'

ROOT_CA_CERT_FILE_0 = 'system-root-ca-0.crt'
ROOT_CA_CERT_FILE_1 = 'system-root-ca-1.crt'
ROOT_CA_CERT_FILE_1_PATH = IPSEC_CA_CERT_DIR + ROOT_CA_CERT_FILE_1
CA_CERT_0_PREFIX = 'system-local-ca-0'
CA_CERT_1_PREFIX = 'system-local-ca-1'
CA_CERT_FILE_0 = CA_CERT_0_PREFIX + '.crt'
CA_CERT_FILE_1 = CA_CERT_1_PREFIX + '.crt'


def remove_ca_certificates(prefix):
    for file in os.listdir(IPSEC_CA_CERT_DIR):
        path = os.path.join(IPSEC_CA_CERT_DIR, file)
        if os.path.isfile(path) and file.startswith(prefix):
            try:
                os.remove(path)
            except Exception:
                print("Error removing file: %s" % path)
                return False
    return True


def rename_ca_certificates(old_prefix, new_prefix):
    for file in os.listdir(IPSEC_CA_CERT_DIR):
        path = os.path.join(IPSEC_CA_CERT_DIR, file)
        if os.path.isfile(path) and file.startswith(old_prefix):
            new_path = path.replace(old_prefix, new_prefix)
            try:
                os.rename(path, new_path)
            except Exception:
                print("Error renaming file %s to %s" % (path, new_path))
                return False
    return True


def get_ca_certificate_path(prefix, index):
    if index == 0:
        return IPSEC_CA_CERT_DIR + prefix + '.crt'

    return IPSEC_CA_CERT_DIR + prefix + '_l' + str(index) + '.crt'


def extract_certs_from_pem(pem_contents):
    start = 0
    certs = []
    while True:
        index = pem_contents.find(BEGIN_CERTIFICATE, start)
        if index == -1:
            break
        try:
            cert = x509.load_pem_x509_certificate(pem_contents[index::],
                                                  default_backend())
        except Exception:
            print("Load pem x509 certificate failed at file location: %s" % index)
            return None

        certs.append(cert)
        start = index + len(BEGIN_CERTIFICATE)

    return certs


def save_cert_bundle(cert_data, cert_prefix):
    index = 0

    certs = extract_certs_from_pem(cert_data)
    for cert in certs:
        cert_path = get_ca_certificate_path(cert_prefix, index)
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
        index += 1


if __name__ == '__main__':

    if not os.path.exists(TMP_ROOT_CA_CERT) or not os.path.exists(TMP_LOCA_CA_CERT):
        print("Temporary Certificates files not found")
        sys.exit(1)

    remove_ca_certificates(ROOT_CA_CERT_FILE_0)
    rename_ca_certificates(ROOT_CA_CERT_FILE_1, ROOT_CA_CERT_FILE_0)
    remove_ca_certificates(CA_CERT_0_PREFIX)
    rename_ca_certificates(CA_CERT_1_PREFIX, CA_CERT_0_PREFIX)

    try:
        with open(TMP_ROOT_CA_CERT, 'rb') as tmp_f:
            data = tmp_f.read()
            with open(ROOT_CA_CERT_FILE_1_PATH, 'wb') as f:
                f.write(data)

        with open(TMP_LOCA_CA_CERT, 'r') as tmp_f:
            data = tmp_f.read()
            save_cert_bundle(data.encode('utf-8'), CA_CERT_1_PREFIX)
    except Exception:
        print("Fail to update certificates")
        sys.exit(1)

    load_creds = subprocess.run(['swanctl', '--load-creds'], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)

    if load_creds.returncode != 0:
        err = "Error: %s" % (load_creds.stderr.decode("utf-8"))
        print("Failed to load StrongSwan credentials: %s" % err)
        sys.exit(1)
