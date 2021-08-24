#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import glob
import os.path
from datetime import datetime
from oslo_config import cfg
from oslo_log import log
from OpenSSL import crypto
from sysinv.common import constants
from sysinv.common import kubernetes as sys_kube

LOG = log.getLogger(__name__)
CONF = cfg.CONF

V1_ALPHA_3 = 'v1alpha3'
PLURAL_NAME_CERT = 'certificates'
METADATA = 'metadata'
ANNOTATIONS = 'annotations'
CERTMGR_CERT_NAME = "cert-manager.io/certificate-name"

SNAPSHOT_KEY_EXPDATE = 'expiry_date'

CERT_SNAPSHOT = {}
"""
CERT_SNAPSHOT is a dict of dict. Each entry is per certificate.
Internal dict is expiry_date and all annotations collected via k8s secret
{
    certname1: {
        expiry_date: date
        alarm: enabled
        alarm_before: 30d
        alarm_severity: unknown
        alarm_text: ""
    }
    certname2: {
        ...
    }
}
"""


def get_cert_expiration_date(cert):
    """
    Returns expiration date for certificate or None
    """
    expiration_date = None
    try:
        expiration_date = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    except Exception as e:
        LOG.error(e)

    return expiration_date


def get_tls_secrets_from_all_ns():
    kube_op = sys_kube.KubeOperator()
    try:
        secret_list = kube_op.kube_list_secret_for_all_namespaces("type=kubernetes.io/tls")
        LOG.debug('Total number of TLS secrets found in all namespaces=%d' % len(secret_list))

        # On central cloud (dc-cert ns), every subcloud comes with ICA entry - we want to skip
        # processing the ICA entry in order to scale the solution
        # The ICA secrets will get processed on the respective subcloud controller instead, and
        # will get picked up in sc-cert ns (only present on subclouds)
        ICA_substring = "-adminep-ca-certificate"
        filtered_list = [i for i in secret_list if ICA_substring not in i.metadata.name]
        return filtered_list
    except Exception:
        raise Exception('Failed to access secrets from all namespaces')


def collect_certificate_data_from_file(certname, pem_file):
    """
    Collect certificate data
    Input: certname, pem_file
    Returns: (certname, expiration_date, annotation_data)
            expiration_date will be None if data missing or error
            annotation_data will be set to defaults
    """
    LOG.debug('collect_certificate_data_from_file called for %s. Location=%s' % (certname, pem_file))
    expiration_date = None
    annotation_data = dict()
    try:
        with open(pem_file, "r") as f:
            cert_buf = f.read()
    except IOError:
        LOG.info('Certificate %s file not found' % certname)
        return (certname, None, None)

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
    expiration_date = get_cert_expiration_date(cert)
    annotation_data = get_default_annotation_values()
    return (certname, expiration_date, annotation_data)


def is_certname_already_processed(certname):
    """
    Check if certname is already processed and present in CERT_SNAPSHOT
    When iterating through pem files listed in CERT_LOCATION_MAP, we
    avoid duplicating if cert already seen during k8s secret collection
    Returns: True/False
    """
    ret = False
    if certname in constants.CERT_MODE_TO_SECRET_NAME:
        secret_name = constants.CERT_MODE_TO_SECRET_NAME[certname]
        if secret_name in CERT_SNAPSHOT:
            LOG.info('%s already processed in k8s secret scan. Skipping PEM file check' % certname)
            ret = True

    return ret


def collect_certificate_data_for_ssl_cas():
    """
    Collect certificate data for SSL_CA files
    Returns: list of tuples for each certificate file found
            Each tuple: (ssl_ca_x, exp_date, annotation_data)
    """
    ret = []

    ca_path = os.path.join(constants.SSL_CERT_CA_LIST_SHARED_DIR, "ssl_ca_*")
    LOG.debug('ssl_ca checking for files %s' % ca_path)
    ca_cert_files = glob.glob(ca_path)
    for fullpath in ca_cert_files:
        filename = os.path.basename(fullpath)
        LOG.info('ssl_ca file found: %s' % filename)
        ret.append(collect_certificate_data_from_file(filename, fullpath))

    return ret


def collect_certificate_data_from_kube_secret(secretobj):
    """
    Collect certificate data
    Input: secret object
    Returns: (certname, expiration_date, annotation_data)
            expiration_date will be None if data missing or error
            annotation_data from k8s Secret or Certificate CRD
    """
    certname = secretobj.metadata.name
    LOG.debug('collect_certificate_data_from_kube_secret called for %s' % certname)

    if 'tls.crt' not in secretobj.data:
        raise Exception('%s tls.crt data missing' % certname)

    expiration_date = None
    txt_crt = base64.b64decode(secretobj.data['tls.crt'])
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, txt_crt)
    expiration_date = get_cert_expiration_date(cert)
    annotation_data = get_annotation_data(secretobj)
    LOG.debug('returning (%s, %s, %s)' % (certname, expiration_date, annotation_data))
    return (certname, expiration_date, annotation_data)


def get_annotation_data(secretobj):
    """
    If secret created by cert-manager, will retrieve annotation data from Certificate CRD
    Else will retrieve annotation from Secret
    In either case, if data missing, will return defaults
    Returns: annotation data as dict
    """
    LOG.info('Retrieving annotation data for %s' % secretobj.metadata.name)
    kube_op = sys_kube.KubeOperator()

    ns = secretobj.metadata.namespace
    annotation_dict = dict()
    patch_needed = False

    cm_managed = False
    # Annotations can be None, so need a check first
    if secretobj.metadata.annotations is not None:
        # If cert-manager annotations present in metadata, secret is managed by cert-manager
        if CERTMGR_CERT_NAME in secretobj.metadata.annotations:
            try:
                crd_cert_name = secretobj.metadata.annotations[CERTMGR_CERT_NAME]
                certobj = kube_op.get_custom_resource(sys_kube.CERT_MANAGER_GROUP, V1_ALPHA_3,
                                                        ns, PLURAL_NAME_CERT, crd_cert_name)
                cm_managed = True

                # Note: unlike k8s secret obj, get_custom_resource() returns a dict()
                certobj_annotation = certobj[METADATA][ANNOTATIONS]
                annotation_dict, patch_needed = process_annotation_data(certobj_annotation)
                if patch_needed is True:
                    # Update the annotation
                    LOG.debug('Patching k8s cert with metadata %s' % annotation_dict)
                    certobj[METADATA][ANNOTATIONS] = annotation_dict
                    kube_op.apply_custom_resource(sys_kube.CERT_MANAGER_GROUP, V1_ALPHA_3,
                                                    ns, PLURAL_NAME_CERT, crd_cert_name, certobj)
            except Exception as e:
                LOG.error(e)

    if cm_managed is False:
        # Secret *not* created/managed by cert-manager. Annotation in Secret.
        LOG.debug('Secret NOT managed by cert-manager')
        annotation_dict, patch_needed = process_annotation_data(secretobj.metadata.annotations)
        if patch_needed is True:
            # Update the annotation
            LOG.debug('Patching k8s secret with metadata %s' % annotation_dict)
            secretobj.metadata.annotations = annotation_dict
            kube_op.kube_patch_secret(secretobj.metadata.name, ns, secretobj)

    return annotation_dict


def process_annotation_data(annotation_dict):
    """
    Parses annotation data with retrieved data, or initializes it with default values
    Returns: Initialized annotation_data as dict, patch needed True/False value
    """
    # Initialize 'process_ann_data' with 'annotation_dict'
    # (we dont want to lose other metadata when we patch back)
    processed_ann_data = annotation_dict
    patch_needed = False
    # Resource could have partial values or missing annotations. Set to default if data not set
    if annotation_dict is None:
        processed_ann_data = get_default_annotation_values()
        patch_needed = True
    else:
        # check for missing fields. If keys are missing, add to dict
        if constants.CERT_ALARM_ANNOTATION_ALARM not in annotation_dict:
            processed_ann_data[constants.CERT_ALARM_ANNOTATION_ALARM] = \
                                            constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM
            patch_needed = True
        if constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE not in annotation_dict:
            processed_ann_data[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE] = \
                                            constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE
            patch_needed = True
        if constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY not in annotation_dict:
            processed_ann_data[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY] = \
                                            constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY
            patch_needed = True
        if constants.CERT_ALARM_ANNOTATION_ALARM_TEXT not in annotation_dict:
            processed_ann_data[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT] = \
                                            constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT
            patch_needed = True

    return processed_ann_data, patch_needed


def reset_cert_snapshot():
    global CERT_SNAPSHOT
    CERT_SNAPSHOT = {}


def print_cert_snapshot():
    LOG.info('Cert snapshot = %s' % CERT_SNAPSHOT)


def add_cert_snapshot(certname, expirydate, annotation_data):
    global CERT_SNAPSHOT
    internaldict = dict()
    internaldict[SNAPSHOT_KEY_EXPDATE] = expirydate
    internaldict[constants.CERT_ALARM_ANNOTATION_ALARM] = \
                    annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM]
    internaldict[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE] = \
                    annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE]
    internaldict[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY] = \
                    annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY]
    internaldict[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT] = \
                    annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT]
    CERT_SNAPSHOT[certname] = internaldict


def get_default_annotation_values():
    ret = dict()
    ret[constants.CERT_ALARM_ANNOTATION_ALARM] = constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM
    ret[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE] = constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE
    ret[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY] = constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY
    ret[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT] = constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT
    return ret
