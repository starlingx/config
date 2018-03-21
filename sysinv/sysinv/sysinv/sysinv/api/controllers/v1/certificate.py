# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2018 Wind River Systems, Inc.
#

import datetime
import os

import pecan
import wsme
import wsmeext.pecan as wsme_pecan
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fm_api import constants as fm_constants
from fm_api import fm_api
from pecan import expose, rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _
from wsme import types as wtypes

LOG = log.getLogger(__name__)


class CertificatePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class Certificate(base.APIBase):
    """API representation of CERTIFICATE Configuration.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a certificate.
    """

    uuid = types.uuid
    "Unique UUID for this certificate"

    certtype = wtypes.text
    "Represents the type of certificate"

    issuer = wtypes.text
    "Represents the certificate issuer"

    signature = wtypes.text
    "Represents the certificate signature"

    start_date = wtypes.datetime.datetime
    "Represents the certificate start date"

    expiry_date = wtypes.datetime.datetime
    "Represents the certificate expiry"

    passphrase = wtypes.text
    "Represents the passphrase for pem"

    mode = wtypes.text
    "Represents the desired mode"

    details = types.MultiType({dict})
    "Represents additional details of the certificate"

    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.certificate.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

        # 'details' is not part of the object.certificate.fields
        # (it is an API-only attribute)
        self.fields.append('details')
        setattr(self, 'details', kwargs.get('details', None))

    @classmethod
    def convert_with_links(cls, rpc_certificate, expand=False):
        certificate = Certificate(**rpc_certificate.as_dict())
        if not expand:
            certificate.unset_fields_except(['uuid',
                                             'certtype',
                                             'issuer',
                                             'signature',
                                             'details',
                                             'start_date',
                                             'expiry_date'])

        # insert details for this certificate if they exist
        certificate = _insert_certificate_details(certificate)

        certificate.links = \
            [link.Link.make_link('self', pecan.request.host_url,
                                 'certificates', certificate.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'certificates', certificate.uuid,
                                 bookmark=True)]

        return certificate


class CertificateCollection(collection.Collection):
    """API representation of a collection of certificates."""

    certificates = [Certificate]
    "A list containing certificate objects"

    def __init__(self, **kwargs):
        self._type = 'certificates'

    @classmethod
    def convert_with_links(cls, rpc_certificates, limit, url=None,
                           expand=False, **kwargs):
        collection = CertificateCollection()
        collection.certificates = [Certificate.convert_with_links(p, expand)
                                   for p in rpc_certificates]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############

def _check_certificate_data(certificate):

    if not utils.get_https_enabled():
        raise wsme.exc.ClientSideError(
            _("Cannot configure Certificate without HTTPS mode being enabled"))

    return certificate


def _insert_certificate_details(certificate):
    if not certificate:
        return

    if certificate.certtype == constants.CERT_MODE_TPM:
        try:
            tpmconfig = pecan.request.dbapi.tpmconfig_get_one()
        except exception.NotFound:
            return certificate

        tpmdevices = pecan.request.dbapi.tpmdevice_get_list()
        certificate.details = {}
        states = {}
        for device in tpmdevices:
            # extract the state info per host
            ihost = pecan.request.dbapi.ihost_get(device['host_id'])
            if ihost:
                states[ihost.hostname] = device.state
        if tpmdevices:
            certificate.details['state'] = states
            if tpmconfig.updated_at:
                certificate.details['updated_at'] = \
                    tpmconfig.updated_at.isoformat()

    return certificate


LOCK_NAME = 'CertificateController'


class CertificateController(rest.RestController):
    """REST controller for certificates."""

    _custom_actions = {'certificate_install': ['POST']}

    def __init__(self):
        self._api_token = None

    @wsme_pecan.wsexpose(Certificate, types.uuid)
    def get_one(self, certificate_uuid):
        """Retrieve information about the given certificate."""

        try:
            sp_certificate = objects.certificate.get_by_uuid(
                pecan.request.context,
                certificate_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No certificate found for %s" % certificate_uuid))

        return Certificate.convert_with_links(sp_certificate)

    def _get_certificates_collection(self, uuid, marker, limit,
                                     sort_key, sort_dir, expand=False,
                                     resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.certificate.get_by_uuid(pecan.request.context,
                                                         marker)

        certificates = pecan.request.dbapi.certificate_get_list(
            limit,
            marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir)

        certificates_c = CertificateCollection.convert_with_links(
            certificates, limit,
            url=resource_url,
            expand=expand,
            sort_key=sort_key,
            sort_dir=sort_dir)
        return certificates_c

    @wsme_pecan.wsexpose(CertificateCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of certificates. """
        return self._get_certificates_collection(uuid, marker, limit,
                                                 sort_key, sort_dir)

    @staticmethod
    def _check_cert_validity(cert):
        """Perform checks on validity of certificate
        """
        now = datetime.datetime.utcnow()
        msg = ("certificate is not valid before %s nor after %s" %
               (cert.not_valid_before, cert.not_valid_after))
        LOG.info(msg)
        if now <= cert.not_valid_before or now >= cert.not_valid_after:
            msg = ("certificate is not valid before %s nor after %s" %
                   (cert.not_valid_before, cert.not_valid_after))
            LOG.info(msg)
            return msg
        return True
        # Check that the CN is not Empty

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def certificate_install(self):
        """Install the certificate.

           Certificates are installed according to one of the following modes:
               default: install certificate for ssl
               tpm_mode: install certificate to tpm devices for ssl
               murano: install certificate for rabbit-murano
               murano_ca: install ca certificate for rabbit-murano
        """

        log_start = cutils.timestamped("certificate_do_post_start")

        fileitem = pecan.request.POST['file']
        passphrase = pecan.request.POST.get('passphrase')
        mode = pecan.request.POST.get('mode')

        certificate_file = pecan.request.POST.get('certificate_file')
        # Ensure that the certificate_file is a valid file path
        if os.path.isabs(certificate_file):
            if not os.path.isfile(certificate_file):
                msg = "'certificate_file' is not a valid file path"
                LOG.info(msg)
                return dict(success="", error=msg)

        LOG.info("certificate %s mode=%s" % (log_start, mode))

        if mode and mode not in constants.CERT_MODES_SUPPORTED:
            msg = "Invalid mode: %s" % mode
            LOG.info(msg)
            return dict(success="", error=msg)
        elif not mode:
            # Default certificate install is non-tpm SSL
            mode = constants.CERT_MODE_SSL

        system = pecan.request.dbapi.isystem_get_one()
        capabilities = system.capabilities

        if not mode.startswith(constants.CERT_MODE_MURANO):
            system_https_enabled = capabilities.get('https_enabled', False)
            if system_https_enabled is False or system_https_enabled == 'n':
                msg = "No certificates have been added, https is not enabled."
                LOG.info(msg)
                return dict(success="", error=msg)

        if not fileitem.filename:
            return dict(success="", error="Error: No file uploaded")
        try:
            fileitem.file.seek(0, os.SEEK_SET)
            pem_contents = fileitem.file.read()
        except Exception as e:
            return dict(
                success="",
                error=("No certificates have been added, "
                       "invalid PEM document: %s" % e))

        # Extract the certificate from the pem file
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        msg = self._check_cert_validity(cert)
        if msg is not True:
            return dict(success="", error=msg)

        if mode == constants.CERT_MODE_TPM:
            try:
                tpm = pecan.request.dbapi.tpmconfig_get_one()
            except exception.NotFound:
                tpm = None
                pass

            if tpm:
                tpmdevices = pecan.request.dbapi.tpmdevice_get_list()
                # if any of the tpm devices are in APPLYING state
                # then disallow a modification until previous config
                # either applies or fails
                for device in tpmdevices:
                    if device.state == constants.TPMCONFIG_APPLYING:
                        msg = ("TPM Device %s is still in APPLYING state. "
                               "Wait for the configuration to finish "
                               "before attempting a modification." %
                               device.uuid)
                        LOG.info(msg)
                        return dict(success="", error=msg)

        try:
            config_dict = {'passphrase': passphrase,
                           'mode': mode,
                           'certificate_file': certificate_file,
                           }
            signature = pecan.request.rpcapi.config_certificate(
                pecan.request.context,
                pem_contents,
                config_dict)

        except Exception as e:
            msg = "Exception occured e={}".format(e)
            LOG.info(msg)
            return dict(success="", error=e.value, body="", certificates={})

        # Update with installed certificate information
        values = {
            'certtype': mode,
            # TODO(jkung) 'issuer': cert.issuer,
            'signature': signature,
            'start_date': cert.not_valid_before,
            'expiry_date': cert.not_valid_after,
        }
        LOG.info("config_certificate values=%s" % values)

        if mode in [constants.CERT_MODE_SSL, constants.CERT_MODE_TPM]:
            if mode == constants.CERT_MODE_SSL:
                remove_certtype = constants.CERT_MODE_TPM
            else:
                remove_certtype = constants.CERT_MODE_SSL
            try:
                remove_certificate = \
                    pecan.request.dbapi.certificate_get_by_certtype(
                        remove_certtype)
                LOG.info("remove certificate certtype=%s uuid`=%s" %
                         (remove_certtype, remove_certificate.uuid))
                pecan.request.dbapi.certificate_destroy(
                    remove_certificate.uuid)
            except exception.CertificateTypeNotFound:
                pass

        try:
            certificate = \
                pecan.request.dbapi.certificate_get_by_certtype(
                    mode)
            certificate = \
                pecan.request.dbapi.certificate_update(certificate.uuid,
                                                       values)
        except exception.CertificateTypeNotFound:
            certificate = pecan.request.dbapi.certificate_create(values)
            pass

        sp_certificates_dict = certificate.as_dict()

        LOG.debug("certificate_install sp_certificates={}".format(
            sp_certificates_dict))

        log_end = cutils.timestamped("certificate_do_post_end")
        LOG.info("certificate %s" % log_end)

        return dict(success="", error="", body="",
                    certificates=sp_certificates_dict)
