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
import ssl
import wsme
import wsmeext.pecan as wsme_pecan

from cryptography import x509
from pecan import expose
from pecan import rest

from oslo_log import log
from sysinv._i18n import _
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common.rpc.common import RemoteError
from wsme import types as wtypes

LOG = log.getLogger(__name__)


class CertificatePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class RequestResult(base.APIBase):
    result = wtypes.text
    message = wtypes.text


class RenewCertificate(base.APIBase):
    certtype = wtypes.text
    root_ca_crt = wtypes.text
    sc_ca_cert = wtypes.text
    sc_ca_key = wtypes.text


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
        self.fields = list(objects.certificate.fields.keys())
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

    _custom_actions = {'certificate_install': ['POST'],
                       'certificate_renew': ['POST']}

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
               docker_registry: install certificate for docker registry
               openstack: install certificate for openstack
               openstack_ca: install ca certificate for openstack
        """

        log_start = cutils.timestamped("certificate_do_post_start")

        fileitem = pecan.request.POST['file']
        passphrase = pecan.request.POST.get('passphrase')
        mode = pecan.request.POST.get('mode')

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

        standalone_certs = [constants.CERT_MODE_DOCKER_REGISTRY,
                            constants.CERT_MODE_SSL_CA]
        if mode not in standalone_certs:
            system_https_enabled = capabilities.get('https_enabled', False)
            if system_https_enabled is False or system_https_enabled == 'n':
                msg = "No certificates have been added, https is not enabled."
                LOG.info(msg)
                return dict(success="", error=msg)

        if mode.startswith(constants.CERT_MODE_OPENSTACK):
            try:
                pecan.request.dbapi.certificate_get_by_certtype(
                    constants.CERT_MODE_SSL)
            except exception.CertificateTypeNotFound:
                msg = "No openstack certificates have been added, " \
                      "platform SSL certificate is not installed."
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

        # Extract the certificates from the pem file
        try:
            certs = cutils.extract_certs_from_pem(pem_contents)
        except Exception as e:
            msg = "No certificates have been added, %s" % e
            return dict(success="", error=msg)

        if not certs:
            msg = "No certificates have been added, " \
                  "no valid certificates found in file."
            LOG.info(msg)
            return dict(success="", error=msg)

        hash_issuers = []
        for index, cert in enumerate(certs):
            msg = self._check_cert_validity(cert)
            if msg is not True:
                return dict(success="", error=msg)

            # validation checking for ssl, tpm_mode, docker_registry
            # and openstack certficcates
            if mode in [constants.CERT_MODE_SSL,
                        constants.CERT_MODE_TPM,
                        constants.CERT_MODE_DOCKER_REGISTRY,
                        constants.CERT_MODE_OPENSTACK,
                        ]:
                try:
                    hash_issuers.append(cutils.get_cert_issuer_hash(cert))
                    if index == 0:
                        if cutils.is_ca_cert(cert):
                            msg = "The first cert in the file should not be " \
                                  "a CA cert"
                            return dict(success="", error=msg)
                    else:
                        if not cutils.is_ca_cert(cert):
                            msg = "Number %s cert in the file should be a " \
                                  "CA cert" % (index + 1)
                            return dict(success="", error=msg)
                        hash_subject = cutils.get_cert_subject_hash(cert)
                        if hash_subject != hash_issuers[index - 1]:
                            msg = "Number %s cert in the file is not " \
                                  "signing cert of the preceding one. Check " \
                                  "certs order in the file." % (index + 1)
                            return dict(success="", error=msg)
                except Exception as e:
                    msg = "No certificates have been added, exception " \
                          "occured on cert %s: %s" % (index, e)
                    return dict(success="", error=msg)

            if mode == constants.CERT_MODE_OPENSTACK and index == 0:
                domain, msg = _check_endpoint_domain_exists()
                if domain:
                    msg = _check_cert_dns_name(cert, domain)
                    if msg is not True:
                        return dict(success="", error=msg.message)
                elif msg:
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
                           }
            inv_certs = pecan.request.rpcapi.config_certificate(
                pecan.request.context,
                pem_contents,
                config_dict)

        except RemoteError as e:
            msg = "Exception occurred e={}".format(e)
            LOG.warn(msg)
            return dict(success="", error=str(e.value), body="", certificates={})

        certificates = pecan.request.dbapi.certificate_get_list()
        # ssl and ssl_tpm certs are mutual exclusive, so
        # if the new cert is a SSL cert, delete the existing TPM cert as well
        # if the new cert is a TPM cert, delete the existing SSL cert as well
        for certificate in certificates:
            if (mode == constants.CERT_MODE_SSL
                    and certificate.certtype == constants.CERT_MODE_TPM) or \
                (mode == constants.CERT_MODE_TPM
                    and certificate.certtype == constants.CERT_MODE_SSL):
                pecan.request.dbapi.certificate_destroy(certificate.uuid)

        # Create new or update existing certificates in sysinv with the
        # information returned from conductor manager.
        certificate_dicts = []
        for inv_cert in inv_certs:
            # for ssl, tmp_mode, docker_registry and openstack certs, if the
            # cert is ICA signed cert (ie, the pem_contents contains
            # intermediate CA certs), skip these intermediate CA certs.
            if mode in [constants.CERT_MODE_SSL,
                        constants.CERT_MODE_TPM,
                        constants.CERT_MODE_DOCKER_REGISTRY,
                        constants.CERT_MODE_OPENSTACK] \
                    and inv_cert.get('is_ca', None):
                continue

            values = {
                'certtype': mode,
                'signature': inv_cert.get('signature'),
                'start_date': inv_cert.get('not_valid_before'),
                'expiry_date': inv_cert.get('not_valid_after'),
            }
            LOG.info("config_certificate values=%s" % values)

            # check to see if the installed cert exist in sysinv
            uuid = None
            for certificate in certificates:
                if mode == constants.CERT_MODE_SSL_CA:
                    if inv_cert.get('signature') == certificate.signature:
                        uuid = certificate.uuid
                        break
                else:
                    if mode == certificate.certtype:
                        uuid = certificate.uuid
                        break
            if uuid:
                certificate = pecan.request.dbapi.certificate_update(uuid,
                                                                     values)
            else:
                certificate = pecan.request.dbapi.certificate_create(values)
            certificate_dict = certificate.as_dict()
            LOG.debug("certificate_install certificate={}".format(
                certificate_dict))
            certificate_dicts.append(certificate_dict)

        log_end = cutils.timestamped("certificate_do_post_end")
        LOG.info("certificate %s" % log_end)

        return dict(success="", error="", body="",
                    certificates=certificate_dicts)

    @wsme_pecan.wsexpose(RequestResult, body=RenewCertificate)
    def certificate_renew(self, data):
        LOG.info('refresh_admin_endpoint_certificate %s' % data.certtype)
        if data.certtype == constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT:
            return self._update_admin_endpoint_cert(data)
        elif data.certtype == constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA:
            return self._update_inter_ca_cert(data)
        else:
            raise wsme.exc.ClientSideError(_("Not implemented"))

    @staticmethod
    def _update_admin_endpoint_cert(data):
        role = utils.get_distributed_cloud_role()
        if role not in [constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD,
                        constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER]:
            raise wsme.exc.ClientSideError(
                _("Update admin endpoint certificate is supported "
                  "in Distributed Cloud only"))

        pecan.request.rpcapi.update_admin_ep_certificate(
            pecan.request.context)

        res = RequestResult()
        res.result = 'OK'

        return res

    @staticmethod
    def _update_inter_ca_cert(data):
        role = utils.get_distributed_cloud_role()
        if role != constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            raise wsme.exc.ClientSideError(
                _("Update admin endpoint intermediate CA certificate is "
                  "supported on subclouds only"))

        if not utils.verify_ca_crt(data.root_ca_crt):
            raise wsme.exc.ClientSideError(
                _("Provided CA cert is invalid")
            )

        if not utils.verify_intermediate_ca_cert(
                data.root_ca_crt, data.sc_ca_cert):
            raise wsme.exc.ClientSideError(
                _("Provided intermediate CA cert is invalid")
            )

        pecan.request.rpcapi.update_intermediate_ca_certificate(
            pecan.request.context,
            data.root_ca_crt, data.sc_ca_cert, data.sc_ca_key)

        res = RequestResult()
        res.result = 'OK'

        return res

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Certificate, types.uuid, status_code=200)
    def delete(self, certificate_uuid):
        """Uninstall a certificate."""

        # Only support ssl_ca cert type
        log_start = cutils.timestamped("certificate_do_delete_start")

        try:
            certificate = pecan.request.dbapi.certificate_get(certificate_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No certificate found for %s" % certificate_uuid))

        if certificate and \
                certificate.certtype not in [constants.CERT_MODE_SSL_CA]:
            msg = "Unupported mode: {}".format(certificate.certtype)
            raise wsme.exc.ClientSideError(_(msg))

        LOG.info("certificate %s certificate_uuid=%s" %
                 (log_start, certificate_uuid))

        try:
            pecan.request.rpcapi.delete_certificate(pecan.request.context,
                                                    certificate.certtype,
                                                    certificate.signature)
        except RemoteError as e:
            msg = "Exception occurred e={}".format(e)
            LOG.warn(msg)
            raise wsme.exc.ClientSideError(
                _("Failed to delete the certificate: %s, %s" %
                  (certificate_uuid, str(e.value))))

        pecan.request.dbapi.certificate_destroy(certificate_uuid)

        log_end = cutils.timestamped("certificate_do_delete_end")
        LOG.info("certificate %s" % log_end)

        return Certificate.convert_with_links(certificate)


def _check_endpoint_domain_exists():
    # Check that public endpoint FQDN is configured
    endpoint_domain = None
    msg = None
    try:
        endpoint_domain = pecan.request.dbapi.service_parameter_get_one(
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN).value
    except exception.NotFound:
        msg = _("Service parameter for %s, %s, %s is not provisioned" % (
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN
        ))
        LOG.info(msg)
    return endpoint_domain, msg


def _check_cert_dns_name(cert, endpoint_domain):
    # Prepend the domain with any service name
    service_endpoint_domain = 'keystone.' + endpoint_domain

    # Check that the endpoint FQDN matches common name or
    # the dns names in the subject alternative name section of the certificate
    try:
        alt_names = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.extensions.ExtensionNotFound:
        alt_names = None
        pass

    if alt_names:
        dns_names = alt_names.value.get_values_for_type(x509.DNSName)
    if not alt_names or not dns_names:
        cn = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)[0].value
        LOG.debug("certificate has common name %s" % cn)
        cert_cn = {'subject': ((('commonName', cn),),)}
        try:
            ssl.match_hostname(cert_cn, service_endpoint_domain)
        except Exception as e:
            LOG.info("Failed to match CN: %s" % e)
            return e
    else:
        LOG.debug("Certificate contains subject alternative name %s" % dns_names)
        dns_list = []
        for name in dns_names:
            dns_list.append(('DNS', name))
        cert_san = {'subjectAltName': dns_list}
        try:
            ssl.match_hostname(cert_san, service_endpoint_domain)
        except Exception as e:
            LOG.info("Failed to match SAN: %s" % e)
            return e

    return True
