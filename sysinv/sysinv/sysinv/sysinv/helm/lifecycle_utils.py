#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

import time

from oslo_log import log as logging
from oslo_serialization import base64
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.helm import common

LOG = logging.getLogger(__name__)


def _is_rbd_provisioner_required(app_op):
    """ Check if RBD provisioner is required

    :param app_op: AppOperator object

    """
    if StorageBackendConfig.has_backend(
            app_op._dbapi,
            constants.SB_TYPE_CEPH
    ):
        return True
    else:
        return False


# TODO(dvoicule) remove once each app has its lifecycle operator and takes care of its rbd
def _decoupling_app_has_rbd_actions(app):
    """ Temporary function for decoupling

    :param app: AppOperator.Application object

    """
    if app.name in [constants.HELM_APP_CERT_MANAGER,
                    constants.HELM_APP_OIDC_AUTH,
                    constants.HELM_APP_NGINX_IC]:
        return False

    return True


def create_rbd_provisioner_secrets(app_op, app, hook_info):
    """ Provide access to the system persistent RBD provisioner.

    The rbd-provisioner is installed as part of system provisioning and has
    created secrets for all common default namespaces. Copy the secret to
    this application's namespace(s) to provide resolution for PVCs

    :param app_op: AppOperator object
    :param app: AppOperator.Application object
    :param hook_info: LifecycleHookInfo object

    """
    if not _is_rbd_provisioner_required(app_op) or \
            not _decoupling_app_has_rbd_actions(app):
        return

    # Only set up a secret for the default storage pool (i.e. ignore
    # additional storage tiers)
    pool_secret = K8RbdProvisioner.get_user_secret_name({
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]})
    app_ns = app_op._helm.get_helm_application_namespaces(app.name)
    namespaces = \
        list(set([ns for ns_list in app_ns.values() for ns in ns_list]))
    for ns in namespaces:
        if (ns in [common.HELM_NS_HELM_TOOLKIT,
                   common.HELM_NS_RBD_PROVISIONER] or
                app_op._kube.kube_get_secret(pool_secret, ns) is not None):
            # Secret already exist
            continue

        try:
            if not app_op._kube.kube_get_namespace(ns):
                app_op._kube.kube_create_namespace(ns)
            app_op._kube.kube_copy_secret(
                pool_secret, common.HELM_NS_RBD_PROVISIONER, ns)
        except Exception as e:
            LOG.error(e)
            raise


def delete_rbd_provisioner_secrets(app_op, app, hook_info):
    """ Remove access to the system persistent RBD provisioner.

    As part of launching a supported application, secrets were created to
    allow access to the provisioner from the application namespaces. This
    will remove those created secrets.

    :param app_op: AppOperator object
    :param app: AppOperator.Application object
    :param hook_info: LifecycleHookInfo object

    """
    if not _is_rbd_provisioner_required(app_op) or \
            not _decoupling_app_has_rbd_actions(app):
        return

    # Only set up a secret for the default storage pool (i.e. ignore
    # additional storage tiers)
    pool_secret = K8RbdProvisioner.get_user_secret_name({
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]})
    app_ns = app_op._helm.get_helm_application_namespaces(app.name)
    namespaces = \
        list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

    for ns in namespaces:
        if (ns == common.HELM_NS_HELM_TOOLKIT or
                ns == common.HELM_NS_RBD_PROVISIONER):
            continue

        try:
            LOG.info("Deleting Secret %s under Namespace "
                     "%s ..." % (pool_secret, ns))
            app_op._kube.kube_delete_secret(
                pool_secret, ns, grace_period_seconds=0)
            LOG.info("Secret %s under Namespace %s delete "
                     "completed." % (pool_secret, ns))
        except Exception as e:
            LOG.error(e)
            raise


def delete_namespace(app_op, namespace):
    """Delete application specific resources.

    :param app_op: AppOperator object
    :param namespace:

    """
    loop_timeout = 1
    timeout = 300
    try:
        LOG.info("Deleting Namespace %s ..." % namespace)
        app_op._kube.kube_delete_namespace(namespace,
                                           grace_periods_seconds=0)

        # Namespace termination timeout 5 mins
        while loop_timeout <= timeout:
            if not app_op._kube.kube_get_namespace(namespace):
                # Namespace has been terminated
                break
            loop_timeout += 1
            time.sleep(1)

        if loop_timeout > timeout:
            raise exception.KubeNamespaceDeleteTimeout(name=namespace)
        LOG.info("Namespace %s delete completed." % namespace)
    except Exception as e:
        LOG.error(e)
        raise


def delete_persistent_volume_claim(app_op, namespace):
    """Delete application specific resources.

    :param app_op: AppOperator object
    :param namespace:

    """
    try:
        LOG.info("Deleting Persistent Volume Claim "
                 "under Namespace %s ..." % namespace)
        app_op._kube.kube_delete_persistent_volume_claim(namespace,
                                                         timeout_seconds=10)
        LOG.info("Persistent Volume Claim delete completed.")
    except Exception as e:
        LOG.error(e)
        raise


def delete_configmap(app_op, namespace, configmap):
    """Delete application specific resources.

    :param app_op: AppOperator object
    :param namespace:
    :param configmap:

    """
    try:
        LOG.info("Deleting ConfigMap %s"
                 "under Namespace %s ..." % (configmap, namespace))
        app_op._kube.kube_delete_config_map(
            configmap,
            namespace)
        LOG.info("ConfigMap delete completed.")
    except Exception as e:
        LOG.error(e)
        raise


def add_pod_security_admission_controller_labels(app_op, app, hook_info):
    """ adds labels to newly created namespaces

    Pod security admission controllers uses labels to enforce policies
    this method adds labels used by pod security admission controller
    this is needed because new applications can create new namespaces
    as they are deployed.

    :param app_op: AppOperator object
    :param app: AppOperator.Application object
    :param hook_info: LifecycleHookInfo object

    """
    app_ns = app_op._helm.get_helm_application_namespaces(app.name)

    namespaces = \
        list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

    for ns in namespaces:

        security_level = 'baseline'
        if ns in common.PRIVILEGED_NS:
            security_level = 'privileged'

        body = {
            "metadata": {
                "labels": {
                    "pod-security.kubernetes.io/enforce": security_level,
                    "pod-security.kubernetes.io/warn": security_level,
                    "pod-security.kubernetes.io/audit": security_level,
                    "pod-security.kubernetes.io/enforce-version": common.POD_SECURITY_VERSION,
                    "pod-security.kubernetes.io/warn-version": common.POD_SECURITY_VERSION,
                    "pod-security.kubernetes.io/audit-version": common.POD_SECURITY_VERSION}
            }
        }

        try:
            app_op._kube.kube_patch_namespace(ns, body)
        except Exception as e:
            LOG.error(e)
            raise


def create_local_registry_secrets(app_op, app, hook_info):
    # Temporary function to create default registry secret
    # which would be used by kubernetes to pull images from
    # local registry.
    # This should be removed after OSH supports the deployment
    # with registry has authentication turned on.
    # https://blueprints.launchpad.net/openstack-helm/+spec/
    # support-docker-registry-with-authentication-turned-on
    body = {
        'type': 'kubernetes.io/dockerconfigjson',
        'metadata': {},
        'data': {}
    }

    app_ns = app_op._helm.get_helm_application_namespaces(app.name)
    namespaces = \
        list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

    sysinv_registry_secret = app_op._kube.kube_get_secret(app_op.DOCKER_REGISTRY_SECRET,
                                                          common.HELM_NS_KUBE_SYSTEM)
    for ns in namespaces:
        if (ns == common.HELM_NS_HELM_TOOLKIT or
                app_op._kube.kube_get_secret(app_op.DOCKER_REGISTRY_SECRET, ns) is not None):
            # Secret already exist
            continue

        try:
            if sysinv_registry_secret is not None:
                # Use the sysinv token in default_registry_key secret in
                # kube-system namespace to create secret in another namespace.
                sysinv_registry_token = sysinv_registry_secret.data['.dockerconfigjson']
                body['data'].update({'.dockerconfigjson': sysinv_registry_token})
            else:
                # This must be the first platform app in the kube-system
                # namespace (i.e. nginx-ingress-controller app)
                local_registry_auth = cutils.get_local_docker_registry_auth()

                auth = '{0}:{1}'.format(local_registry_auth['username'],
                                        local_registry_auth['password'])
                token = '{{\"auths\": {{\"{0}\": {{\"auth\": \"{1}\"}}}}}}'.format(
                    constants.DOCKER_REGISTRY_SERVER, base64.encode_as_text(auth))
                body['data'].update({'.dockerconfigjson': base64.encode_as_text(token)})

            body['metadata'].update({'name': app_op.DOCKER_REGISTRY_SECRET,
                                     'namespace': ns})

            if not app_op._kube.kube_get_namespace(ns):
                app_op._kube.kube_create_namespace(ns)
            app_op._kube.kube_create_secret(ns, body)
            LOG.info("Secret %s created under Namespace %s." % (app_op.DOCKER_REGISTRY_SECRET, ns))
        except Exception as e:
            LOG.error(e)
            raise


def delete_local_registry_secrets(app_op, app, hook_info):
    app_ns = app_op._helm.get_helm_application_namespaces(app.name)
    namespaces = \
        list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

    for ns in namespaces:
        if ns in [common.HELM_NS_HELM_TOOLKIT, common.HELM_NS_KUBE_SYSTEM]:
            continue

        try:
            LOG.info("Deleting Secret %s under Namespace "
                     "%s ..." % (app_op.DOCKER_REGISTRY_SECRET, ns))
            app_op._kube.kube_delete_secret(
                app_op.DOCKER_REGISTRY_SECRET, ns, grace_period_seconds=0)
            LOG.info("Secret %s under Namespace %s delete "
                     "completed." % (app_op.DOCKER_REGISTRY_SECRET, ns))
        except Exception as e:
            LOG.error(e)
            raise
