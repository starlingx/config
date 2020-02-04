#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient._i18n import _
from cgtsclient.common import utils
from cgtsclient import exc


def _get_ksclient(**kwargs):
    """Get an endpoint and auth token from Keystone.

    :param kwargs: keyword args containing credentials:
            * username: name of user
            * password: user's password
            * user_domain_name: User's domain name for authentication.
            * project_domain_name: Project's domain name for project
            * auth_url: endpoint to authenticate against
            * insecure: allow insecure SSL (no cert verification)
            * project_name: Project name for project scoping.
    """
    from keystoneclient.v3 import client as ksclient
    return ksclient.Client(username=kwargs.get('username'),
                           password=kwargs.get('password'),
                           user_domain_name=kwargs.get('user_domain_name'),
                           project_domain_name=kwargs.get('project_domain_name'),
                           project_name=kwargs.get('project_name'),
                           auth_url=kwargs.get('auth_url'),
                           insecure=kwargs.get('insecure'),
                           cacert=kwargs.get('os_cacert'))


def _get_sm_endpoint(client, **kwargs):
    """Get an endpoint for smapi using the provided keystone client."""
    return client.auth_ref.service_catalog.url_for(
        service_type=kwargs.get('service_name') or 'smapi',
        endpoint_type=kwargs.get('endpoint_type') or 'public',
        region_name=kwargs.get('os_region_name') or 'RegionOne')


def _get_endpoint(client, **kwargs):
    """Get an endpoint using the provided keystone client."""
    return client.auth_ref.service_catalog.url_for(
        service_type=kwargs.get('service_type') or 'platform',
        endpoint_type=kwargs.get('endpoint_type') or 'public',
        region_name=kwargs.get('os_region_name') or 'RegionOne')


def get_client(api_version, **kwargs):
    """Get an authenticated client, based on the credentials
       in the keyword args.

    :param api_version: the API version to use ('1' or '2')
    :param kwargs: keyword args containing credentials, either:
            * os_auth_token: pre-existing token to re-use
            * system_url: system API endpoint
            or:
            * os_username: name of user
            * os_password: user's password
            * os_auth_url: endpoint to authenticate against
            * insecure: allow insecure SSL (no cert verification)
            * os_tenant_{name|id}: name or ID of tenant
            * os_region_name: region of the service
            * os_project_name: name of a project
            * os_project_id: ID of a project
            * os_user_domain_name: name of a domain the user belongs to
            * os_user_domain_id: ID of a domain the user belongs to
            * os_project_domain_name: name of a domain the project belongs to
            * os_project_domain_id: ID of a domain the project belongs to
    """
    if kwargs.get('os_auth_token') and kwargs.get('system_url'):
        token = kwargs.get('os_auth_token')
        endpoint = kwargs.get('system_url')
        auth_ref = None
    elif (kwargs.get('os_username') and
          kwargs.get('os_password') and
          kwargs.get('os_auth_url') and
          (kwargs.get('os_project_id') or kwargs.get('os_project_name'))):

        ks_kwargs = {
            'username': kwargs.get('os_username'),
            'password': kwargs.get('os_password'),
            'project_id': kwargs.get('os_project_id'),
            'project_name': kwargs.get('os_project_name'),
            'user_domain_id': kwargs.get('os_user_domain_id'),
            'user_domain_name': kwargs.get('os_user_domain_name'),
            'project_domain_id': kwargs.get('os_project_domain_id'),
            'project_domain_name': kwargs.get('os_project_domain_name'),
            'auth_url': kwargs.get('os_auth_url'),
            'service_type': kwargs.get('os_service_type'),
            'endpoint_type': kwargs.get('os_endpoint_type'),
            'insecure': kwargs.get('insecure'),
            'os_cacert': kwargs.get('ca_file')
        }
        _ksclient = _get_ksclient(**ks_kwargs)
        token = kwargs.get('os_auth_token') if kwargs.get('os_auth_token') else _ksclient.auth_ref.auth_token

        ep_kwargs = {
            'service_type': kwargs.get('os_service_type'),
            'endpoint_type': kwargs.get('os_endpoint_type'),
            'os_region_name': kwargs.get('os_region_name'),
        }
        endpoint = kwargs.get('system_url') or \
            _get_endpoint(_ksclient, **ep_kwargs)

        auth_ref = _ksclient.auth_ref

    else:
        e = (_('Must provide Keystone credentials or user-defined endpoint '
               'and token'))
        raise exc.AmbigiousAuthSystem(e)

    try:
        smapi_endpoint = _get_sm_endpoint(_ksclient, **ep_kwargs)
    except Exception:
        # Could be invoked during controller bootstrap where smapi
        # endpoint is not yet available.
        smapi_endpoint = None

    cli_kwargs = {
        'token': token,
        'insecure': kwargs.get('insecure'),
        'cacert': kwargs.get('cacert'),
        'timeout': kwargs.get('timeout'),
        'ca_file': kwargs.get('ca_file'),
        'cert_file': kwargs.get('cert_file'),
        'key_file': kwargs.get('key_file'),
        'auth_ref': auth_ref,
        'auth_url': kwargs.get('os_auth_url'),
        'smapi_endpoint': smapi_endpoint,
    }

    return Client(api_version, endpoint, **cli_kwargs)


def Client(version, *args, **kwargs):
    module = utils.import_versioned_module(version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(*args, **kwargs)
