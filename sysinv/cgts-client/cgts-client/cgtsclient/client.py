#
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from keystoneauth1 import loading
from oslo_utils import importutils

from cgtsclient._i18n import _
from cgtsclient import exc


SERVICE_NAME = 'sysinv'
SERVICE_TYPE = 'platform'


def _make_session(**kwargs):
    """Construct a session based on authentication information

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
        * timeout: request timeout (in seconds)
        * ca_file: trusted CA file
        * cert_file: client certificate file
        * key_file: client key file
    """
    session = None
    if (kwargs.get('os_username') and
        kwargs.get('os_password') and
        kwargs.get('os_auth_url') and
        (kwargs.get('os_project_id') or
         kwargs.get('os_project_name'))):
        auth_kwargs = {}
        auth_url = kwargs.get('os_auth_url')
        project_id = kwargs.get('os_project_id')
        project_name = kwargs.get('os_project_name')
        user_domain_id = kwargs.get('os_user_domain_id')
        user_domain_name = kwargs.get('os_user_domain_name') or "Default"
        project_domain_id = kwargs.get('os_project_domain_id')
        project_domain_name = kwargs.get('os_project_domain_name') or "Default"
        # todo(abailey): we can enhance this to also support token
        auth_type = 'password'
        username = kwargs.get('os_username')
        password = kwargs.get('os_password')
        auth_kwargs.update({
            'auth_url': auth_url,
            'project_id': project_id,
            'project_name': project_name,
            'user_domain_id': user_domain_id,
            'user_domain_name': user_domain_name,
            'project_domain_id': project_domain_id,
            'project_domain_name': project_domain_name,
            'username': username,
            'password': password
        })

        # construct the appropriate session
        timeout = kwargs.get('timeout')
        insecure = kwargs.get('insecure')
        cacert = kwargs.get('ca_file')
        cert = kwargs.get('cert_file')
        key = kwargs.get('key_file')

        loader = loading.get_plugin_loader(auth_type)
        auth_plugin = loader.load_from_options(**auth_kwargs)
        session = loading.session.Session().load_from_options(auth=auth_plugin,
                                                              timeout=timeout,
                                                              insecure=insecure,
                                                              cacert=cacert,
                                                              cert=cert,
                                                              key=key)
    # session could still be None
    return session


def get_client(api_version, session=None, service_type=SERVICE_TYPE, **kwargs):
    """Get an authenticated client, based on credentials in the keyword args.

    :param api_version: the API version to use ('1' or '2')
    :param session: the session to use (if it exists)
    :param service_type: service_type should always be 'platform'
    :param kwargs: additional keyword args to pass to the client or auth
    """

    endpoint = kwargs.get('system_url')

    if endpoint:
        api_version_str = '/v' + api_version
        if api_version_str not in endpoint.split('/'):
            endpoint += api_version_str

    auth_token = kwargs.get('os_auth_token')
    # if we have an endpoint and token, use those
    if endpoint and auth_token:
        pass
    elif not session:
        # Make a session to determine the endpoint
        session = _make_session(**kwargs)

    if not endpoint:
        exception_msg = _('Must provide Keystone credentials or '
                          'user-defined endpoint and token')
        if session:
            try:
                # todo(abailey): add support for non 'os_' keys
                interface = kwargs.get('os_endpoint_type')
                region_name = kwargs.get('os_region_name')
                endpoint = session.get_endpoint(service_type=service_type,
                                                interface=interface,
                                                region_name=region_name)
            except Exception as e:
                raise exc.EndpointException(
                    _('%(message)s, error was: %(error)s') %
                    {'message': exception_msg, 'error': e})
        else:
            raise exc.AmbigiousAuthSystem(exception_msg)

    if session:
        # this will be a LegacyJsonAdapter
        cli_kwargs = {
            'session': session,
            'service_type': service_type,
            'service_name': SERVICE_NAME,
            'interface': kwargs.get('os_endpoint_type'),
            'region_name': kwargs.get('os_region_name'),
            'endpoint_override': endpoint,
            'global_request_id': kwargs.get('global_request_id'),
            'user_agent': kwargs.get('user_agent', 'cgtsclient')
        }
    else:
        # This will become a httplib2 object
        auth_ref = None
        cli_kwargs = {
            'token': auth_token,
            'insecure': kwargs.get('insecure'),
            'cacert': kwargs.get('cacert'),
            'timeout': kwargs.get('timeout'),
            'ca_file': kwargs.get('ca_file'),
            'cert_file': kwargs.get('cert_file'),
            'key_file': kwargs.get('key_file'),
            'auth_ref': auth_ref,
            'auth_url': kwargs.get('os_auth_url'),
        }
    return Client(api_version, endpoint, session, **cli_kwargs)


def Client(version, *args, **kwargs):
    module = importutils.import_versioned_module('cgtsclient',
                                                 version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(*args, **kwargs)
