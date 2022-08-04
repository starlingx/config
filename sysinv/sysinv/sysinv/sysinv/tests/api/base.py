# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""Base classes for API tests."""

from oslo_config import cfg
import os.path
import mock
import pecan
import pecan.testing

from sysinv.api import acl
from sysinv.db import api as dbapi
from sysinv.tests import base
from sysinv.common import context as sysinv_context
from sysinv.common import utils as cutils


PATH_PREFIX = '/v1'
DEBUG_PRINTING = False


class FunctionalTest(base.TestCase):
    """Used for functional tests of Pecan controllers where you need to
    test your literal application and its integration with the
    framework.
    """

    SOURCE_DATA = {'test_source': {'somekey': '666'}}

    # @mock.patch('sysinv.common.utils.synchronized',
    #             side_effect=lambda a: lambda f: lambda *args: f(*args))
    def setUp(self):
        super(FunctionalTest, self).setUp()
        cfg.CONF.set_override("auth_version", "v2.0", group=acl.OPT_GROUP_NAME)
        self.app = self._make_app()
        self.dbapi = dbapi.get_instance()
        self.context = sysinv_context.RequestContext(is_admin=True)
        p = mock.patch.object(cutils, 'synchronized')
        p.start()
        self.addCleanup(p.stop)

    def _make_app(self, enable_acl=False):
        # Determine where we are so we can set up paths in the config
        root_dir = self.path_get()

        # pecan warns: `static_root` is only used when `debug` is True
        # which is set by CONF.debug
        cfg.CONF.set_override("debug", True)
        self.config = {
            'app': {
                'root': 'sysinv.api.controllers.root.RootController',
                'modules': ['sysinv.api'],
                'static_root': '%s/public' % root_dir,
                'template_path': '%s/api/templates' % root_dir,
                'enable_acl': enable_acl,
                'acl_public_routes': ['/', '/v1'],
            },
        }
        os.path.isdir = mock.Mock(return_value=True)
        return pecan.testing.load_test_app(self.config)

    def tearDown(self):
        super(FunctionalTest, self).tearDown()
        pecan.set_config({}, overwrite=True)
        # self.context.session.remove()

    def post_json(self, path, params, expect_errors=False, headers=None,
                  method="post", extra_environ=None, status=None,
                  path_prefix=PATH_PREFIX):
        full_path = path_prefix + path
        if DEBUG_PRINTING:
            print('%s: %s %s' % (method.upper(), full_path, params))
        response = getattr(self.app, "%s_json" % method)(
            str(full_path),
            params=params,
            headers=headers,
            status=status,
            extra_environ=extra_environ,
            expect_errors=expect_errors
        )
        if DEBUG_PRINTING:
            print('GOT:%s' % response)
        return response

    def post_with_files(self, path, params, upload_files, expect_errors=False,
                        headers=None, method="post", extra_environ=None,
                        status=None, path_prefix=PATH_PREFIX):
        full_path = path_prefix + path
        if DEBUG_PRINTING:
            print('%s: %s %s' % (method.upper(), full_path, params))
        response = getattr(self.app, "%s" % method)(
            str(full_path),
            params,
            upload_files=upload_files,
            headers=headers,
            status=status,
            extra_environ=extra_environ,
            expect_errors=expect_errors
        )
        if DEBUG_PRINTING:
            print('GOT:%s' % response)
        return response

    def put_json(self, *args, **kwargs):
        kwargs['method'] = 'put'
        return self.post_json(*args, **kwargs)

    def patch_json(self, *args, **kwargs):
        kwargs['method'] = 'patch'
        return self.post_json(*args, **kwargs)

    def patch_dict_json(self, path, expect_errors=False, headers=None, **kwargs):
        newargs = {}
        newargs['method'] = 'patch'
        patch = []
        for key, value in kwargs.items():
            pathkey = '/' + key
            patch.append({'op': 'replace', 'path': pathkey, 'value': value})
        newargs['params'] = patch
        return self.post_json(path, expect_errors=expect_errors,
                              headers=headers, **newargs)

    def patch_dict(self, path, data, expect_errors=False, headers=None):
        params = []
        for key, value in data.items():
            pathkey = '/' + key
            params.append({'op': 'replace', 'path': pathkey, 'value': value})
        return self.post_json(path, expect_errors=expect_errors, params=params,
                              method='patch', headers=headers)

    def delete(self, path, expect_errors=False, headers=None,
               extra_environ=None, status=None, path_prefix=PATH_PREFIX):
        full_path = path_prefix + path
        if DEBUG_PRINTING:
            print('DELETE: %s' % (full_path))
        response = self.app.delete(str(full_path),
                                   headers=headers,
                                   status=status,
                                   extra_environ=extra_environ,
                                   expect_errors=expect_errors)
        if DEBUG_PRINTING:
            print('GOT: %s' % response)
        return response

    def get_json(self, path, expect_errors=False, headers=None,
                 extra_environ=None, q=None, path_prefix=PATH_PREFIX, **params):
        if q is None:
            q = []
        full_path = path_prefix + path
        query_params = {'q.field': [],
                        'q.value': [],
                        'q.op': [],
                        }
        for query in q:
            for name in ['field', 'op', 'value']:
                query_params['q.%s' % name].append(query.get(name, ''))
        all_params = {}
        all_params.update(params)
        if q:
            all_params.update(query_params)
        if DEBUG_PRINTING:
            print('GET: %s %r' % (full_path, all_params))
        response = self.app.get(full_path,
                                params=all_params,
                                headers=headers,
                                extra_environ=extra_environ,
                                expect_errors=expect_errors)
        if not expect_errors:
            response = response.json
        if DEBUG_PRINTING:
            print('GOT:%s' % response)
        return response
