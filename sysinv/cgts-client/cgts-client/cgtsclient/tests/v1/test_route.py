#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import testtools
from unittest import mock

from cgtsclient.v1 import route

HOST = 'host-uuid'
URL = '/v1/ihosts/%s/routes' % HOST
IFACE = 'iface-uuid'
IF_URL = '/v1/iinterfaces/%s/routes' % IFACE


def _routes(first, last):
    return [{'uuid': 'uuid-%d' % i} for i in range(first, last + 1)]


class FakePagedAPI(object):
    """Emulates sysinv-api returning 'page_size' routes per response."""

    def __init__(self, total, page_size=2, url=URL):
        self.total = total
        self.page_size = page_size
        self.url = url
        self.urls = []

    def json_request(self, method, url, **kwargs):
        self.urls.append(url)
        start = 1
        if 'marker=uuid-' in url:
            start = int(url.split('marker=uuid-')[1]) + 1
        end = min(start + self.page_size - 1, self.total)
        body = {'routes': _routes(start, end) if start <= end else []}
        if len(body['routes']) == self.page_size:
            body['next'] = 'http://sysinv%s?marker=uuid-%d' % (self.url, end)
        return mock.Mock(), body


class RouteManagerPaginationTest(testtools.TestCase):

    def _uuids(self, routes):
        return [r.uuid for r in routes]

    def test_list_by_host_follows_all_pages(self):
        api = FakePagedAPI(total=5)
        routes = route.RouteManager(api).list_by_host(HOST)
        self.assertEqual(['uuid-%d' % i for i in range(1, 6)],
                         self._uuids(routes))
        self.assertEqual(3, len(api.urls))
        self.assertEqual(URL, api.urls[0])
        self.assertEqual(URL + '?marker=uuid-2', api.urls[1])

    def test_list_by_host_exact_multiple_of_page_size(self):
        # The server cannot tell the last page is full: one extra empty
        # request must end the loop without duplicating entries.
        api = FakePagedAPI(total=4)
        routes = route.RouteManager(api).list_by_host(HOST)
        self.assertEqual(4, len(routes))
        self.assertEqual(3, len(api.urls))

    def test_list_by_host_single_page(self):
        api = FakePagedAPI(total=1)
        routes = route.RouteManager(api).list_by_host(HOST)
        self.assertEqual(['uuid-1'], self._uuids(routes))
        self.assertEqual(1, len(api.urls))

    def test_list_by_host_empty(self):
        api = FakePagedAPI(total=0)
        self.assertEqual([], route.RouteManager(api).list_by_host(HOST))

    def test_list_by_interface_follows_all_pages(self):
        api = FakePagedAPI(total=5, url=IF_URL)
        routes = route.RouteManager(api).list_by_interface(IFACE)
        self.assertEqual(['uuid-%d' % i for i in range(1, 6)],
                         self._uuids(routes))
        self.assertEqual(3, len(api.urls))
        self.assertEqual(IF_URL, api.urls[0])
        self.assertEqual(IF_URL + '?marker=uuid-2', api.urls[1])
