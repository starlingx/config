# Copyright (c) 2016-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
from sysinv.common import constants


class ServiceConfig(object):
    def __init__(self, db_params=None):
        self.feature_enabled = False
        self.cache_enabled = False
        self.params = {}
        self.uuid = {}
        if db_params is not None:
            for p in db_params:
                if p.name == constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED:
                    self.feature_enabled = (p.value.lower() == 'true')
                elif p.name == constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED:
                    self.cache_enabled = (p.value.lower() == 'true')
                else:
                    self.params[p.name] = p.value
                self.uuid[p.name] = p.uuid

    def __repr__(self):
        return ("ServiceConfig({}={}, {}={}, params={}, uuid={})").format(
            constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED, self.feature_enabled,
            constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED, self.cache_enabled,
            self.params, self.uuid)

    def __eq__(self, other):
        return (self.feature_enabled == other.feature_enabled and
                self.cache_enabled == other.cache_enabled and
                self.params == other.params)

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self):
        return {constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED: self.feature_enabled,
                constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED: self.cache_enabled,
                'params': copy.deepcopy(self.params),
                'uuid': copy.deepcopy(self.uuid)}

    @classmethod
    def from_dict(cls, data):
        try:
            sp = cls()
            sp.feature_enabled = data[constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED]
            sp.cache_enabled = data[constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED]
            sp.params = copy.deepcopy(data['params'])
            sp.uuid = copy.deepcopy(data['uuid'])
            return sp
        except (KeyError, TypeError):
            pass
        return
