#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class BaseLoadImport(object):

    @abc.abstractmethod
    def extract_files(self, load_version):
        """Extract files from the importing load.

        :param load_version: A string containing the load version
        :returns: None
        """
