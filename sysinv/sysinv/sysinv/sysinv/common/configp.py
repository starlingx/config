#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from six.moves import configparser


# Configuration Global used by other modules to get access to the configuration
# specified in the config file.
CONFP = dict()


class Config(configparser.ConfigParser):
    """
    Override ConfigParser class to add dictionary functionality.
    """
    def as_dict(self):
        d = dict(self._sections)
        for key in d:
            d[key] = dict(self._defaults, **d[key])
            d[key].pop('__name__', None)
        return d


def load(config_file):
    """
    Load the configuration file into a global CONFP variable.
    """
    global CONFP

    if not CONFP:
        config = Config()
        config.read(config_file)
        CONFP = config.as_dict()
