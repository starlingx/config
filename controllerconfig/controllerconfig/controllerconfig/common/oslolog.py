#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""
Oslo Logging configuration
"""

from oslo_config import cfg
from oslo_log import log as logging
from controllerconfig.common import constants


def setup_logger():
    """ Setup a logger """

    # set in cfg what the valid syslog options are
    logging.register_options(cfg.CONF)
    # Send logs to /var/log/platform.log by overriding defaults
    # to use syslog to local1
    cfg.CONF.set_override("use_syslog", True)
    cfg.CONF.set_override("syslog_log_facility", constants.LOG_LOCAL1)

    logging.setup(cfg.CONF, 'controllerconfig')


def configure():
    """ Setup logging """
    setup_logger()
