#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Logging
"""

import logging
import logging.handlers

_loggers = {}


def get_logger(name):
    """ Get a logger or create one  """

    if name not in _loggers:
        _loggers[name] = logging.getLogger(name)

    return _loggers[name]


def setup_logger(logger):
    """ Setup a logger """

    # Send logs to /var/log/platform.log
    syslog_facility = logging.handlers.SysLogHandler.LOG_LOCAL1

    formatter = logging.Formatter("configassistant[%(process)d] " +
                                  "%(pathname)s:%(lineno)s " +
                                  "%(levelname)8s [%(name)s] %(message)s")

    handler = logging.handlers.SysLogHandler(address='/dev/log',
                                             facility=syslog_facility)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def configure():
    """ Setup logging """

    for logger in _loggers:
        setup_logger(_loggers[logger])
