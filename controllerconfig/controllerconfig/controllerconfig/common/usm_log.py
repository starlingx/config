#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import configparser
import logging
import os
import sys

from controllerconfig.common import constants

LOG = logging.getLogger('main_logger')

logging_default_format_string = None
software_conf_mtime = 0
software_conf = '/etc/software/software.conf'


def configure_logging(filename=constants.USM_LOG_FILE, log_level=logging.INFO):
    read_log_config()

    my_exec = os.path.basename(sys.argv[0])

    log_format = logging_default_format_string
    log_format = log_format.replace('%(exec)s', my_exec)
    formatter = logging.Formatter(log_format, datefmt="%FT%T")

    LOG.setLevel(log_level)
    main_log_handler = logging.FileHandler(filename)
    main_log_handler.setFormatter(formatter)
    LOG.addHandler(main_log_handler)


def read_log_config():
    global software_conf_mtime  # pylint: disable=global-statement
    global software_conf  # pylint: disable=global-statement

    if software_conf_mtime == os.stat(software_conf).st_mtime:
        # The file has not changed since it was last read
        return

    global logging_default_format_string  # pylint: disable=global-statement

    config = configparser.ConfigParser(interpolation=None)

    config.read(software_conf)
    software_conf_mtime = os.stat(software_conf).st_mtime
    # TODO(lbonatti) Remove this constants.LOG_DEFAULT_FORMAT when
    #  logging_default_format_string is present in stx11, when this
    #  becomes the N release.
    logging_default_format_string = config.get(
        "DEFAULT", "logging_default_format_string",
        fallback=constants.LOG_DEFAULT_FORMAT
    )
