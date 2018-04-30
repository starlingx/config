#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from coverage import Coverage
import os
import signal

flag_file = "/etc/coverage/sysinv/flag"
cov = None


def signal_handler(signum, frame):
    cov.stop()
    cov.save()


def register_handler(signum=signal.SIGUSR1):
    signal.signal(signum, signal_handler)


def flag_file_exists():
    return os.path.isfile(flag_file)


def start():
    global cov
    cov = Coverage(config_file=flag_file)
    register_handler()
    cov.erase()
    cov.start()
