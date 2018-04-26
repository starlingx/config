# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
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
