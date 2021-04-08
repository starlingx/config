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
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
from oslo_config import cfg
from oslo_log import log as logging
from sysinv.fpga_agent.reset_n3000_fpgas import reset_n3000_fpgas

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def main():
    logging.register_options(CONF)
    CONF(project='sysinv', prog='reset-n3000-fpgas')

    logging.set_defaults()
    logging.setup(cfg.CONF, 'reset-n3000-fpgas')

    if reset_n3000_fpgas():
        exit(0)
    else:
        exit(1)


if __name__ == '__main__':
    main()
