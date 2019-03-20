#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#

SBINDIR ?= /usr/sbin
SYSTEMDDIR ?= /usr/lib/systemd/system/

install:
	install -d -m 755 $(SBINDIR)
	install -d -m 755 $(SYSTEMDDIR)
	install -p -D -m 555 wait_for_config_init.sh $(SBINDIR)/wait_for_config_init.sh
	install -p -D -m 555 wait_for_worker_config_init.sh $(SBINDIR)/wait_for_worker_config_init.sh
	install -p -D -m 444 config.service $(SYSTEMDDIR)/config.service
	install -p -D -m 444 worker-config-gate.service $(SYSTEMDDIR)/worker-config-gate.service
