#
# SPDX-License-Identifier: Apache-2.0
#

SBINDIR ?= /usr/sbin
SYSTEMDDIR ?= /usr/lib/systemd/system/

install:
	install -d -m 755 $(SBINDIR)
	install -d -m 755 $(SYSTEMDDIR)
	install -p -D -m 555 wait_for_config_init.sh $(SBINDIR)/wait_for_config_init.sh
	install -p -D -m 555 wait_for_compute_config_init.sh $(SBINDIR)/wait_for_compute_config_init.sh
	install -p -D -m 444 config.service $(SYSTEMDDIR)/config.service
	install -p -D -m 444 compute-config-gate.service $(SYSTEMDDIR)/compute-config-gate.service
