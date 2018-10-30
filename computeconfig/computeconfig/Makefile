#
# SPDX-License-Identifier: Apache-2.0
#

INITDDIR ?= /etc/init.d/
GOENABLEDDIR ?= /etc/goenabled.d/
SYSTEMDDIR ?= /etc/systemd/system/

install:
	install -d -m 755 $(INITDDIR)
	install -d -m 755 $(GOENABLEDDIR)
	install -d -m 755 $(SYSTEMDDIR)
	install -d -m 755 $(SYSTEMDDIR)/config
	install -p -D -m 700 compute_config $(INITDDIR)/compute_config
	install -p -D -m 700 compute_services $(INITDDIR)/compute_services
	install -p -D -m 755 config_goenabled_check.sh $(GOENABLEDDIR)/config_goenabled_check.sh
	install -p -D -m 664 computeconfig.service $(SYSTEMDDIR)/config/computeconfig-standalone.service
	install -p -D -m 664 computeconfig-combined.service $(SYSTEMDDIR)/config/computeconfig-combined.service
