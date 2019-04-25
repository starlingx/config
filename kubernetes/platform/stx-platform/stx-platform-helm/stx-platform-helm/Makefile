#
# Copyright 2017 The Openstack-Helm Authors.
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# It's necessary to set this because some environments don't link sh -> bash.
SHELL := /bin/bash
TASK  := build

EXCLUDES := helm-toolkit doc tests tools logs tmp
CHARTS := helm-toolkit $(filter-out $(EXCLUDES), $(patsubst %/.,%,$(wildcard */.)))

.PHONY: $(EXCLUDES) $(CHARTS)

all: $(CHARTS)

$(CHARTS):
	@if [ -d $@ ]; then \
		echo; \
		echo "===== Processing [$@] chart ====="; \
		make $(TASK)-$@; \
	fi

init-%:
	if [ -f $*/Makefile ]; then make -C $*; fi
	if [ -f $*/requirements.yaml ]; then helm dep up $*; fi

lint-%: init-%
	if [ -d $* ]; then helm lint $*; fi

build-%: lint-%
	if [ -d $* ]; then helm package $*; fi

clean:
	@echo "Clean all build artifacts"
	rm -f */templates/_partials.tpl */templates/_globals.tpl
	rm -f *tgz */charts/*tgz */requirements.lock
	rm -rf */charts */tmpcharts

%:
	@:
