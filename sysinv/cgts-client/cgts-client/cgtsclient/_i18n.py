#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""oslo.i18n integration module.

See https://docs.openstack.org/oslo.i18n/latest/user/usage.html

"""

import oslo_i18n

DOMAIN = 'python-cgtsclient'

_translators = oslo_i18n.TranslatorFactory(domain=DOMAIN)

# The primary translation function using the well-known name "_"
_ = _translators.primary

# The contextual translation function using the name "_C"
# requires oslo.i18n >=2.1.0
_C = _translators.contextual_form

# The plural translation function using the name "_P"
# requires oslo.i18n >=2.1.0
_P = _translators.plural_form


def get_available_languages():
    return oslo_i18n.get_available_languages(DOMAIN)
