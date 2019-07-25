# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import fixtures
import keyring


class TestKeyring(keyring.backend.KeyringBackend):
    """A faked keyring for testing."""
    def __init__(self):
        self.passwords = {}

    def supported(self):
        return 0

    def get_password(self, service, username):
        try:
            return self.passwords[(service, username)]
        except KeyError:
            return None

    def set_password(self, service, username, password):
        self.passwords[(service, username)] = password
        return 0

    def delete_password(self, service, username):
        try:
            del self.passwords[(service, username)]
        except KeyError:
            raise keyring.errors.PasswordDeleteError("not set")


class KeyringBackend(fixtures.Fixture):
    """Fixture to create and set keyring backend."""

    def setUp(self):
        super(KeyringBackend, self).setUp()
        keyring.set_keyring(TestKeyring())
