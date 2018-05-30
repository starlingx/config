#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Manager Interactions
"""

import log

from Crypto.Hash import MD5
from configutilities.common import crypt

import json


LOG = log.get_logger(__name__)


class UserList(object):
    """
    User List
    """
    def __init__(self, user_data, hash_string):
        # Decrypt the data using input hash_string to generate
        # the key
        h = MD5.new()
        h.update(hash_string)
        encryption_key = h.hexdigest()
        user_data_decrypted = crypt.urlsafe_decrypt(encryption_key,
                                                    user_data)

        self._data = json.loads(user_data_decrypted)

    def get_password(self, name):
        """
        Search the users for the password
        """
        for user in self._data:
            if user['name'] == name:
                return user['password']
        return None
