#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from eventlet.green import subprocess
import os
import shutil
from grp import getgrnam
from pwd import getpwnam

from oslo_config import cfg
from oslo_log import log as logging
from sysinv._i18n import _
from sysinv.common import exception

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

fernet_group = cfg.OptGroup(
    'fernet_repo',
    title='fernet repo Options',
    help="Configuration options for the fernet key repository")

fernet_opts = [
    cfg.StrOpt('key_repository',
               default='/etc/keystone/fernet-keys',
               help="The fernet key repository."),
]

CONF.register_group(fernet_group)
CONF.register_opts(fernet_opts, group=fernet_group)

KEYSTONE_USER = 'keystone'
KEYSTONE_GROUP = 'keystone'


class FernetOperator(object):
    """Class to encapsulate Fernet Key operations for System Inventory"""

    def __init__(self, keystone_user_id=None, keystone_group_id=None):
        self.key_repository = CONF.fernet_repo.key_repository
        self.keystone_user_id = keystone_user_id
        self.keystone_group_id = keystone_group_id

    def _set_user_group(self):
        if self.keystone_user_id is None:
            self.keystone_user_id = getpwnam(KEYSTONE_USER).pw_uid

        if self.keystone_group_id is None:
            self.keystone_group_id = getgrnam(KEYSTONE_GROUP).gr_gid

    def _check_key_directory(self):
        """Check if the key directory exists and attempt to create it if it
           doesn't.
        """
        if not os.access(self.key_repository, os.F_OK):
            LOG.info(_("key_repository:(%s) does not exist; attempting to "
                     "create it") % self.key_repository)
            try:
                os.makedirs(self.key_repository, 0o700)
            except OSError:
                LOG.error(_("Failed to create key_repository"))
                return False

            self._set_user_group()
            os.chown(self.key_repository, self.keystone_user_id,
                     self.keystone_group_id)
        return True

    def _create_key_file(self, id, key):
        """Create a tmp key file."""

        self._set_user_group()
        old_umask = os.umask(0o177)
        old_egid = os.getegid()
        old_euid = os.geteuid()
        os.setegid(self.keystone_group_id)
        os.seteuid(self.keystone_user_id)

        temp_key_file = os.path.join(self.key_repository, str(id) + '.tmp')
        real_key_file = os.path.join(self.key_repository, str(id))
        create = False
        try:
            with open(temp_key_file, 'w') as f:
                f.write(key)
                f.flush()
                create = True
        except IOError:
            LOG.error(_('Failed to create new temporary key: %s',
                        temp_key_file))
            raise
        finally:
            # restore the umask, user and group identifiers
            os.umask(old_umask)
            os.seteuid(old_euid)
            os.setegid(old_egid)
            if not create and os.access(temp_key_file, os.F_OK):
                os.remove(temp_key_file)
                return False

        os.rename(temp_key_file, real_key_file)
        LOG.debug('Created a new key: %s', real_key_file)
        return True

    def _get_key_files(self):
        # read the list of key files
        key_files = dict()
        for filename in os.listdir(self.key_repository):
            path = os.path.join(self.key_repository, str(filename))
            if os.path.isfile(path):
                try:
                    key_id = int(filename)
                except ValueError:
                    pass
                else:
                    key_files[key_id] = path
        return key_files

    def _validate_key_repository(self):
        """Validate permissions on the key repository directory."""

        # ensure current user has sufficient access to the key repository
        is_valid = os.access(self.key_repository, os.R_OK)

        if not is_valid:
            LOG.error(_("Either (%s) key_repository does not exist or we "
                      "don't have sufficient permission to access it." %
                        self.key_repository))
        return is_valid

    def update_fernet_keys(self, new_keys):
        new_key_ids = []

        if not self._check_key_directory():
            raise exception.SysinvException(_(
                "Error checking key repository."))

        try:
            for key in new_keys:
                self._create_key_file(key['id'], key['key'])
                new_key_ids.append(key['id'])

            # remove excess keys
            key_files = self._get_key_files()
            for key in key_files.keys():
                if key not in new_key_ids:
                    key_to_purge = key_files[key]
                    LOG.info('Purge excess key: %s', key_to_purge)
                    os.remove(key_to_purge)
        except Exception as e:
            msg = _("Failed to update fernet keys: %s") % e.message
            LOG.exception(msg)
            raise exception.SysinvException(msg)

    def reset_fernet_keys(self):
        try:
            if os.path.isdir(self.key_repository):
                LOG.info("Remove fernet repo")
                shutil.rmtree(self.key_repository)
        except OSError as e:
            LOG.exception(e)

        with open(os.devnull, "w") as fnull:
            try:
                LOG.info("Re-setup fernet repo")
                subprocess.check_call(['/usr/bin/keystone-manage',  # pylint: disable=not-callable
                                       'fernet_setup',
                                       '--keystone-user',
                                       KEYSTONE_USER,
                                       '--keystone-group',
                                       KEYSTONE_GROUP],
                                      stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError as e:
                msg = _("Failed to setup fernet keys: %s") % e.message
                LOG.exception(msg)
                raise exception.SysinvException(msg)

    def get_fernet_keys(self, key_id=None):
        keys = []
        if not self._validate_key_repository():
            return keys

        key_files = self._get_key_files()
        for k, v in key_files.items():
            key = dict()
            key['id'] = k
            with open(v, 'r') as key_file:
                key['key'] = key_file.read()
                keys.append(key)
                if key_id is not None and key_id == k:
                    break
        return keys
