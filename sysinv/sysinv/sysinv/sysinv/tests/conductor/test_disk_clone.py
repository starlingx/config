# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""Test class for disk clone GPT format skip logic in ConductorManager."""

import mock

from oslo_context import context
from sysinv.common import constants
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.tests.db import base
from sysinv.tests.db import utils


class TestDiskCloneGptSkip(base.BaseHostTestCase):
    """Tests for skipping GPT formatting on cloned installs."""

    def setUp(self):
        super(TestDiskCloneGptSkip, self).setUp()
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()

        # Create a test host
        self.ihost = self._create_test_host(
            personality=constants.CONTROLLER,
            administrative=constants.ADMIN_UNLOCKED,
            rootfs_device='/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0')

    def _create_test_host(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        ihost_dict = utils.get_test_ihost(**kwargs)
        if 'id' not in kwargs:
            del ihost_dict['id']
        return self.service.dbapi.ihost_create(ihost_dict)

    def _create_disk(self, **kwargs):
        defaults = {
            'forihostid': self.ihost['id'],
            'device_node': '/dev/sdb',
            'device_path': '/dev/disk/by-path/pci-0000:04:00.0-nvme-1',
            'serial_id': 'SOURCE_SERIAL_123',
            'device_type': 'NVME',
        }
        defaults.update(kwargs)
        disk = utils.get_test_idisk(**defaults)
        if 'id' not in kwargs:
            del disk['id']
        if 'foripvid' not in kwargs:
            del disk['foripvid']
        if 'foristorid' not in kwargs:
            del disk['foristorid']
        return self.service.dbapi.idisk_create(disk['forihostid'], disk)

    def _make_agent_disk_dict(self, disk, serial_id=None):
        """Create a dict as the agent would report for a disk."""
        return {
            'device_node': disk.device_node,
            'device_path': disk.device_path,
            'serial_id': serial_id or disk.serial_id,
            'device_type': disk.device_type,
            'device_num': disk.device_num,
            'available_mib': 1788000,
            'rpm': 'N/A',
            'capabilities': {},
        }

    @mock.patch.object(manager.ConductorManager, 'disk_format_gpt')
    @mock.patch('os.path.isfile')
    def test_clone_flag_skips_gpt_format(self, mock_isfile, mock_format_gpt):
        """Test .cloned_install flag prevents GPT format on mismatch."""
        # Create a disk in the DB with the source serial
        disk = self._create_disk(serial_id='SOURCE_SERIAL_123')

        # Agent reports a different serial (target hardware)
        agent_disk = self._make_agent_disk_dict(
            disk, serial_id='TARGET_SERIAL_456')

        # Simulate the .cloned_install flag being present
        mock_isfile.return_value = True

        self.service.idisk_update_by_ihost(
            self.context, self.ihost['uuid'], [agent_disk])

        # disk_format_gpt should NOT have been called
        mock_format_gpt.assert_not_called()

    @mock.patch.object(manager.ConductorManager, 'disk_format_gpt')
    def test_no_clone_flag_formats_gpt_on_serial_mismatch(
            self, mock_format_gpt):
        """Test without .cloned_install, mismatch triggers GPT format."""
        # Create a disk in the DB with the source serial
        disk = self._create_disk(serial_id='SOURCE_SERIAL_123')

        # Agent reports a different serial (target hardware)
        agent_disk = self._make_agent_disk_dict(
            disk, serial_id='TARGET_SERIAL_456')

        # Ensure .cloned_install does NOT exist
        with mock.patch('os.path.isfile', return_value=False):
            self.service.idisk_update_by_ihost(
                self.context, self.ihost['uuid'], [agent_disk])

        # disk_format_gpt SHOULD have been called
        mock_format_gpt.assert_called_once()

    @mock.patch.object(manager.ConductorManager, 'disk_format_gpt')
    def test_clone_iso_disk_sid_skips_gpt_format(self, mock_format_gpt):
        """Test CLONEISODISKSID_ marker in serial_id prevents GPT."""
        hostname = self.ihost['hostname']
        device_node = '/dev/sdb'

        # Create a disk with the clone marker as serial_id
        clone_serial = constants.CLONE_ISO_DISK_SID + hostname + device_node
        disk = self._create_disk(
            device_node=device_node,
            serial_id=clone_serial)

        # Agent reports the actual target serial
        agent_disk = self._make_agent_disk_dict(
            disk, serial_id='TARGET_SERIAL_456')

        # No .cloned_install flag needed for this path
        with mock.patch('os.path.isfile', return_value=False):
            self.service.idisk_update_by_ihost(
                self.context, self.ihost['uuid'], [agent_disk])

        # disk_format_gpt should NOT have been called
        mock_format_gpt.assert_not_called()

    @mock.patch.object(manager.ConductorManager, 'disk_format_gpt')
    def test_same_serial_no_gpt_format(self, mock_format_gpt):
        """Test that matching serials don't trigger GPT format."""
        disk = self._create_disk(serial_id='SAME_SERIAL_789')

        # Agent reports same serial - no mismatch
        agent_disk = self._make_agent_disk_dict(
            disk, serial_id='SAME_SERIAL_789')

        self.service.idisk_update_by_ihost(
            self.context, self.ihost['uuid'], [agent_disk])

        # No serial mismatch = no GPT format
        mock_format_gpt.assert_not_called()

    @mock.patch.object(manager.ConductorManager, 'disk_format_gpt')
    def test_root_disk_serial_mismatch_skips_gpt(self, mock_format_gpt):
        """Test root disk serial mismatch doesn't trigger GPT format."""
        # Create a disk at the rootfs device path
        disk = self._create_disk(
            serial_id='SOURCE_SERIAL_123',
            device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0')

        # Agent reports different serial
        agent_disk = self._make_agent_disk_dict(
            disk, serial_id='TARGET_SERIAL_456')

        with mock.patch('os.path.isfile', return_value=False):
            self.service.idisk_update_by_ihost(
                self.context, self.ihost['uuid'], [agent_disk])

        # Root disk should never be GPT formatted
        mock_format_gpt.assert_not_called()
