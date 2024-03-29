import mock
import subprocess

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.loads.extract_files import ExtractFiles
from sysinv.tests import base


class TestExtractFiles(base.TestCase):
    def setUp(self):
        super(TestExtractFiles, self).setUp()

        subprocess_patch = mock.patch("sysinv.common.utils.subprocess")
        self.mock_subprocess = subprocess_patch.start()
        self.mock_subprocess.return_value = mock.MagicMock()
        self.addCleanup(subprocess_patch.stop)

        os_patch = \
            mock.patch("sysinv.loads.extract_files.os", mock.MagicMock())
        self.mock_os = os_patch.start()
        self.addCleanup(os_patch.stop)

        self.plugin = ExtractFiles()


@mock.patch.object(utils, "get_os_target", lambda x: constants.OS_CENTOS)
class TestExtractFilesCentos(TestExtractFiles):
    def setUp(self):
        super(TestExtractFilesCentos, self).setUp()

        utils_patch = \
            mock.patch("sysinv.common.utils.os", mock.MagicMock())
        self.mock_utils_patch = utils_patch.start()
        self.mock_utils_patch.listdir.return_value = ["playbookconfig"]
        self.addCleanup(utils_patch.stop)

        shutil_patch = \
            mock.patch("sysinv.loads.extract_files.shutil", mock.MagicMock())
        self.mock_shutil = shutil_patch.start()
        self.addCleanup(shutil_patch.stop)

    def test_extract_files_centos(self):
        self.plugin.extract_files("1.0")

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_shutil.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)

    def test_extract_files_centos_without_playbook_pkg(self):
        self.mock_utils_patch.listdir.return_value = []

        self.assertRaises(
            exception.SysinvException,
            self.plugin.extract_files,
            "1.0"
        )

        self.assertTrue(self.mock_os.method_calls)
        self.assertFalse(self.mock_shutil.method_calls)
        self.assertFalse(self.mock_subprocess.method_calls)

    def test_extract_files_centos_subprocess_error(self):
        self.mock_subprocess.CalledProcessError = \
            subprocess.CalledProcessError

        self.mock_subprocess.run.side_effect = \
            subprocess.CalledProcessError(1, "")

        self.assertRaises(
            exception.SysinvException,
            self.plugin.extract_files,
            "1.0"
        )

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)
        self.assertFalse(self.mock_shutil.method_calls)


@mock.patch.object(utils, "get_os_target", lambda x: constants.OS_DEBIAN)
class TestExtractFilesDebian(TestExtractFiles):
    def test_extract_files_debian(self):
        refs = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout="starlingx",
            stderr=None,
        )

        commit = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout="""
            commit c1bb601e1dc78b4a1ad7b687badd16edeb5ca59e28413902d1b3
            ContentChecksum:  4aacd1c71b056f8e28a8be27c508f21f62afba955
            Date:  2022-12-18 18:55:09 +0000

            Commit-id: starlingx-intel-x86-64-20221218185325
            """,
            stderr=None,
        )

        result = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout=None,
            stderr=None,
        )

        self.mock_subprocess.run.side_effect = [
            refs,
            commit,
            result,
        ]

        self.plugin.extract_files("1.0")

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)

    def test_extract_files_debian_without_commit(self):
        refs = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout="",
            stderr=None,
        )

        commit = subprocess.CompletedProcess(
            args="",
            returncode=1,
            stdout="Usage: ostree log [OPTION...] REF",
            stderr=None,
        )

        self.mock_subprocess.run.side_effect = [
            refs,
            commit,
        ]

        self.assertRaises(
            exception.SysinvException,
            self.plugin.extract_files,
            "1.0",
        )

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)

    def test_extract_files_debian_get_commit_error(self):
        self.mock_subprocess.CalledProcessError = \
            subprocess.CalledProcessError

        self.mock_subprocess.run.side_effect = \
            subprocess.CalledProcessError(1, "Generic error")

        self.assertRaises(
            exception.SysinvException,
            self.plugin.extract_files,
            "1.0",
        )

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)

    def test_extract_files_debian_checkout_commit_error(self):
        refs = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout="starlingx",
            stderr=None,
        )

        commit = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout="""
            commit c1bb601e1dc78b4a1ad7b687badd16edeb5ca59e28413902d1b3
            ContentChecksum:  4aacd1c71b056f8e28a8be27c508f21f62afba955
            Date:  2022-12-18 18:55:09 +0000

            Commit-id: starlingx-intel-x86-64-20221218185325
            """,
            stderr=None,
        )

        self.mock_subprocess.run.side_effect = [
            refs,
            commit,
            subprocess.CalledProcessError(1, "error: Invalid refspec"),
        ]

        self.mock_subprocess.CalledProcessError = \
            subprocess.CalledProcessError

        self.assertRaises(
            exception.SysinvException,
            self.plugin.extract_files,
            "1.0",
        )

        self.assertTrue(self.mock_os.method_calls)
        self.assertTrue(self.mock_subprocess.method_calls)
