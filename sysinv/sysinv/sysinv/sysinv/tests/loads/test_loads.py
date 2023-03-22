import mock

from stevedore import extension
from sysinv.common import exception
from sysinv.loads.loads import LoadImport
from sysinv.tests import base


class TestLoadImport(base.TestCase):
    def setUp(self):
        super(TestLoadImport, self).setUp()

        self.base_class = mock.MagicMock()

        extensions = [
            extension.Extension(
                "load_plugin",
                None,
                None,
                self.base_class,
            )
        ]

        mock_mgr = extension.ExtensionManager.make_test_instance(
            extensions=extensions,
            namespace="systemconfig.loads_plugins",
            propagate_map_exceptions=True,
        )

        extension_patch = mock.patch("sysinv.loads.loads.extension")
        mock_extension_manager = extension_patch.start()
        mock_extension_manager.ExtensionManager.return_value = mock_mgr
        self.addCleanup(extension_patch.stop)

    def test_extract_files(self):
        LoadImport.extract_files("1.0")

        self.base_class.extract_files.assert_called()

    def test_extract_files_exception(self):
        def extract_files(load_version):
            raise exception.SysinvException("error")

        self.base_class.extract_files = extract_files

        self.assertRaises(
            exception.SysinvException,
            LoadImport.extract_files,
            "1.0"
        )
