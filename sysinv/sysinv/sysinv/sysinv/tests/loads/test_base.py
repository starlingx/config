from sysinv.tests import base
from sysinv.loads.base import BaseLoadImport


class ConcreteLoadImport(BaseLoadImport):
    def extract_files(self, load_version):
        return load_version


class TestBase(base.TestCase):
    def test_class_instance(self):
        load_import = ConcreteLoadImport()

        self.assertIsInstance(load_import, BaseLoadImport)
