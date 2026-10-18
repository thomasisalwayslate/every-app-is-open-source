"""Release boundary checks against real locally built candidates."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('distribution_check', ROOT/'scripts/check_distribution.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


@unittest.skipUnless(list((ROOT/'dist').glob('*.whl')), 'build local candidates first')
class DistributionBoundary(unittest.TestCase):
    def test_actual_candidates_have_no_private_material(self):
        result = checker.inspect(ROOT/'dist')
        self.assertEqual(len(result['artifacts']), 2)
        self.assertFalse(result['uploaded'])

    def test_injected_answer_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for path in (ROOT/'dist').iterdir():
                if path.suffix == '.whl' or path.name.endswith('.tar.gz'):
                    shutil.copy2(path, directory/path.name)
            wheel = next(directory.glob('*.whl'))
            with zipfile.ZipFile(wheel, 'a') as archive:
                archive.writestr('private/oracle.json', '{"secret":"do not ship"}')
            with self.assertRaisesRegex(ValueError, 'Unexpected wheel member'):
                checker.inspect(directory)

    def test_traversal_paths_are_rejected(self):
        for name in ['../oracle.json', '/private/oracle.json', 'eaos/../../oracle', 'eaos\\oracle']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                checker.safe_path(name)
