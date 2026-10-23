"""Release boundary checks against real locally built candidates."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('distribution_check', ROOT/'scripts/check_distribution.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
ARTIFACTS = Path(os.environ.get('EAOS_DISTRIBUTION_DIR',str(ROOT/'dist')))


@unittest.skipUnless(list(ARTIFACTS.glob('*.whl')), 'build local candidates first')
class DistributionBoundary(unittest.TestCase):
    def test_actual_candidates_have_no_private_material(self):
        result = checker.inspect(ARTIFACTS)
        self.assertEqual(len(result['artifacts']), 2)
        self.assertFalse(result['uploaded'])

    def test_injected_answer_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for path in ARTIFACTS.iterdir():
                if path.suffix == '.whl' or path.name.endswith('.tar.gz'):
                    shutil.copy2(path, directory/path.name)
            wheel = next(directory.glob('*.whl'))
            with zipfile.ZipFile(wheel, 'a') as archive:
                archive.writestr('private/oracle.json', '{"secret":"do not ship"}')
            with self.assertRaisesRegex(ValueError, 'Unexpected wheel member'):
                checker.inspect(directory)

    def test_missing_or_changed_runtime_modules_are_rejected(self):
        for mode in ('missing','changed'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp)
                for path in ARTIFACTS.iterdir():
                    if path.name.endswith('.tar.gz'):shutil.copy2(path,directory/path.name)
                source=next(ARTIFACTS.glob('*.whl'))
                with zipfile.ZipFile(source) as original,zipfile.ZipFile(directory/source.name,'w') as altered:
                    for info in original.infolist():
                        if mode=='missing' and info.filename=='eaos/function_discovery.py':continue
                        raw=original.read(info.filename)
                        if mode=='changed' and info.filename=='eaos/backend.py':raw+=b'\n# changed after review\n'
                        altered.writestr(info,raw)
                with self.assertRaisesRegex(ValueError,'missing code|differs from reviewed source'):
                    checker.inspect(directory)

    def test_traversal_paths_are_rejected(self):
        for name in ['../oracle.json', '/private/oracle.json', 'eaos/../../oracle', 'eaos\\oracle']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                checker.safe_path(name)
