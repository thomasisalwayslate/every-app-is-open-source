import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('benchmark_prepare', ROOT / 'benchmark/prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def source_archive(name='chocolate/src/doom/p_pspr.c'):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        item = tarfile.TarInfo(name)
        item.size = 4
        tar.addfile(item, io.BytesIO(b'test'))
    return output.getvalue()


class BenchmarkPreparation(unittest.TestCase):
    def test_preparation_creates_missing_public_source_and_receipt(self):
        raw = source_archive()
        pin = {'url': 'https://example.invalid/source.tar.gz', 'sha256': hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(prepare.urllib.request, 'urlopen', return_value=io.BytesIO(raw)) as network:
                destination = prepare.prepare(root, pin)
            self.assertTrue((destination / 'chocolate/src/doom/p_pspr.c').is_file())
            self.assertEqual(json.loads((root / 'private/download.json').read_text()), pin)
            with patch.object(prepare.urllib.request, 'urlopen') as network:
                self.assertEqual(prepare.prepare(root, pin), destination)
                network.assert_not_called()

    def test_bad_digest_and_traversal_are_rejected_without_source(self):
        for raw, digest in [(source_archive(), '0' * 64), (source_archive('../escaped'), None)]:
            pin = {'url': 'https://example.invalid/source.tar.gz', 'sha256': digest or hashlib.sha256(raw).hexdigest()}
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with patch.object(prepare.urllib.request, 'urlopen', return_value=io.BytesIO(raw)):
                    with self.assertRaises((RuntimeError, tarfile.FilterError)):
                        prepare.prepare(root, pin)
                self.assertFalse((root / 'private/upstream').exists())
                self.assertFalse((root / 'escaped').exists())


if __name__ == '__main__':
    unittest.main()
