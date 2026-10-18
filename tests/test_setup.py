"""Installer failure boundaries; no network or real runtime installs."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('eaos_setup',Path(__file__).resolve().parents[1]/'scripts/setup.py')
setup=importlib.util.module_from_spec(spec);spec.loader.exec_module(setup)

def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


class Installer(unittest.TestCase):
    def test_checksum_rejects_same_length_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'runtime';path.write_bytes(b'bad')
            with self.assertRaisesRegex(RuntimeError,'integrity'):setup.verify_archive(path,pin(b'yes'))

    def test_unsupported_platform_does_not_download_or_create_tools(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(setup,'ROOT',Path(tmp)),patch.object(setup.platform,'system',return_value='Linux'),patch.object(setup.urllib.request,'urlopen') as network:
            with self.assertRaisesRegex(RuntimeError,'Only Apple Silicon'):setup.install()
            network.assert_not_called();self.assertFalse((Path(tmp)/'.tools').exists())

    def test_failed_download_keeps_existing_archive_and_removes_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'runtime';path.write_bytes(b'previous good archive')
            response=io.BytesIO(b'corrupt')
            with patch.object(setup.urllib.request,'urlopen',return_value=response):
                with self.assertRaisesRegex(RuntimeError,'integrity'):setup.download('https://example.invalid',path,pin(b'expected'))
            self.assertEqual(path.read_bytes(),b'previous good archive')
            self.assertEqual(list(Path(tmp).glob('*.part')),[])

    def test_download_verifies_before_promoting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'runtime';raw=b'verified runtime'
            with patch.object(setup.urllib.request,'urlopen',return_value=io.BytesIO(raw)):
                setup.download('https://example.invalid',path,pin(raw))
            self.assertEqual(path.read_bytes(),raw);self.assertEqual(list(Path(tmp).glob('*.part')),[])

    def test_failed_unpack_does_not_leave_a_runtime_that_rerun_would_trust(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);tools=root/'tools';tools.mkdir();archive=root/'jdk.tar.gz'
            with tarfile.open(archive,'w:gz') as out:
                info=tarfile.TarInfo(setup.JDK+'/wrong-file');info.size=1;out.addfile(info,io.BytesIO(b'x'))
            with self.assertRaisesRegex(RuntimeError,'missing'):setup.unpack(archive,tools,setup.JDK)
            self.assertFalse((tools/setup.JDK).exists());self.assertEqual(list(tools.iterdir()),[])
            with tarfile.open(archive,'w:gz') as out:
                info=tarfile.TarInfo(setup.JDK+'/Contents/Home/bin/java');info.size=1;out.addfile(info,io.BytesIO(b'x'))
            setup.unpack(archive,tools,setup.JDK)
            self.assertTrue((tools/setup.JDK/'Contents/Home/bin/java').is_file())
            with self.assertRaisesRegex(RuntimeError,'existing runtime'):setup.unpack(archive,tools,setup.JDK)


if __name__=='__main__':unittest.main()
