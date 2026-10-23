"""Input capture and cache identity regressions; native coverage is opt-in."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from eaos.backend import Backend


class InputIntegrity(unittest.TestCase):
    def test_replacement_after_open_cannot_change_captured_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'selected'
            target.write_bytes(b'original bytes')
            backend = Backend(str(target))
            target.write_bytes(b'replacement bytes')
            self.assertEqual(backend.snapshot.read_bytes(), b'original bytes')
            self.assertEqual(backend.digest, hashlib.sha256(b'original bytes').hexdigest())
            self.assertEqual(backend.evidence.target_sha256, backend.digest)
            backend.close()

    def test_corrupted_snapshot_is_rejected_without_overwriting_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'selected'
            target.write_bytes(b'original')
            first = Backend(str(target))
            first.snapshot.chmod(0o644)
            first.snapshot.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'snapshot is corrupt'):
                Backend(str(target))
            self.assertEqual(first.snapshot.read_bytes(), b'changed')
            first.close()

    def test_bundled_executable_is_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bundle in ['Example.app', 'Helper.framework', 'Widget.APPEX']:
                macos = Path(tmp) / bundle / 'Contents' / 'MacOS'
                macos.mkdir(parents=True)
                target = macos / 'Example'
                target.write_bytes(b'never executed')
                linked = Path(tmp) / ('link-' + bundle)
                linked.symlink_to(target)
                for path in (target, linked):
                    with self.assertRaisesRegex(ValueError, 'inside the bundle.*Copy the executable'):
                        Backend(str(path))
                self.assertEqual(sorted(p.name for p in macos.iterdir()), ['Example'])
                self.assertEqual(target.read_bytes(), b'never executed')

    def test_bundle_cli_refusal_handles_shell_metacharacters_without_command_advice(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'Example "quoted" $(printf unsafe) `whoami`.app' / 'Contents' / 'MacOS'
            folder.mkdir(parents=True)
            target = folder / 'Example'
            target.write_bytes(b'never executed')
            result = subprocess.run(
                [sys.executable, '-m', 'eaos.cli', 'call', str(target), 'open_program'],
                capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('Traceback', result.stderr)
            self.assertIn(str(target.resolve()), result.stderr)
            self.assertIn('then open that copy with EAOS', result.stderr)
            self.assertNotIn('mkdir ', result.stderr)
            self.assertNotIn('cp ', result.stderr)
            self.assertEqual(list(folder.iterdir()), [target])
            self.assertEqual(target.read_bytes(), b'never executed')

    def test_ordinary_folder_named_like_contents_is_still_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'apps' / 'Contents' / 'MacOS'
            folder.mkdir(parents=True)
            target = folder / 'Example'
            target.write_bytes(b'bytes')
            Backend(str(target)).close()
            self.assertTrue((folder / 'eaos-analysis').is_dir())

    def test_failed_native_load_releases_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'selected'
            target.write_bytes(b'bytes')
            backend = Backend(str(target))
            with patch.object(backend, '_load_project', side_effect=RuntimeError('failed')):
                with self.assertRaisesRegex(RuntimeError, 'failed'):
                    backend._load()
            self.assertIsNone(backend.lock)


@unittest.skipUnless(os.environ.get('EAOS_NATIVE_TESTS') == '1', 'requires existing managed Java/Ghidra')
class NativeIntegrity(unittest.TestCase):
    def test_snapshot_and_mismatched_cache_with_real_ghidra(self):
        with tempfile.TemporaryDirectory(prefix='eaos-native-') as tmp:
            root = Path(tmp)
            binaries = []
            for name, value in [('original', 11), ('replacement', 29)]:
                source = root / (name + '.c')
                source.write_text(f'int audit_value(void){{return {value};}}\nint main(void){{return audit_value();}}\n')
                binary = root / name
                subprocess.run(['clang', '-O0', str(source), '-o', str(binary)], check=True)
                binaries.append(binary)
            target = root / 'selected'
            shutil.copyfile(binaries[0], target)
            backend = Backend(str(target))
            shutil.copyfile(binaries[1], target)
            try:
                opened = backend.open_program()
                self.assertEqual(str(backend.program.getExecutableSHA256()).lower(), backend.digest)
                self.assertEqual(opened['data']['sha256'], hashlib.sha256(binaries[0].read_bytes()).hexdigest())
            finally:
                backend.close()
            # Reproduce the 0.1.0 poisoned cache by putting a real replacement
            # project into the original digest directory. Never modify originals.
            replacement = Backend(str(target))
            try:
                replacement.open_program()
            finally:
                replacement.close()
            shutil.rmtree(backend.directory / 'ghidra')
            shutil.copytree(replacement.directory / 'ghidra', backend.directory / 'ghidra')
            shutil.copyfile(binaries[0], target)
            reopened = Backend(str(target))
            with self.assertRaisesRegex(RuntimeError, 'hash does not match'):
                reopened.open_program()
            self.assertIsNone(reopened.lock)
            self.assertIsNone(reopened.program)
            self.assertTrue((backend.directory / 'ghidra').exists())


if __name__ == '__main__':
    unittest.main()
