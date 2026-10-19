"""Installed-package storage, setup dispatch and download failure boundaries."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from eaos import cli, runtime


class InstalledRuntime(unittest.TestCase):
    def test_installed_package_uses_user_storage_not_site_packages(self):
        with patch.dict(os.environ, {'EAOS_RUNTIME_DIR':''}), \
             patch.object(runtime, '__file__', '/isolated/lib/python3.13/site-packages/eaos/runtime.py'), \
             patch.object(Path, 'home', return_value=Path('/user')):
            self.assertEqual(runtime.runtime_directory(),
                             Path('/user/Library/Application Support/Every App Is Open Source/runtimes'))

    def test_missing_setup_is_actionable_and_does_not_download(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(os.environ, {'EAOS_RUNTIME_DIR':tmp}), \
             patch.object(runtime.urllib.request, 'urlopen') as network:
            with self.assertRaisesRegex(RuntimeError, 'Run eaos setup first'):
                runtime.configure()
            network.assert_not_called()

    def test_unsupported_setup_rejects_before_writes_or_network(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.dict(os.environ, {'EAOS_RUNTIME_DIR':str(Path(tmp)/'absent')}), \
             patch.object(runtime.platform,'system',return_value='Linux'), \
             patch.object(runtime.urllib.request,'urlopen') as network:
            with self.assertRaisesRegex(RuntimeError, 'Only Apple Silicon'):
                runtime.install()
            self.assertFalse((Path(tmp)/'absent').exists())
            network.assert_not_called()

    def test_setup_dispatch_does_not_open_a_target(self):
        with patch('sys.argv',['eaos','setup']), patch.object(runtime,'install') as install, \
             patch.object(cli,'Backend') as backend:
            cli.main()
            install.assert_called_once_with(False, None)
            backend.assert_not_called()

    def test_setup_failure_returns_nonzero_without_traceback(self):
        with patch('sys.argv',['eaos','setup']), \
             patch.object(runtime,'install',side_effect=RuntimeError('checksum mismatch')), \
             contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as stopped:
                cli.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn('EAOS setup failed: checksum mismatch', error.getvalue())

    def test_failed_demangler_rebuild_keeps_existing_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools = Path(tmp)
            ghidra = tools/'ghidra'
            output = ghidra/'GPL/DemanglerGnu/os/mac_arm_64'/runtime.GNU_DEMANGLERS[0]
            output.parent.mkdir(parents=True)
            output.write_bytes(b'previous working helper')
            with patch.object(runtime.subprocess, 'run',
                              side_effect=subprocess.CalledProcessError(1, 'clang')):
                with self.assertRaises(subprocess.CalledProcessError):
                    runtime.build_demanglers(ghidra, tools, rebuild=True)
            self.assertEqual(output.read_bytes(), b'previous working helper')
            self.assertFalse(output.with_name('.eaos-'+output.name).exists())
