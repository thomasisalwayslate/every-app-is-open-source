#!/usr/bin/env python3
"""Verified, checkout-local setup. Entry point: ./install.sh [--rebuild]."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from eaos import runtime
from eaos.runtime import GHIDRA, JDK, BUILD_ARGS, digest, verify_archive, download, archive_url, unpack


def prerequisites():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('Only Apple Silicon macOS is currently supported; no runtime downloads were started.')
    if platform.python_version() != (ROOT/'.python-version').read_text().strip():
        raise RuntimeError('Use ./install.sh to select the pinned Python version.')
    if not shutil.which('uv'):
        raise RuntimeError('uv is required on PATH.')
    subprocess.run(['/usr/bin/xcode-select','-p'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    for tool in ['make','clang++']:
        subprocess.run(['/usr/bin/xcrun','--find',tool],stdout=subprocess.DEVNULL,check=True)


def install(rebuild=False, archive_cache=None):
    prerequisites()
    tools = ROOT/'.tools';tools.mkdir(exist_ok=True)
    import fcntl
    with (tools/'setup.lock').open('a+') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another installation is running in this checkout') from None
        return install_locked(tools,rebuild,archive_cache)


def install_locked(tools, rebuild, archive_cache):
    native_report = runtime.install_locked(tools, rebuild, archive_cache)
    print('Installing the locked Python environment…',flush=True)
    env = {**os.environ,'UV_PROJECT_ENVIRONMENT':str(ROOT/'.venv')}
    subprocess.run(['uv','--no-config','sync','--frozen','--no-dev','--python',sys.executable],cwd=ROOT,env=env,check=True)
    python = ROOT/'.venv/bin/python'
    check_python = subprocess.check_output([str(python),'-I','-c',
        'import json,platform,eaos;from importlib.metadata import version;print(json.dumps({"python":platform.python_version(),"pyghidra":version("pyghidra")}))'],text=True)
    versions = json.loads(check_python)
    if versions != {'python':(ROOT/'.python-version').read_text().strip(),'pyghidra':'3.1.0'}:
        raise RuntimeError('Installed Python dependencies do not match the pins')
    report = {**native_report, **versions, 'lock_sha256':digest(ROOT/'uv.lock')}
    (tools/'setup.json').write_text(json.dumps(report,indent=2)+'\n')
    print('\nInstalled. No shell profile or agent configuration was changed.',flush=True)
    print('Analyze: '+shlex.quote(str(ROOT/'eaos'))+' call /absolute/path/to/program open_program',flush=True)
    print('MCP command: '+shlex.quote(str(ROOT/'eaos'))+' mcp /absolute/path/to/program',flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rebuild',action='store_true',help='Rebuild the ARM64 decompiler')
    parser.add_argument('--archive-cache',type=Path,help='Read-only directory with verified ghidra.zip and jdk.tar.gz; otherwise download them')
    args = parser.parse_args()
    try:
        install(args.rebuild,args.archive_cache.expanduser().resolve() if args.archive_cache else None)
    except (RuntimeError,OSError,subprocess.CalledProcessError) as exc:
        raise SystemExit(f'EAOS installation failed: {exc}') from exc


if __name__ == '__main__':main()
