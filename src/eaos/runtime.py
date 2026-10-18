"""Verified Java/Ghidra installation shared by wheels and checkout setup."""
from pathlib import Path
from importlib.resources import files
from importlib.metadata import version, PackageNotFoundError
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

GHIDRA = 'ghidra_12.1.4_PUBLIC'
JDK = 'jdk-21.0.12.1+1'
BUILD_ARGS = ['make','-B','-o','xml.cc','-o','grammar.cc','-o','pcodeparse.cc',
    '-o','slghparse.cc','-o','slghscan.cc','-j4','ghidra_opt',
    'CXX=clang++ -std=c++11','ARCH_TYPE=-arch arm64',
    'ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w']


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verify_archive(path, pin):
    if path.stat().st_size != pin['bytes'] or digest(path) != pin['sha256']:
        raise RuntimeError(f'Archive integrity check failed: {path}. Keep it for inspection; supply a valid archive before retrying.')


def download(url, destination, pin):
    """An interrupted or corrupt download never becomes the cached archive."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, suffix='.part', delete=False) as out:
            temporary = Path(out.name)
            request = urllib.request.Request(url, headers={'User-Agent':'EAOS-setup'})
            with urllib.request.urlopen(request, timeout=60) as response:
                shutil.copyfileobj(response, out, length=1024*1024)
        verify_archive(temporary, pin)
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def archive_url(name):
    if name == 'jdk.tar.gz':
        return 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz'
    request = urllib.request.Request(
        'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.4_build',
        headers={'User-Agent':'EAOS-setup'})
    with urllib.request.urlopen(request, timeout=60) as response:
        release = json.load(response)
    matches = [a['browser_download_url'] for a in release['assets']
        if a['name'].startswith(GHIDRA+'_') and a['name'].endswith('.zip')]
    if len(matches) != 1:
        raise RuntimeError('Pinned Ghidra release asset is missing or ambiguous')
    return matches[0]


def unpack(archive, tools, directory):
    """Commit a complete extraction; leave an existing runtime untouched."""
    destination = tools/directory
    if destination.exists():
        raise RuntimeError(f'Refusing to replace an existing runtime: {destination}')
    with tempfile.TemporaryDirectory(dir=tools, prefix='.unpack-') as temporary:
        staging = Path(temporary)
        if archive.name.endswith('.zip'):
            subprocess.run(['/usr/bin/ditto','-x','-k',str(archive),str(staging)],check=True)
        else:
            with tarfile.open(archive) as source:
                source.extractall(staging,filter='data')
        extracted = staging/directory
        required = extracted/'Ghidra/application.properties' if directory == GHIDRA else extracted/'Contents/Home/bin/java'
        if not required.is_file():
            raise RuntimeError(f'Archive is missing its expected runtime: {directory}')
        extracted.rename(destination)


def runtime_directory():
    """Installed packages never derive writable storage from site-packages."""
    override = os.environ.get('EAOS_RUNTIME_DIR')
    if override:
        return Path(override).expanduser().resolve()
    source = Path(__file__).resolve()
    checkout = source.parents[2]
    if source.parent.parent.name == 'src' and (checkout/'install.sh').is_file():
        return checkout/'.tools'
    return Path.home()/'Library/Application Support/Every App Is Open Source/runtimes'


def prerequisites():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('Only Apple Silicon macOS is currently supported; no runtime downloads were started.')
    subprocess.run(['/usr/bin/xcode-select','-p'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    for tool in ['make','clang++']:
        subprocess.run(['/usr/bin/xcrun','--find',tool],stdout=subprocess.DEVNULL,check=True)


def configure():
    tools = runtime_directory()
    ghidra = tools/GHIDRA
    java = tools/JDK/'Contents/Home'
    required = [java/'bin/java', ghidra/'Ghidra/application.properties',
                ghidra/'Ghidra/Features/Decompiler/os/mac_arm_64/decompile']
    if not all(path.is_file() for path in required):
        raise RuntimeError('Java/Ghidra setup is incomplete. Run eaos setup first. Runtime directory: '+str(tools))
    # Match the checkout launcher: prefer our verified managed runtimes over
    # unrelated JAVA_HOME/GHIDRA_INSTALL_DIR values inherited from a client.
    os.environ['JAVA_HOME'] = str(java)
    os.environ['GHIDRA_INSTALL_DIR'] = str(ghidra)
    return tools, ghidra, java


def install(rebuild=False, archive_cache=None):
    prerequisites()
    tools = runtime_directory()
    tools.mkdir(parents=True, exist_ok=True)
    with (tools/'setup.lock').open('a+') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another installation is running in '+str(tools)) from None
        return install_locked(tools, rebuild, archive_cache)


def install_locked(tools, rebuild=False, archive_cache=None):
    pins = json.loads(files('eaos').joinpath('distributions.json').read_text())
    archives = {};downloaded = []
    for name,directory in [('ghidra.zip',GHIDRA),('jdk.tar.gz',JDK)]:
        destination = tools/directory
        required = destination/'Ghidra/application.properties' if directory == GHIDRA else destination/'Contents/Home/bin/java'
        if destination.exists():
            if not required.is_file():
                raise RuntimeError(f'Incomplete runtime at {destination}; move it aside before retrying.')
            continue
        archive = (archive_cache or tools/'distributions')/name
        if not archive.is_file():
            if archive_cache is not None:
                raise RuntimeError(f'Missing archive in supplied cache: {archive}')
            print(f'Downloading pinned {name} ({pins[name]["bytes"]:,} bytes)…',flush=True)
            download(archive_url(name),archive,pins[name]);downloaded.append(name)
        verify_archive(archive,pins[name]);archives[name]=str(archive)
        print(f'Extracting verified {name}…',flush=True)
        unpack(archive,tools,directory)
    ghidra = tools/GHIDRA;java = tools/JDK/'Contents/Home'
    properties = (ghidra/'Ghidra/application.properties').read_text()
    if 'application.version=12.1.4' not in properties.splitlines():
        raise RuntimeError('Unexpected Ghidra version')
    output = ghidra/'Ghidra/Features/Decompiler/os/mac_arm_64/decompile'
    rebuilt = rebuild or not output.is_file()
    if rebuilt:
        print('Building the Apple Silicon decompiler; log: '+str(tools/'decompiler-build.log'),flush=True)
        cpp = ghidra/'Ghidra/Features/Decompiler/src/decompile/cpp'
        # Keep release-generated parsers; no Bison, CMake or other build installs.
        with (tools/'decompiler-build.log').open('w') as log:
            subprocess.run(BUILD_ARGS,cwd=cpp,stdout=log,stderr=subprocess.STDOUT,check=True)
        output.parent.mkdir(parents=True,exist_ok=True)
        temporary = output.with_name('.eaos-decompile')
        try:
            shutil.copy2(cpp/'ghidra_opt',temporary);temporary.replace(output)
        finally:temporary.unlink(missing_ok=True)
    check = subprocess.check_output(['file',str(output)],text=True).strip()
    if 'arm64' not in check:
        raise RuntimeError('Decompiler is not an ARM64 executable: '+check)
    java_check = subprocess.run([str(java/'bin/java'),'-version'],capture_output=True,text=True,check=True)
    if 'version "21.' not in java_check.stderr:
        raise RuntimeError('Unexpected Java version: '+java_check.stderr)
    try:
        pyghidra_version = version('pyghidra')
    except PackageNotFoundError:
        pyghidra_version = None  # The checkout installs bindings after native setup.
    report = {'ghidra':str(ghidra),'java_home':str(java),'java_version':java_check.stderr.splitlines()[0],
        'python':platform.python_version(),'pyghidra':pyghidra_version,
        'python_executable':sys.executable,'package_location':str(Path(__file__).resolve().parent),
        'decompiler':check,'decompiler_sha256':digest(output),'decompiler_built':rebuilt,
        'verified_archives':archives,'downloaded':downloaded}
    temporary = tools/'setup.json.part'
    temporary.write_text(json.dumps(report,indent=2)+'\n')
    temporary.replace(tools/'setup.json')
    print('Ready. Java and Ghidra: '+str(tools),flush=True)
    print('Receipt: '+str(tools/'setup.json'),flush=True)
    return report
