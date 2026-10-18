#!/usr/bin/env python3
"""Inspect local release candidates without importing them or contacting PyPI."""
import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = {
    'README.md', 'pyproject.toml', 'uv.lock', '.python-version', 'install.sh',
    'eaos', 'MANIFEST.in', 'PKG-INFO', 'setup.cfg',
    'LICENSE', 'NOTICE', 'DISCLAIMER.md',
    'scripts/setup.py', 'scripts/distributions.json',
    'scripts/python-downloads.json', 'scripts/python-provenance.json',
}
REQUIRED_SOURCE = SOURCE_FILES - {'PKG-INFO', 'setup.cfg', 'MANIFEST.in', 'DISCLAIMER.md'}
WHEEL_METADATA = {'METADATA', 'WHEEL', 'entry_points.txt', 'top_level.txt', 'RECORD'}


def safe_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError(f'Unsafe archive path: {name}')
    return path


def source_allowed(path):
    parts = path.parts
    return (str(path) in SOURCE_FILES
            or (len(parts) == 3 and parts[:2] == ('src', 'eaos')
                and (path.suffix == '.py' or parts[-1] == 'distributions.json'))
            or (len(parts) == 3 and parts[:2] == ('src', 'every_app_is_open_source.egg-info')
                and parts[-1] in {'PKG-INFO', 'SOURCES.txt', 'dependency_links.txt',
                                  'entry_points.txt', 'requires.txt', 'top_level.txt'}))


def check_metadata(data, project):
    metadata = BytesParser().parsebytes(data)
    if metadata['Name'] != project['name'] or metadata['Version'] != project['version']:
        raise ValueError('Distribution metadata does not match pyproject.toml')


def inspect(directory):
    project = tomllib.loads((ROOT/'pyproject.toml').read_text())['project']
    stem = project['name'].replace('-', '_') + '-' + project['version']
    paths = sorted(directory.iterdir())
    artifacts = [p for p in paths if p.is_file() and not p.name.startswith('.')]
    if {p.name for p in artifacts} != {stem+'.tar.gz', stem+'-py3-none-any.whl'}:
        raise ValueError('Expected exactly one version-matched wheel and source archive')
    output = []
    for artifact in artifacts:
        names = []
        if artifact.suffix == '.whl':
            with zipfile.ZipFile(artifact) as archive:
                for item in archive.infolist():
                    path = safe_path(item.filename)
                    if item.is_dir():
                        continue
                    if (item.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError('Wheel contains a symbolic link')
                    parts = path.parts
                    allowed = (len(parts) == 2 and parts[0] == 'eaos'
                               and (path.suffix == '.py' or parts[-1] == 'distributions.json'))
                    allowed |= (len(parts) == 2 and parts[0] == stem+'.dist-info'
                                and parts[1] in WHEEL_METADATA)
                    allowed |= (len(parts) == 3 and parts[:2] == (stem+'.dist-info', 'licenses')
                                and parts[2] in {'LICENSE', 'NOTICE'})
                    if not allowed:
                        raise ValueError(f'Unexpected wheel member: {path}')
                    names.append(str(path))
                required = {'eaos/cli.py', 'eaos/backend.py', 'eaos/runtime.py',
                            'eaos/distributions.json', stem+'.dist-info/METADATA',
                            stem+'.dist-info/entry_points.txt',
                            stem+'.dist-info/licenses/LICENSE', stem+'.dist-info/licenses/NOTICE'}
                if not required.issubset(names):
                    raise ValueError('Wheel is missing code or entry-point metadata')
                check_metadata(archive.read(stem+'.dist-info/METADATA'), project)
                if archive.read('eaos/distributions.json') != (ROOT/'scripts/distributions.json').read_bytes():
                    raise ValueError('Wheel runtime pins differ from the reviewed archive manifest')
        else:
            with tarfile.open(artifact) as archive:
                for item in archive:
                    path = safe_path(item.name)
                    if path.parts[0] != stem:
                        raise ValueError('Unexpected source archive root')
                    if item.isdir():
                        continue
                    if not item.isfile():
                        raise ValueError('Source archive contains a non-regular file')
                    relative = PurePosixPath(*path.parts[1:])
                    if not source_allowed(relative):
                        raise ValueError(f'Unexpected source member: {relative}')
                    names.append(str(relative))
                if not REQUIRED_SOURCE.issubset(names):
                    raise ValueError('Source archive is missing installer assets')
                if 'src/eaos/runtime.py' not in names or 'src/eaos/distributions.json' not in names:
                    raise ValueError('Source archive is missing packaged setup or runtime pins')
                check_metadata(archive.extractfile(stem+'/PKG-INFO').read(), project)
        with artifact.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        output.append({'file': artifact.name, 'bytes': artifact.stat().st_size,
                       'sha256': digest,
                       'members': sorted(names)})
    return {'project': project['name'], 'version': project['version'],
            'classification': 'computed', 'uploaded': False, 'artifacts': output}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.directory), indent=2))
