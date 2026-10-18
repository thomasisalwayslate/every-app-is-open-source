"""Fetch and verify public benchmark source; never run agents or install tools."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PIN = {
    'url': 'https://codeload.github.com/chocolate-doom/chocolate-doom/tar.gz/refs/tags/chocolate-doom-3.1.1',
    'sha256': '1edcc41254bdc194beb0d33e267fae306556c4d24110a1d3d3f865717f25da23',
}


def prepare(root, pin=None):
    pin = pin or PIN
    private = root / 'private'
    private.mkdir(parents=True, exist_ok=True)
    destination = private / 'upstream'
    receipt = private / 'download.json'
    if destination.exists():
        if not receipt.exists() or json.loads(receipt.read_text()) != pin:
            raise RuntimeError('Existing upstream has no matching receipt; preserve it and use a fresh checkout')
        directories = list(destination.iterdir())
        if len(directories) != 1 or not (directories[0] / 'src/doom/p_pspr.c').is_file():
            raise RuntimeError('Existing upstream is incomplete; use a fresh checkout')
        return destination
    with tempfile.TemporaryDirectory(prefix='prepare-', dir=private) as temporary:
        staging = Path(temporary)
        archive = staging / 'upstream.tar.gz'
        with urllib.request.urlopen(pin['url'], timeout=60) as response, archive.open('wb') as out:
            while block := response.read(1024 * 1024):
                out.write(block)
                if out.tell() > 50 * 1024 * 1024:
                    raise RuntimeError('Upstream archive exceeds the preparation size limit')
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != pin['sha256']:
                raise RuntimeError('Upstream checksum mismatch; no source was installed')
        extracted = staging / 'source'
        with tarfile.open(archive) as tar:
            tar.extractall(extracted, filter='data')
        directories = list(extracted.iterdir())
        if len(directories) != 1 or not (directories[0] / 'src/doom/p_pspr.c').is_file():
            raise RuntimeError('Unexpected upstream source layout')
        extracted.replace(destination)
        receipt.write_text(json.dumps(pin, indent=2) + '\n')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT, help='A fresh checkout or isolated benchmark directory')
    args = parser.parse_args()
    print('Verified source: ' + str(prepare(args.root.resolve())))
