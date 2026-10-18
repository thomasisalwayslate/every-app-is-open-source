#!/bin/sh
# Install only inside this checkout. Existing prerequisites: uv and Apple CLT.
set -eu
EAOS_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo 'EAOS currently supports Apple Silicon macOS. No installation was started.' >&2
    exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
    echo 'uv is required. Put your existing uv installation on PATH, then rerun ./install.sh.' >&2
    exit 1
fi
if ! /usr/bin/xcode-select -p >/dev/null 2>&1; then
    echo 'Apple Command Line Tools are required. Install them with xcode-select --install, then rerun ./install.sh.' >&2
    exit 1
fi
IFS= read -r EAOS_PYTHON < "$EAOS_ROOT/.python-version"
export UV_CACHE_DIR="$EAOS_ROOT/.cache/uv"
export UV_PYTHON_INSTALL_DIR="$EAOS_ROOT/.tools/python"
export UV_PROJECT_ENVIRONMENT="$EAOS_ROOT/.venv"
export UV_PYTHON_DOWNLOADS_JSON_URL="$EAOS_ROOT/scripts/python-downloads.json"
unset VIRTUAL_ENV
uv --no-config python install --no-bin "$EAOS_PYTHON"
exec uv run --no-config --no-project --no-env-file --managed-python --python "$EAOS_PYTHON" python -I "$EAOS_ROOT/scripts/setup.py" "$@"
