# Contributing

EAOS is maintained solely by @thomasisalwayslate. Bug reports and suggestions are welcome; external code contributions are not currently accepted. Pull requests are restricted to repository collaborators.

You are welcome to use, fork and modify the project under its Apache-2.0 license. A fork is a separate project; changes to the official repository and releases remain under the maintainer's control.

## Maintainer development notes

Keep the native tool interface small and compatible. New output must distinguish observed facts, computed results and guesses, and provide working evidence identifiers. Never label a guess exact. Changes to analysis, input capture, validation or evidence need regression tests for their failure cases.

Use Python 3.13 and the existing dependencies. Run `uv build`, then `PYTHONPATH=src uv run --no-project --python 3.13 python -m unittest discover -s tests -v` and `python3 scripts/check_distribution.py dist`. On a configured Apple Silicon Mac, `EAOS_NATIVE_TESTS=1 uv run python -m unittest discover -s tests -p test_integrity.py -v` checks real Ghidra import/cache identity. It uses temporary compiled test programs, not the benchmark oracle.

Do not include `private/`, answer keys, modified benchmark sources, binaries, generated evidence, personal paths or secrets in a contribution or release artifact. Preserve upstream attribution and licenses. Report vulnerabilities through the route in [SECURITY.md](SECURITY.md), not a public issue containing sensitive details.

For performance claims, freeze a new task set, use the same model, effort and prewarming for every condition, keep failures and prior results, and report measured cost/time separately from correctness. The recorded 0.1.0 benchmark is historical evidence, not a guarantee for another version or target.

The release workflow is manually dispatched and defaults to **build/check only**. Publishing requires explicitly enabling its publish input on approved `main`, with the matching reviewed `v<version>` tag pointing to that exact commit. The `pypi` environment requires approval before upload. The publisher downloads the already checked wheel/source archive and verifies their SHA-256 manifest; it does not rebuild them. Routine CI never publishes. Do not create a tag, push code, change security settings or publish on somebody's behalf without their authorization.
