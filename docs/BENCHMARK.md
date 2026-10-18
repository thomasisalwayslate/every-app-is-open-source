# Rebuilding the benchmark target

The published comparison is **historical EAOS 0.1.0**, REA 6.7.0 with its installed skill, and community GhidraMCP pinned in `benchmark/community-pin.json`. It used gpt-6.1-sol/high, fresh sessions, a frozen six-question set, three runs each, and equal prewarming. All three answered everything correctly. Nothing in the 0.1.1 hardening work establishes a new cost, speed or correctness result.

## Prepare a new secret target

Use a fresh checkout or isolated directory. Do not run the builders over existing private targets/keys. They deliberately refuse to overwrite them. The benchmark additionally needs Apple clang, `strip`, `codesign`, `nm`, `dsymutil`, and these SDL2 packages at the normal Apple Silicon Homebrew prefix:

```sh
brew install sdl2 sdl2_mixer sdl2_net
```

This is a benchmark-only prerequisite, not part of normal EAOS installation. The preparation command below downloads source only; it does not install dependencies, run an agent, or make API calls to a model:

```sh
python3 benchmark/prepare.py
python3 benchmark/build_doom.py
```

Preparation downloads the **Chocolate Doom 3.1.1** source archive from the official GitHub repository and verifies SHA-256 `1edcc41254bdc194beb0d33e267fae306556c4d24110a1d3d3f865717f25da23`. It extracts under `private/upstream/` and writes `private/download.json`. Re-running preparation reuses a matching completed preparation. Keep that tree unmodified before building; use a fresh directory if in doubt.

The builder creates `private/doom/` (modified source, new random values, patch, symbols, build commands, executable oracles, and `target-manifest.json`) plus `benchmark/targets/chocolate-doom-secret`. Internal labels are stripped. The old tracked target manifest and published reports are never replaced by this command. A WAD is not required to compile the executable or run its code-derived oracles; no Doom game data is downloaded by this procedure.

To keep new work away from this checkout's historic artifacts:

```sh
python3 benchmark/prepare.py --root /absolute/path/to/new-study
python3 benchmark/build_doom.py --root /absolute/path/to/new-study
```

The paths must be writable. Keep `private/` and the oracle inaccessible to the analyst. `build_round2.py` adds the later control-flow mutations on top of the first private build; its existing non-overwrite checks remain in place. It expects `private/doom` from the first builder in its checkout.

## What the historical three-way runner needs

`benchmark/run.py`, `engine.mjs`, `relay.py` and `study2.py` are the preserved audit harness, not a newly validated public one-command comparison installer. They additionally expect:

- Existing managed Java/Ghidra under `.tools/`, the EAOS environment under `.venv/`, and a selected target already analyzed once.
- Node and the stock REA 6.7.0 package. Install REA's bundled skill normally in a throwaway home using `npx rea-agents@6.7.0 setup`; the audit recorded the resulting package path in `benchmark/installer/package-path.txt`. That file and installed third-party code are intentionally not committed.
- The community server at commit `1e980252087b2479a21b9ca6d82d5829538651a7`, its own environment and built Ghidra extension, under `benchmark/vendor/` as expected by `engine.mjs`. Follow that commit's upstream headless build instructions; these dependencies are not included in the PyPI package.
- The user's own authenticated Codex CLI and access to gpt-6.1-sol/high. Starting trials is a separate billable action. The saved protocols include original target hashes and oracle locations; a fresh study must freeze its own manifest, protocol, answer key and output paths before running agents. Do not relax hash checks or overwrite historical runs to reuse those protocols.

**The target preparation/build is the reproducibility fix in this candidate. The complete three-arm orchestration is still audit-specific.** It has not been repackaged or rerun here, and the README does not claim otherwise. A new complete comparison runner should be treated as separate work, including tightening the audit harness's path-argument policy before further trials. Report unsuccessful runs and measured billing categories; do not substitute raw token ratios for API-equivalent cost.

The private historical target/key are withheld to prevent answer-key leakage. Independent readers can inspect saved transcripts and protocols and build fresh tests, but this is not a claim that the original scores can be exactly replayed from public material alone.
