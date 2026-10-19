# Every App Is Open Source

Give an AI agent a compiled program and inspect how it works through seven Ghidra-powered MCP tools, with compact replies and traceable evidence.

**On one modified-Doom benchmark, EAOS 0.1.0 returned the same answers as REA 6.7.0 using 52% fewer total tokens, with 36% lower API-equivalent cost and 27% lower median time.** All three tools tied on correctness. This is a measured result for that test, not a general accuracy or performance guarantee.

> **0.1.1 adds input-integrity and validation fixes.** See [CHANGELOG.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/CHANGELOG.md). The historical comparison has not been rerun for 0.1.1.

The name is a provocation, not a license: reconstructing an app's logic does not give permission to copy it. Ghidra does the decompilation; this project provides the agent interface, input capture, cache and evidence handling.

## A first example

[Real agent walkthrough and tool transcript](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/DEMO.md) — the installed 0.1.1 candidate, a fresh Codex session, and all four tool calls.

The supplied [tiny C program](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/tests/fixture.c) has a function called `quote`. Ask your connected agent:

> What does quote(6) return? Explain both branches and show the function address and evidence.

Expected answer: **45**, computed from the recovered logic. Below 4 it returns 19; otherwise it returns `7*n + 3`. Follow the [copy-paste first-result walkthrough](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#first-result) to compile this example yourself, open it, and inspect the saved evidence. Addresses depend on your compiler; the answer follows the inspected logic rather than a copied address.

## Supported platforms

Native analysis and managed setup: **Apple Silicon macOS**, Python 3.13, [uv](https://docs.astral.sh/uv/), and Apple's Command Line Tools. Windows, Linux and Intel macOS native support are not claimed. Python-only CI on Linux does not establish native support there.

## Install and connect

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.1 eaos setup
```

This selects the Python package, downloads checksum-pinned Java 21 and Ghidra 12.1.4, and builds the ARM64 decompiler. It writes managed runtimes under `~/Library/Application Support/Every App Is Open Source/runtimes/`; it does not change shell profiles, system Java or agent settings. Allow about 770 MB of native downloads plus several GB for extraction/build. See [download sources, exact sizes, filesystem changes, troubleshooting and uninstall](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md).

Point one client at one program:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.1 eaos mcp /absolute/path/to/program
```

[Complete Claude Code, Codex and generic MCP setup](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/CLIENTS.md). To test a reviewed local wheel, replace the `--from` value with the absolute reviewed wheel path. To work from a checkout, `./install.sh` installs the existing locked dependencies and native runtimes locally, then `./eaos mcp /absolute/path/to/program` starts the server.

Or call a tool directly:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.1 eaos call /absolute/path/to/program open_program
```

The tool interface exposes the selected program and its evidence; it has no general file-reading or shell tool. **The Python/JVM process is not OS-sandboxed** and runs with your user's permissions. Recovered text is untrusted data. Read the [security model](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/SECURITY.md) before analyzing unfamiliar files.

For an installed macOS app, [copy its executable outside the app bundle and select the intended architecture](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#macos-app-bundles). Complete large programs' first analysis in the terminal before connecting your client.

## Evidence and benchmark

Same model for everyone (gpt-6.1-sol, high effort), fresh sessions, six questions, three runs per tool:

| Tool | Correct | Median time per run | Tokens, 3 runs | API-equivalent cost, 3 runs |
|---|---:|---:|---:|---:|
| **Every App Is Open Source 0.1.0** | **18/18** | **121.8s** | **1,728,000** | **$0.70** |
| Community GhidraMCP | 18/18 | 146.2s | 2,337,886 | $0.84 |
| REA 6.7.0 + its bundled skill | 18/18 | 166.7s | 3,603,877 | $1.09 |

Across the three runs, EAOS used **1,728,000 total tokens versus REA's 3,603,877: about 52% fewer, or roughly half**. These totals include input and output tokens, including cached input. The API-equivalent cost saving is 36% because cached input receives a billing discount.

**How I kept it honest:**
- **Doom's answers are all over the internet, so I changed them.** I built Chocolate Doom with eight gameplay rules secretly altered and stripped its function names. An agent answering from memory gets the original values, and those are now wrong.
- **I froze the questions and the answer key before the first run.** The answer key comes from running the modified game code, not from me reading it.
- **Everyone got the same head start.** All three began with the program already analyzed, outside the timer.
- **REA ran the way people actually install it,** with its bundled skill and its full tool catalog.

**What this doesn't prove:** all three scored 100%, so mine isn't smarter, just cheaper and faster. It's one game, three runs per tool, compiled programs only.

My first version actually lost to GhidraMCP on cost. I read the logs, cut the repeated metadata and the detail nobody had asked for yet, then retested on new questions and a new build. Everything is kept, including the round I lost.

[Full results](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/results.md) · [Every run](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/results.json) · [Answer-by-answer check](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/round2/answer-review.json) · [Frozen protocol](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/benchmark/protocol-round2.json) · [The round I lost](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/reports/results.md)

The expected answers are public in the answer-by-answer review. The modified executables, altered source and executable oracle remain private. Public preparation instructions build a fresh target; the full three-tool comparison requires manual setup. See [benchmark preparation and limits](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md).

## The seven tools

I counted every tool call the agents made across my earlier 24 test runs and built only what they actually used.

| Tool | What it does |
|---|---|
| `open_program` | What the program is: architecture, memory layout, analysis status |
| `search` | Find text inside the program and where it's used, or find functions |
| `inspect` | Decompiled code, raw instructions, callers and callees |
| `read_memory` | Read the actual bytes at an address |
| `calculate` | Safe arithmetic and byte decoding, so the agent doesn't do math in its head |
| `decode_swift_string` | Recover text hidden inside Swift code on Apple platforms |
| `read_evidence` | Pull up the full saved evidence behind any reply, hash-checked |

## Never "exact" for a guess

In REA 6.5.0's JavaScript analysis, I found two false positives labelled "observed, exact": a [Map lookup classified as a network endpoint](https://github.com/morluto/rea/issues/4853) and a [local class classified as SQLite storage](https://github.com/morluto/rea/issues/4854). Both have since been fixed on REA's main branch. These were findings from an earlier JavaScript audit; the native benchmark used REA 6.7.0.

Here, every answer says what it is:

- **fact**: read straight from the binary
- **computed**: worked out deterministically, like decompiled code or a decoded string
- **guess**: an interpretation with nothing solid behind it

Decompiled code is computed, not the original source. When a tool fails, it says it failed.

## Analyze once, reuse forever

Ghidra's analysis is slow, so each program gets its own `eaos-analysis/<sha256>/` folder right next to it, holding the analyzed project and every piece of evidence. Opening the same program again reuses all of it.

One Ghidra quirk: it won't create projects inside a folder whose name starts with a dot, like `.cache`. Keep the program you're analyzing out of those.

Each session now captures a read-only copy and imports the bytes that were hashed. Changes to the original path affect a new session, not the session already open. Cached Ghidra projects must report the same executable hash. A mismatch fails without deleting old evidence; preserve and move the affected directory aside before retrying.

## Limitations and roadmap

The saved comparison covers one modified native game, three runs per tool, one model and fixed prewarming. It does not prove better accuracy: all tools scored 100%. Version 0.1.1 adds integrity/validation protections; its performance has not been benchmarked.

JavaScript/Electron (starting with VS Code), Android, .NET and runtime/web inspection remain future work. Each area needs its own hidden-answer-key test before an improvement claim. Initial Ghidra analysis has no overall timeout; the calculator and individual decompilations have documented limits. See the [tool contract](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/TOOL-CONTRACT.md).

## Development and reproduction

```sh
uv build
PYTHONPATH=src uv run --no-project --python 3.13 python -m unittest discover -s tests -v
python3 scripts/check_distribution.py dist
```

Rebuild the game target in a **fresh checkout**, with the documented SDL2 prerequisites already installed:

```sh
python3 benchmark/prepare.py
python3 benchmark/build_doom.py
```

These commands generate a new random target and private key, not a replay of the published scores. They never start billable model runs. See [BENCHMARK.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md) for what the historical comparison harness additionally needs. Previous runs, reports and protocols are retained.

## Contributing, security and license

Maintained solely by @thomasisalwayslate. Bug reports and suggestions are welcome; external code contributions are not currently accepted.

[Contributing](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/CONTRIBUTING.md) · [Security and reporting status](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/SECURITY.md) · [Changelog](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/CHANGELOG.md). [Report a vulnerability privately](https://github.com/thomasisalwayslate/every-app-is-open-source/security/advisories/new); do not post sensitive binaries or exploit details in a public issue.

Ghidra and PyGhidra are the work of their respective contributors. The comparison baseline is LaurieWired's GhidraMCP; the target is Chocolate Doom, based on id Software's Doom and released under GPLv2. This wrapper is [Apache-2.0](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/LICENSE); retain [NOTICE](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/NOTICE), upstream attribution and the [disclaimer](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/DISCLAIMER.md).
