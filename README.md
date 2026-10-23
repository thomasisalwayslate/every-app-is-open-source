<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/thomasisalwayslate/every-app-is-open-source/main/docs/assets/readme-banner-dark.png">
  <img alt="Every App Is Open Source: give your AI agent a compiled app, it tells you how it works" src="https://raw.githubusercontent.com/thomasisalwayslate/every-app-is-open-source/main/docs/assets/readme-banner-light.png" width="100%">
</picture>

[![PyPI](https://img.shields.io/pypi/v/every-app-is-open-source?style=flat-square&color=121212&label=pypi)](https://pypi.org/project/every-app-is-open-source/)
[![CI](https://img.shields.io/github/actions/workflow/status/thomasisalwayslate/every-app-is-open-source/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/thomasisalwayslate/every-app-is-open-source/actions/workflows/ci.yml)
[![Python 3.13](https://img.shields.io/badge/python-3.13-121212?style=flat-square)](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md)
[![macOS Apple Silicon](https://img.shields.io/badge/macOS-Apple%20Silicon-121212?style=flat-square)](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-121212?style=flat-square)](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/LICENSE)
[![Every App Is Open Source MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/thomasisalwayslate/every-app-is-open-source/badges/score.svg)](https://glama.ai/mcp/servers/thomasisalwayslate/every-app-is-open-source)

# Every App Is Open Source

Give your AI agent a compiled program, and it works out how it's built. Ghidra does the decompiling. This is the agent's side of it: a small set of MCP tools, short answers by default, and evidence you can trace back to the binary.

The name is a provocation, not a license. Seeing how an app works doesn't give you the right to copy it. Read the [disclaimer](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/DISCLAIMER.md).

<!-- mcp-name: io.github.thomasisalwayslate/every-app-is-open-source -->

## What it looks like

An agent connected only to EAOS was given a small compiled program and asked what `quote(6)` returns. These are its actual tool calls:

| Tool call | What came back |
|---|---|
| `search {"kind":"functions","pattern":"quote"}` | `_quote` at `0x100000460` |
| `inspect {"addresses":["100000460"],"mode":"all"}` | Assembly and decompiled code, saved as evidence `fe8589bb…` |
| `read_evidence {"id":"fe8589bb…"}` | The saved evidence, hash-checked |

Its answer: **45**. Below 4 the function returns 19, otherwise `7*n + 3`, citing the address and the evidence ID.

This is one recorded session on version 0.1.1 with an already-analyzed cache, not a benchmark. The [full transcript](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/DEMO.md) has every call and its limits.

## How it compares

I've compared it with [REA](https://github.com/morluto/rea) and GhidraMCP on three modified programs, with the same model and questions for each tool. The results depend on the target, and EAOS doesn't win every time:

| Target | EAOS version | vs GhidraMCP | vs REA |
|---|---|---|---|
| Modified Doom | 0.1.0 | 16% cheaper, 17% faster; all 18/18 correct | 36% cheaper, 27% faster; all 18/18 correct |
| Modified Ollama | 0.1.4 | **28% more expensive, 23% slower**; GhidraMCP missed 3 of 195 cases | 14% cheaper, 17% faster; both 195/195 |
| Modified Ollama, round 2 | 0.1.5 | 6% cheaper, similar time | 25% cheaper, similar time |

Costs are API-equivalent model costs; timings exclude initial analysis. Each row is three runs per tool, so these are descriptive results, not a general ranking. In round 2 the other tools' missed cases were mostly header order and incomplete error text, not wrong behavior. The modified programs and answer keys are private so the tests can't be spoiled. That means you can read every run summary, scoring review and protocol, but you can't replay these exact comparisons yourself. Every number, loss and limitation is in [BENCHMARKS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/BENCHMARKS.md).

## Get your first result

You need an Apple Silicon Mac, [uv](https://docs.astral.sh/uv/) and Apple's Command Line Tools (`xcode-select --install`). Windows, Linux and Intel Macs aren't supported yet.

**1. Install.** This downloads checksum-pinned Java and Ghidra (about 770 MB) and builds Ghidra's Apple Silicon decompiler, which the official download doesn't include:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.8 eaos setup
```

Everything goes into `~/Library/Application Support/Every App Is Open Source/`. It doesn't touch your shell profile, your system Java or your agent's settings. Versions, sizes, troubleshooting and uninstall are in [SETUP.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md).

**2. Build a tiny test program and analyze it:**

```sh
mkdir -p /tmp/eaos-example
cat > /tmp/eaos-example/example.c <<'C'
#include <stdio.h>
__attribute__((noinline)) int quote(int n) { return n < 4 ? 19 : n * 7 + 3; }
int main(int argc, char **argv) { puts("eaos fixture anchor"); return quote(argc); }
C
clang -O0 /tmp/eaos-example/example.c -o /tmp/eaos-example/example
uvx --python 3.13 --from every-app-is-open-source==0.1.8 eaos call /tmp/eaos-example/example open_program
```

You should see `classification: computed`, an ARM64 language, a SHA-256 and an evidence ID.

**3. Connect your agent.** For Claude Code:

```sh
claude mcp add --transport stdio --scope local eaos -- uvx --python 3.13 --from every-app-is-open-source==0.1.8 eaos mcp /tmp/eaos-example/example
```

Codex and other MCP clients are in [CLIENTS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/CLIENTS.md).

**4. Ask:**

> Find the quote function. What does quote(6) return? Explain both branches and cite the function address and saved evidence.

The correct answer is **45**. This checks that your setup works; it doesn't prove the agent will understand any app. Addresses depend on the compiler, so yours will differ from the example above.

For a real program, use the same `eaos mcp /absolute/path/to/program` command. To analyze a Mac app, [copy its executable out of the app bundle first](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#macos-app-bundles). For big programs, run `eaos call ... open_program` in the terminal and let the first analysis finish before you connect your agent.

## The tools

I counted every tool call agents made across 24 earlier test runs and built only what they actually used.

| Tool | What it does |
|---|---|
| `open_program` | What the program is: architecture, memory layout, analysis status |
| `search` | Find text inside the program and where it's used, or find functions |
| `inspect` | Decompiled code, raw instructions, callers and callees |
| `read_memory` | Read static memory or Go string tables, with provenance |
| `calculate` | Safe arithmetic and byte decoding, so the agent doesn't do math in its head |
| `decode_swift_string` | Recover text hidden inside Swift code on Apple platforms |
| `read_evidence` | Pull up the full saved evidence behind any reply, hash-checked |

The exact inputs, outputs and limits of each one are in the [tool contract](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/TOOL-CONTRACT.md).

## Every tool result says what it is

Each tool result is labelled:

- **fact**: read straight from the binary
- **computed**: worked out from it, like decompiled code or a decoded string
- **guess**: an inference that hasn't been verified

Decompiled code is computed, not the original source. Successful analysis results include saved evidence you can pull up with `read_evidence`. Status responses and errors don't include evidence IDs; a tool failure makes no analysis claim.

These labels describe the tool results, not your agent's final answer. An agent can still misread correctly labelled evidence. The labels and evidence IDs let you check a conclusion; they don't certify it.

## Analyze once, reuse it

Ghidra's analysis is slow, so each program gets its own `eaos-analysis/<sha256>/` folder right next to it, with the analyzed project and every piece of evidence. Opening the same program again reuses all of it. Projects made before 0.1.7 are kept but not reused: 0.1.7 analyzes the program again in its new cache format.

Each session works on a read-only copy of the exact bytes it hashed, so changing the original file doesn't affect a session that's already open. If a cached project doesn't match the program's hash, it stops instead of guessing, and it never deletes old evidence.

One Ghidra quirk: it won't create projects inside a folder whose name starts with a dot, like `.cache`. Keep the program you're analyzing out of those.

## Analysis options

Full analysis is the default. The CLI and MCP server accept `--analysis-mode quick` for partial metadata and requested-function preparation, and `--architecture arm64` for an explicit Mach-O slice. Quick function search offers explicit bounded index continuation, separately from view-bound result pagination. Quick mode is limited to 64-bit ARM/x86 Mach-O; it does not recover every Swift name or prove missing references are absent. No new speed or accuracy comparison has been run.

On Apple Silicon, compatible universal inputs select ARM64 automatically. Each captured whole-file hash retains separate architecture/profile/engine caches under `profiles/`, with shared immutable evidence. Legacy projects are preserved; the new cache format does not reuse them. Status remains available during native operations, with configurable deadlines and cancellation. See [setup](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#017-analysis-options) and the [tool contract](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/TOOL-CONTRACT.md#017-analysis-profiles-and-identity) before using these options.

## How the benchmarks are run

The summary is [above](#how-it-compares); the details live in [BENCHMARKS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/BENCHMARKS.md), one row per target, each linked to its run summaries and scoring.

The rules stay the same every time:
- **Same model, fresh sessions, three runs per tool.**
- **Questions and answer key frozen before the first run.** Where a model might know the answers by heart, I secretly change them and rebuild the program first.
- **Same head start.** Every tool begins with the program already analyzed, outside the timer.
- **REA runs the way people actually install it,** with its bundled skill and its full tool catalog.
- **Everything is kept,** including rounds I lost.

The private targets and answer keys mean you can't replay my exact comparisons. You can run the same method on your own target with the [benchmark guide](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md).

## What's next

Right now it handles compiled programs on Apple Silicon Macs. I'd like it to inspect more kinds of software, but there's no fixed order or schedule: new support follows a demonstrated need and reproducible tests, and each one gets its own benchmark before I claim anything.

## Security

The tools only expose the program you selected and its evidence. There's no general file-reading or shell tool. The Python and Java processes aren't sandboxed by the OS, though: they run with your user's permissions, and text recovered from a binary is untrusted. Read the [security model](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/SECURITY.md) before you analyze anything you don't trust.

Found a vulnerability? [Report it privately](https://github.com/thomasisalwayslate/every-app-is-open-source/security/advisories/new), not in a public issue.

## Development

```sh
uv build
PYTHONPATH=src uv run --no-project --python 3.13 python -m unittest discover -s tests -v
python3 scripts/check_distribution.py dist
```

What gets tested where:

| Check | Where it runs |
|---|---|
| Unit, failure-case and packaging tests | CI on Ubuntu, every push |
| Installed-wheel CLI smoke test | CI on Ubuntu, every push |
| Native checks with real Ghidra on Apple Silicon (10 tests) | Locally on a configured Mac before each release; skipped in CI |

The green CI badge covers the first two rows only. To run the native checks after `eaos setup` or `./install.sh`:

```sh
EAOS_NATIVE_TESTS=1 uv run python -m unittest discover -s tests -v
```

To work from a checkout instead of PyPI, `./install.sh` sets up everything locally, then `./eaos mcp /absolute/path/to/program` starts the server.

## Contributing

This is my project, and I build it myself. Bug reports and ideas are very welcome through [issues](https://github.com/thomasisalwayslate/every-app-is-open-source/issues). I don't accept outside code. If you want to take it somewhere else, fork it; that's what the license is for. More in [CONTRIBUTING.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/CONTRIBUTING.md).

## License and credits

[Apache-2.0](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/LICENSE). If you build on it, keep the [NOTICE](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/NOTICE) file. What's changed in each release is in the [changelog](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/CHANGELOG.md).

Ghidra and PyGhidra do the heavy lifting; they're the work of their own contributors. The comparison baseline is LaurieWired's GhidraMCP. The programs I benchmark on, and their licenses, are credited in [BENCHMARKS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/BENCHMARKS.md).

---

Made by [thomasisalwayslate](https://github.com/thomasisalwayslate). I make apps, games and small tools, usually something I want to use myself. More on [my site](https://thomasisalwayslate.github.io), including [the write-ups behind the benchmarks](https://thomasisalwayslate.github.io/research).

If this saved you some digging, a ⭐ helps other people find it.
