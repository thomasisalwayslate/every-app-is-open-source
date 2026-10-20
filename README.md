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

**Benchmarked against [REA](https://github.com/morluto/rea) and GhidraMCP on real programs: same answers, for less cost and less time.** Every run, number and limitation is in [BENCHMARKS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/BENCHMARKS.md).

The name is a provocation, not a license. Seeing how an app works doesn't give you the right to copy it. Read the [disclaimer](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/DISCLAIMER.md).

<!-- mcp-name: io.github.thomasisalwayslate/every-app-is-open-source -->

## Install

You need an Apple Silicon Mac, [uv](https://docs.astral.sh/uv/) and Apple's Command Line Tools (`xcode-select --install`).

```sh
uvx --python 3.13 --from every-app-is-open-source eaos setup
```

That downloads checksum-pinned Java and Ghidra and builds Ghidra's Apple Silicon decompiler, which the official download doesn't include. Everything goes into `~/Library/Application Support/Every App Is Open Source/`. It doesn't touch your shell profile, your system Java or your agent's settings. The exact versions, download sizes, troubleshooting and uninstall steps are in [SETUP.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md).

Windows, Linux and Intel Macs aren't supported yet.

## Connect your agent

Point it at one program:

```sh
uvx --python 3.13 --from every-app-is-open-source eaos mcp /absolute/path/to/program
```

Setup for Claude Code, Codex and any other MCP client is in [CLIENTS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/CLIENTS.md). You can also call a single tool from the terminal:

```sh
uvx --python 3.13 --from every-app-is-open-source eaos call /absolute/path/to/program open_program
```

To analyze a Mac app, [copy its executable out of the app bundle first](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#macos-app-bundles). For big programs, let the first analysis finish in the terminal before you connect your agent.

## Try it on something small

The repo includes a [tiny C program](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/tests/fixture.c) with a function called `quote`. Compile it, connect your agent, and ask:

> What does quote(6) return? Explain both branches and show the function address and evidence.

The answer is **45**: below 4 it returns 19, otherwise `7*n + 3`. The [step-by-step version](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/SETUP.md#first-result) walks you through it, and there's a [full transcript of a real agent session](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/DEMO.md) if you want to see every tool call first.

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

## Never "exact" for a guess

Every answer says what it is:

- **fact**: read straight from the binary
- **computed**: worked out from it, like decompiled code or a decoded string
- **guess**: an interpretation with nothing solid behind it

Decompiled code is computed, not the original source. When a tool fails, it says so.

I care about this because of what I found in REA: a [Map lookup labelled as a network endpoint](https://github.com/morluto/rea/issues/4853) and a [local class labelled as SQLite storage](https://github.com/morluto/rea/issues/4854), both marked "observed, exact". Both are fixed in REA now.

## Analyze once, reuse it

Ghidra's analysis is slow, so each program gets its own `eaos-analysis/<sha256>/` folder right next to it, with the analyzed project and every piece of evidence. Opening the same program again reuses all of it.

Each session works on a read-only copy of the exact bytes it hashed, so changing the original file doesn't affect a session that's already open. If a cached project doesn't match the program's hash, it stops instead of guessing, and it never deletes old evidence.

One Ghidra quirk: it won't create projects inside a folder whose name starts with a dot, like `.cache`. Keep the program you're analyzing out of those.

## Benchmarks

I test it against REA and GhidraMCP whenever I point it at something new. The results live in [BENCHMARKS.md](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/BENCHMARKS.md), one row per target, each linked to every run and answer.

The rules stay the same every time:
- **Same model, fresh sessions, three runs per tool.**
- **Questions and answer key frozen before the first run.** Where a model might know the answers by heart, I secretly change them and rebuild the program first.
- **Same head start.** Every tool begins with the program already analyzed, outside the timer.
- **REA runs the way people actually install it,** with its bundled skill and its full tool catalog.
- **Everything is kept,** including rounds I lost.

Want to check my work? [Run your own](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/BENCHMARK.md).

## What's next

Right now it handles compiled programs. Next up are JavaScript and Electron apps, then Android, .NET, and watching apps while they run. Each one gets its own benchmark before I claim anything.

## Security

The tools only expose the program you selected and its evidence. There's no general file-reading or shell tool. The Python and Java processes aren't sandboxed by the OS, though: they run with your user's permissions, and text recovered from a binary is untrusted. Read the [security model](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/SECURITY.md) before you analyze anything you don't trust.

Found a vulnerability? [Report it privately](https://github.com/thomasisalwayslate/every-app-is-open-source/security/advisories/new), not in a public issue.

## Development

```sh
uv build
PYTHONPATH=src uv run --no-project --python 3.13 python -m unittest discover -s tests -v
python3 scripts/check_distribution.py dist
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
