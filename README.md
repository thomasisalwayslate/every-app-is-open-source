# Every App Is Open Source

**Same answers as REA. 36% cheaper. 27% faster.**

I built this to give an AI agent the tools to take a compiled program apart and work out what it does, without the source code. Ghidra does the actual decompiling. My part is everything around it: a small set of tools, short replies by default, honest labels on every answer, and evidence you can trace back to the binary.

Then I tested it against [REA](https://github.com/morluto/rea), the 300,000-star tool everyone's using, and against the community [GhidraMCP](https://github.com/LaurieWired/GhidraMCP). On a secretly modified Doom, all three got every answer right. Mine was the cheapest and the fastest.

> The name is a provocation, not a license. This shows you how an app works. It doesn't give you the right to copy it.

## Results

Same model for everyone (gpt-6.1-sol, high effort), fresh sessions, six questions, three runs per tool:

| Tool | Correct | Median time per run | Tokens, 3 runs | API-equivalent cost, 3 runs |
|---|---:|---:|---:|---:|
| **Every App Is Open Source** | **18/18** | **121.8s** | **1,728,000** | **$0.70** |
| Community GhidraMCP | 18/18 | 146.2s | 2,337,886 | $0.84 |
| REA 6.7.0 + its bundled skill | 18/18 | 166.7s | 3,603,877 | $1.09 |

**How I kept it honest:**
- **Doom's answers are all over the internet, so I changed them.** I built Chocolate Doom with eight gameplay rules secretly altered and stripped its function names. An agent answering from memory gets the original values, and those are now wrong.
- **I froze the questions and the answer key before the first run.** The answer key comes from running the modified game code, not from me reading it.
- **Everyone got the same head start.** All three began with the program already analyzed, outside the timer.
- **REA ran the way people actually install it,** with its bundled skill and its full tool catalog.

**What this doesn't prove:** all three scored 100%, so mine isn't smarter, just cheaper and faster. It's one game, three runs per tool, compiled programs only.

My first version actually lost to GhidraMCP on cost. I read the logs, cut the repeated metadata and the detail nobody had asked for yet, then retested on new questions and a new build. Everything is kept, including the round I lost.

[Full results](reports/round2/results.md) · [Every run](reports/round2/results.json) · [Answer-by-answer check](reports/round2/answer-review.json) · [Frozen protocol](benchmark/protocol-round2.json) · [The round I lost](reports/results.md)

## Install

You need an Apple Silicon Mac, [uv](https://docs.astral.sh/uv/) and Apple's Command Line Tools (`xcode-select --install`).

```sh
uvx --python 3.13 --from every-app-is-open-source eaos setup
```

That downloads checksum-pinned Ghidra 12.1.4 and Java 21, and builds Ghidra's Apple Silicon decompiler, because the official download doesn't include one. Everything lands in `~/Library/Application Support/Every App Is Open Source/`. Nothing global, no shell profile edits, no touching your agent's settings. It takes under a minute, and running it again reuses what's there.

## Use it

Point your agent at one program:

```sh
uvx --python 3.13 --from every-app-is-open-source eaos mcp /absolute/path/to/program
```

For an MCP client config, the command is `uvx` and the arguments are:

```json
["--python", "3.13", "--from", "every-app-is-open-source", "eaos", "mcp", "/absolute/path/to/program"]
```

Or try a single tool from the terminal:

```sh
uvx --python 3.13 --from every-app-is-open-source eaos call /absolute/path/to/program open_program
```

The server only sees the one program you give it. It can't read other files on your machine.

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

That was REA's worst habit: a name-based guess labelled "observed, exact." Here, every answer says what it is:

- **fact**: read straight from the binary
- **computed**: worked out deterministically, like decompiled code or a decoded string
- **guess**: an interpretation with nothing solid behind it

Decompiled code is computed, not the original source. When a tool fails, it says it failed.

## Analyze once, reuse forever

Ghidra's analysis is slow, so each program gets its own `eaos-analysis/<sha256>/` folder right next to it, holding the analyzed project and every piece of evidence. Opening the same program again reuses all of it.

One Ghidra quirk: it won't create projects inside a folder whose name starts with a dot, like `.cache`. Keep the program you're analyzing out of those.

## From a checkout

If you'd rather run it from the repo:

```sh
./install.sh
./eaos mcp /absolute/path/to/program
```

Same requirements. Java, Ghidra and Python all install inside the checkout.

## What's next

I only claim "better" where I've measured it:

| Area | Status |
|---|---|
| Compiled programs | ✅ Beat REA and GhidraMCP on cost and speed, on modified Doom |
| JavaScript / Electron apps | Next: VS Code, with its own hidden answer key |
| Android apps | Planned |
| .NET apps | Planned |
| Websites, watching apps run | Planned |

Each one gets the same treatment: a secretly modified target, a frozen answer key and a fair fight against REA, before I claim anything.

## Rerun my test

```sh
uv run python -m unittest discover -s tests -v
python3 benchmark/build_doom.py
```

`build_doom.py` makes a fresh build with new random changes, so you get your own answer key. The binary and answer key from my run stay private, since publishing them would spoil the test. In the saved reports, file paths from my machine are shortened to `<repo>`.

## Credits

Ghidra and PyGhidra do the heavy lifting; they're the work of their own contributors. The comparison baseline is LaurieWired's GhidraMCP. The test target is Chocolate Doom, based on id Software's Doom and released under GPLv2.

## License

[Apache 2.0](LICENSE). If you build on this, keep the [NOTICE](NOTICE) file. Before you point it at anything, read the [disclaimer](DISCLAIMER.md).
