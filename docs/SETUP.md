# Setup, filesystem changes and removal

Supported: Apple Silicon macOS, Python 3.13 (uv selects it), uv, and Apple's Command Line Tools. Run `xcode-select --install` yourself if the tools are missing. Intel macOS, Windows and Linux native analysis are not supported by this version. No Homebrew package is required for normal analysis; SDL2 is only for rebuilding the benchmark game.

Install the package and prepare its native runtimes:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.2 eaos setup
```

To test a reviewed local wheel instead, use `uvx --python 3.13 --from /absolute/path/to/every_app_is_open_source-0.1.2-py3-none-any.whl eaos setup`.

## What setup runs and downloads

- uv installs the Python package and its pinned dependencies, and may download Python 3.13 if needed. Python/dependency cache location follows uv's settings.
- Java: Eclipse Temurin JDK 21.0.12.1+1, **200,073,404 bytes** compressed, from Adoptium's GitHub release.
- Ghidra: NSA Ghidra 12.1.4, **569,649,598 bytes** compressed. Setup resolves the one ZIP asset from that pinned GitHub release.
- Java/Ghidra archives are checked against both their recorded byte size and SHA-256 before extraction. The pins are in `src/eaos/distributions.json`; source URL selection is in `src/eaos/runtime.py`.
- Setup extracts archives and uses Apple's existing make/clang++ tools to build the ARM64 decompiler from Ghidra's included source, plus clang to build both bundled GNU C++ demanglers. It downloads no additional source or build tools. Setup checks the native architecture, Java version and C++ name decoding.
- The two native archives total about **770 MB** before extraction; allow several GB for archives, extracted files and compilation. Duration depends on network and machine; there is no under-a-minute guarantee.

For the installed package, managed files live under:

```text
~/Library/Application Support/Every App Is Open Source/runtimes/
  distributions/           verified downloaded archives
  ghidra_12.1.4_PUBLIC/    Ghidra and compiled decompiler
  jdk-21.0.12.1+1/         Java
  setup.json              receipt and versions
  decompiler-build.log    compiler output
  gnu-demangler-build.log C++ name decoder compiler output
  java-state/             Java preferences/state during analysis
```

`EAOS_RUNTIME_DIR` overrides this location. A checkout's `./install.sh` uses `.tools/` and `.venv/` instead. Setup does not change shell profiles, system Java, or agent configuration.

When opening a program, EAOS writes `eaos-analysis/<sha256>/` **beside that program**: a read-only captured input under `input/`, a Ghidra project, session lock, analysis metadata/log, and generated evidence. Your user needs write access there. Each session analyzes its captured bytes; restart the server to pick up a changed original file. A program/Ghidra hash mismatch fails closed and preserves the affected cache.

## macOS app bundles

Copy the executable out of an installed `.app` before analysis. Opening its original `Contents/MacOS` path would put EAOS's cache inside the signed bundle, where writes may fail or invalidate its signature. EAOS inspects the copied executable; it does not open the app's documents or execute the app.

```sh
eaos_case="$(mktemp -d /tmp/eaos-app.XXXXXX)"
cp /absolute/path/Example.app/Contents/MacOS/Example "$eaos_case/Example"
lipo -archs "$eaos_case/Example"
```

Keep the copy and its adjacent evidence directory together. A universal Mach-O contains more than one architecture; choose the intended slice explicitly before analysis. For a copy listing both `x86_64` and `arm64`:

```sh
lipo "$eaos_case/Example" -thin arm64 -output "$eaos_case/Example-arm64"
uvx --python 3.13 --from every-app-is-open-source==0.1.2 eaos call "$eaos_case/Example-arm64" open_program
```

If the executable is already a single architecture, use that copy directly. `arm64e` is a separate architecture name; this example does not establish support for it. An app's main executable may depend on frameworks and resources that are separate analysis targets.

Initial analysis of a large program can take many minutes. In MCP, `open_program` returns the observed stage and elapsed time while work continues; ask the agent to check once when needed. It does not report a percentage or estimate time remaining. Keep the client open. Terminal `eaos call ... open_program` is synchronous, and can also prepare a cached project before a client session. Close the terminal session before opening the same target in MCP.

## Upgrade from 0.1.1

Run the 0.1.2 setup command once after upgrading, using the same `EAOS_RUNTIME_DIR` as your client. It builds the newly required C++ helpers from the already installed Ghidra source, without downloading another runtime. Then restart the MCP client/server. A server that already failed initialization needs that restart.

Completed analyses are reused. A C++ program analyzed before the helpers were available keeps its old recovered names. To re-analyze it with the new helpers, first close every EAOS session using that program, then **move and preserve** its specific `eaos-analysis/<sha256>/` directory elsewhere. Reopen the copied program to create a new analysis. Keep the previous project and evidence if they are still useful; an interrupted analysis starts over rather than resuming reliably.

## First result

This makes a tiny program you own. It needs only the Command Line Tools already required by setup:

```sh
mkdir -p /tmp/eaos-example
cat > /tmp/eaos-example/example.c <<'C'
#include <stdio.h>
__attribute__((noinline)) int quote(int n) { return n < 4 ? 19 : n * 7 + 3; }
int main(int argc, char **argv) { puts("eaos fixture anchor"); return quote(argc); }
C
clang -O0 /tmp/eaos-example/example.c -o /tmp/eaos-example/example
uvx --python 3.13 --from every-app-is-open-source==0.1.2 eaos call /tmp/eaos-example/example open_program
```

Expect `classification: computed`, an ARM64 language, a SHA-256, a positive function count and an evidence ID/file URI. Addresses vary by compiler; never copy an address from somebody else's run.

Connect your client using [CLIENTS.md](CLIENTS.md), then ask:

> Find the quote function in this binary. What does quote(6) return? Explain both branches and cite the function address and saved evidence.

Expected: **45**, computed from the recovered logic. For n below 4 it returns **19**; otherwise it returns **7n + 3**. This is the expected example result, not a claim that every agent will answer correctly. You can also use `search` with `{"kind":"functions","pattern":"quote"}` and `inspect` at its returned address from the terminal.

## Troubleshooting

- **Run eaos setup first:** the client and setup must use the same `EAOS_RUNTIME_DIR` and user. Check the printed runtime directory.
- **Unsupported platform:** this is an explicit supported-platform check; do not bypass it and assume native analysis was tested there.
- **Cannot create Ghidra project:** Ghidra rejects projects under a dot-prefixed directory. Put the selected program in an ordinary writable directory such as `/tmp/eaos-example`.
- **Already open:** close the other server/client session. In MCP, explicitly call `open_program` again to retry after that lock error; other initialization failures still require restarting the server. Do not delete an active lock file to bypass it.
- **Hash mismatch / affected 0.1.0 cache:** preserve and move that specific `eaos-analysis/<sha256>/` directory aside, then restart against the original binary. The new session will create a fresh cache. Do not treat existing mismatched records as verified evidence.
- **Client cannot find uvx:** use the absolute result of `command -v uvx` in its config and restart the client.
- **Analysis takes time:** initial analysis has no overall timeout. In MCP, ask for `open_program` status while it runs; terminal calls wait synchronously. A completed analysis is reused; interrupted work may need to start over. Per-function decompilation is limited to 60 seconds, and native requests after readiness still run serially.

## Uninstall

First close EAOS clients. Preserve any evidence you want to keep. Delete only the managed runtime directory listed above (or your explicitly chosen `EAOS_RUNTIME_DIR`); it contains this tool's Java and Ghidra, not system Java. A checkout can remove its own `.tools/` and `.venv/` instead.

Remove the EAOS entry from your client's configuration using `codex mcp remove eaos` or `claude mcp remove eaos` if you added it. Delete individual `eaos-analysis/<sha256>/` directories beside your own programs only when you no longer need those projects/evidence. uvx does not install a permanent `eaos` command globally; `uv cache clean every-app-is-open-source` removes that package's cached entries without clearing unrelated packages.
