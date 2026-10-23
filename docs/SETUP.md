# Setup, filesystem changes and removal

Supported: Apple Silicon macOS, Python 3.13 (uv selects it), uv, and Apple's Command Line Tools. Run `xcode-select --install` yourself if the tools are missing. Intel macOS, Windows and Linux native analysis are not supported by this version. No Homebrew package is required for normal analysis; SDL2 is only for rebuilding the benchmark game.

Install the package and prepare its native runtimes:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos setup
```

To test a reviewed local wheel instead, use `uvx --python 3.13 --from /absolute/path/to/every_app_is_open_source-0.1.9-py3-none-any.whl eaos setup`.

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

For standalone native analysis, copy the executable out of an installed `.app` first. Alternatively, use the [application-directory workflow](#application-directory-workflow) below with an external workspace. Opening its original `Contents/MacOS` path would put EAOS's cache inside the signed bundle, where writes may fail or invalidate its signature. 0.1.7 does not stop you from doing this; 0.1.8 and later refuse an individual executable path inside an `.app`, `.framework` or similar bundle before writing anything. EAOS inspects the copied executable; it does not open the app's documents or execute the app.

```sh
eaos_case="$(mktemp -d /tmp/eaos-app.XXXXXX)"
cp /absolute/path/Example.app/Contents/MacOS/Example "$eaos_case/Example"
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos call "$eaos_case/Example" open_program
```

Keep the copy and its adjacent evidence directory together. A universal executable (check with `lipo -archs`) needs no manual thinning: 0.1.7 selects the ARM64 slice automatically, or use `--architecture` to choose one explicitly (see [analysis options](#017-analysis-options)). An app's main executable may depend on frameworks and resources that are separate analysis targets.

Initial analysis of a large program can take many minutes. In MCP, `open_program` returns the observed stage and elapsed time while work continues; ask the agent to check once when needed. It does not report a percentage or estimate time remaining. Keep the client open. Terminal `eaos call ... open_program` is synchronous, and can also prepare a cached project before a client session. Close the terminal session before opening the same target in MCP.

## Upgrading

Run the current setup command (`eaos setup` from `every-app-is-open-source==0.1.9`) once after upgrading, using the same `EAOS_RUNTIME_DIR` as your client, then restart the MCP client/server. Setup reuses an already installed runtime of the same pinned version instead of downloading it again. A server that already failed initialization needs that restart.

Projects made before 0.1.7 are preserved but not reused: 0.1.7 creates a new project under `profiles/` on first open, so expect one fresh analysis per program. Old projects and evidence are left in place, not migrated or deleted.

### Historical: upgrading from 0.1.1 to 0.1.2

0.1.2 added C++ name-decoding helpers built from the installed Ghidra source. A C++ program analyzed by 0.1.1 kept its old recovered names until re-analyzed. Since 0.1.7 re-analyzes legacy projects anyway, this matters only if you are pinned to 0.1.2–0.1.6: close every EAOS session using that program, **move and preserve** its `eaos-analysis/<sha256>/` directory elsewhere, and reopen it. An interrupted analysis starts over rather than resuming reliably.

## 0.1.7 analysis options

These options were introduced in 0.1.7 and remain available in 0.1.9 after setup:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos call /absolute/path/to/program open_program --architecture arm64 --analysis-mode quick
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos mcp /absolute/path/to/program --analysis-mode quick
```

Full analysis remains the default. Quick mode supports 64-bit ARM/x86 Mach-O. It imports the selected image, recovers available Objective-C metadata and loader-provided names, and searches bounded literal bytes. It does not run whole-program analysis or recover every Swift name. Individual inspections prepare bounded reachable instructions; unresolved indirect jumps, tail edges or unsafe boundaries can leave assembly only or refuse the request. Every affected response reports coverage; missing matches/references do not prove absence.

Universal inputs automatically select ARM64 on Apple Silicon when available (otherwise ARM64e when available); thin inputs keep their architecture. `--architecture arm64|arm64e|x86_64` makes the choice explicit and rejects an unavailable/ambiguous choice. Selection identifies the actual captured slice and verifies its hash, language and mapped executable bytes. No manual `lipo` thinning is needed. ARM64e selection is not a claim that all pointer-authentication constructs decompile correctly.

New projects live under `eaos-analysis/<whole-file-sha256>/profiles/<identity>/`. Identity includes selected slice offset/size/subtype/hash, full/quick profile, pinned Ghidra and index version; the actual compiler/language are validated on reuse. The original whole-file capture remains under `input/`, along with a derived read-only selected slice for universal inputs. Evidence stays under the shared `evidence/`; raw pseudocode uses content-addressed artifacts. Legacy projects and evidence are preserved without destructive migration. One session owns the whole captured target at a time across profiles.

Quick function discovery starts with a bounded prefix. When `search(kind="functions")` reports `coverage.function_candidates.next_index_cursor`, pass that value back as `index_cursor` to request exactly one additional bounded batch (same 50,000-candidate/two-second iteration budget, plus an 8 MiB batch payload limit). Each batch commits atomically in the current profile's derived `function-index-v1.sqlite`; completed progress survives reopening. The index has a 256 MiB payload budget plus SQLite overhead, and reports if it cannot continue. Ordinary searches and result pagination do not grow it.

Use `next_offset` **with `view`** to page the same query's current results. Index expansion changes the view, requires offset zero, and rejects old page/index cursors. Expansion returns cumulative matches, so restart paging deliberately; no old offset silently skips or repeats rows. After cancellation or a stale cursor, restart with offset zero and no cursors to obtain current progress. A complete candidate index still does not mean complete symbol recovery or analysis. See the [continuation contract](TOOL-CONTRACT.md#bounded-function-discovery-continuation) for limits, cursor identity and failure recovery.

In MCP, `open_program` with `{"analysis_mode":"full"}` explicitly opens the separate full-analysis profile. It does not promote a partial cache or erase previous evidence. `full=true` still controls output detail only. The same choice is available to terminal calls with `--analysis-mode full`.

CLI/MCP defaults are a 3,600-second initialization deadline and a 120-second native-operation deadline. Set `--analysis-timeout` and `--request-timeout` in seconds (0.05–7,200). MCP status and ping remain available while native work runs. `open_program` with `{"cancel":true}`, a matching MCP cancellation notification or client shutdown stops owned work. A cancelled/deadline-expired session must be restarted; interrupted work has no resume guarantee. Objective-C metadata has a 30-second budget, requested-function preparation 15 seconds, and decompilation 20 seconds in quick mode / 60 in full mode. A live process and elapsed time still provide no percentage or ETA.


## Application-directory workflow

0.1.9 adds selected-root inventory and explicit component inspection. Configure the native runtimes with setup first; no additional dependencies are required for this workflow. It does not integrate a separate app or change any client configuration automatically:

```sh
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos mcp /Applications/YourApp.app --workspace /absolute/path/outside-bundles/analysis
```

In that persistent MCP session, call `inventory_application`, then `select_component` with an inventory-returned native component ID. `open_program` starts/checks analysis; full remains default. Use `analysis_mode="quick"` explicitly when partial metadata is sufficient. `search`, `inspect` and `trace_calls` operate on that one selected component. For inventoried JavaScript, use `inspect_javascript` with its component ID instead of selecting it as native. No target program or JavaScript is executed.

Native sessions expose eight tools; application sessions expose eleven. The workspace contains immutable inventory snapshots, component captures, evidence and ordinary native profile caches. It must be outside the original root and all signed bundles. Nothing is written into the app. Symlinks, unsupported ASAR members, dynamic JavaScript and budget omissions remain explicit. This is a narrow static inspection slice, not general Electron/Swift recovery or evidence of runtime behavior. See [TOOL-CONTRACT.md](TOOL-CONTRACT.md#application-scope-and-bounded-call-traversal) for exact limits, selection, paging, identities and cancellation.

The default directory inventory is bounded to 10,000 entries, depth 16, 128 MiB per file, 512 MiB aggregate hashed bytes and 15 seconds. JavaScript inspection is limited to 1 MiB per component; unsupported syntax and dynamic values remain explicit. Reopening inventories the selected root again; changed inputs receive different snapshot/component identities. Old captures and evidence remain on disk. In a reopened application session, inventory the root to activate its application evidence scope; reselect the original native component to retrieve its native evidence. Captures whose original bytes no longer match are refused rather than silently rebound.

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
uvx --python 3.13 --from every-app-is-open-source==0.1.9 eaos call /tmp/eaos-example/example open_program
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
- **Analysis takes time:** 0.1.7 defaults to a 3,600-second initialization deadline and a 120-second native-request deadline; both are configurable as described above. In MCP, ask for `open_program` status while it runs; terminal calls wait synchronously. A completed analysis is reused; interrupted work may need to start over. Per-function decompilation is limited to 60 seconds, and native requests after readiness still run serially.

## Uninstall

First close EAOS clients. Preserve any evidence you want to keep. Delete only the managed runtime directory listed above (or your explicitly chosen `EAOS_RUNTIME_DIR`); it contains this tool's Java and Ghidra, not system Java. A checkout can remove its own `.tools/` and `.venv/` instead.

Remove the EAOS entry from your client's configuration using `codex mcp remove eaos` or `claude mcp remove eaos` if you added it. Delete individual `eaos-analysis/<sha256>/` directories beside your own programs only when you no longer need those projects/evidence. uvx does not install a permanent `eaos` command globally; `uv cache clean every-app-is-open-source` removes that package's cached entries without clearing unrelated packages.
