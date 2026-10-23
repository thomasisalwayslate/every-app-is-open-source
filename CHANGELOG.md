# Changelog

## 0.1.7 — Unreleased

- Reject corrupt candidate search keys before filtering/paging, inconsistent cached payload accounting and nonfinite batch provenance. Verify evidence content IDs and target scope when reading. Check that wheel and source archives contain every reviewed runtime module with matching bytes. Keep conservative discovery invalidation after real function preparation; repeated inspection of prepared functions reuses committed progress.

- Select the compatible ARM64 slice of universal Mach-O inputs on Apple Silicon, with explicit architecture selection and unavailable-choice rejection. Keep immutable whole-file and selected-slice identities; validate slice bytes, Ghidra language/compiler and architecture/profile/engine-aware caches. Preserve legacy projects and evidence without migration.
- Search available class/namespace-qualified names and aliases while preserving duplicate/overloaded entries and external address spaces. Keep compact previews and avoid whole-binary demangling. Loader/Objective-C metadata is not a guarantee of original Swift name recovery.
- Add opt-in quick analysis for 64-bit ARM/x86 Mach-O; full stays default. Expose supported metadata and bounded literal searches, prepare requested functions with reachable-flow/ownership validation and independent readiness, and retain useful assembly when safe decompilation is unavailable. Report partial coverage in compact results and evidence.
- Keep MCP status/ping responsive during native operations. Add configurable initialization/request deadlines, cancellation and owned-worker shutdown. Explicit full-mode transition uses a separate profile, preserving evidence. Invalidate analysis views after mutations and save raw pseudocode as immutable content-addressed artifacts.
- Add explicit, bounded quick-function index continuation through search, separately from view-bound result pagination. Persist contiguous candidate progress transactionally inside each profile; bind cursors to input, architecture, schema and revision, reject stale views, and retain previous progress/evidence after interruption. Report candidate counts, completion, stop reasons, result/index continuation and match scope in compact output and saved evidence. Keep cancellation shutdown off the reader, expose the cancelling state and reject new native work until shutdown completes.
- Add portable failure-case tests and small native Objective-C/Swift/universal fixtures. Local readiness/discovery checks used instrumented study binaries; they do not establish shipping-app behavior or general performance. Separate local app/model acceptance checks do not establish reliable answer accuracy. No new comparative benchmark or general performance/accuracy claim follows from these changes.

## 0.1.6 — 2026-10-20

- Distinguish initialized analyzed-image bytes, validated Mach-O loader initial zeros and unavailable memory; preserve per-segment provenance and reject synthetic/partial Swift storage. Keep ordinary initialized-memory replies compact, with full provenance in saved evidence.
- Extend read_memory with explicit, bounded Go pointer/length table decoding, program-derived byte order/pointer width, invalid-entry reporting and paged compact previews with complete evidence.
- Keep paired focused code/instruction views explicit through mode=all, omit unrelated call lists and keep missing mappings explicit. Honor requested call-list limits within the reply budget; keep the existing seven tools and focus occurrence selector.
- Add malformed-loader, partial-read, descriptor, pagination and evidence-integrity regressions plus an opt-in native fixture. Historical tool-request replays are diagnostic checks, not new model benchmark or performance claims.

## 0.1.5 — 2026-10-20

- Replace large-function head previews with compact outlines of callees, referenced text and candidate return/error sites. Code batches return outlines; complete rendered code and address mappings remain in saved evidence.
- Extend `inspect` with in-function literal text and decimal/hex integer search in decompiled code and assembly, returning matching lines, bounded context, available addresses and match pagination. Integer search is lexical, not expression evaluation or runtime value recovery.
- Add focused inspection by instruction, string reference or call, including assembly-only operation without successful decompilation. Keep missing mappings and scan limits explicit rather than substituting guessed code locations.
- Make sequential code reads resumable with bounded line/column pages, preserving long lines. Keep the same seven tools, content-checked evidence and fact/computed/guess labels; recommend outline, then search/focus, then paging.
- Add portable failure-case regressions and a native fixture covering search, focus, complete pagination, reply bounds and evidence integrity. This release makes no new benchmark performance or accuracy claim.

## 0.1.4 — 2026-10-19

- Extend the existing seven-tool interface with bounded Go pclntab name discovery and literal-byte string search, including stored Ghidra references at the actual match address. Keep matched slices distinct from complete strings and preserve full evidence.
- Enrich inspected functions with recovered Go names without renaming Ghidra's project or claiming repaired Go types/ABI. Cache the metadata index beside the program and reuse existing Ghidra analysis; report indexing status and unsupported layouts.
- Add malformed-metadata, cache-integrity and string-boundary regressions, a small stripped Go fixture and an opt-in native MCP walkthrough. Native checks cover Go 1.25.14 and 1.27.1 on Apple Silicon; missing stored references remain explicitly reported. This work has no new model benchmark or performance claim.

## 0.1.3 — 2026-10-19

- Add `every-app-is-open-source` as an alias of `eaos` so MCP Registry clients can launch the package by its PyPI name. The short command and seven-tool interface stay the same.
- Prepare versioned MCP Registry metadata with Python 3.13, stdio transport and a required native-program path. The listing requires this package version to be published first; preparing the metadata does not submit it.

## 0.1.2 — 2026-10-19

- Keep MCP responsive during initial native analysis with one owned worker process. `open_program` reports the observed coarse stage and elapsed time until ready; premature native queries return status-bearing errors. Keep the seven tools, captured-input identity, honest labels and evidence formats.
- Reuse completed analyses. Closing the client stops unfinished analysis; interrupted work may need to start over. Terminal calls remain synchronous.
- Recover from a busy-program lock on the next explicit `open_program` request once the other session closes. Status checks do not create retry loops; other initialization failures require a server restart after addressing their cause.
- Build and validate both GNU C++ demanglers on Apple Silicon using Ghidra's bundled source and the existing Apple compiler. Preserve a working helper if compilation fails.
- **Upgrade:** run `eaos setup` once, then restart your MCP client. Previously cached C++ analyses keep their old names; preserve and move the specific analysis directory aside to request a fresh analysis with the new helpers.
- Harden the audit-only benchmark adapter: validate arguments against each tool's declared fields, reject unknown nested keys, and resolve target/export paths and symlinks before forwarding calls. Add portable regressions to CI. This interface boundary is not an operating-system sandbox.

Historical published benchmark results retain their original version and scope; this release makes no new performance or accuracy claim.

## 0.1.1 — 2026-10-18

- Capture and hash the same input snapshot that Ghidra imports. Changes to the selected path after opening a session no longer change that session's input.
- Reject imported/cached Ghidra programs whose executable hash differs from the input hash; preserve affected caches and evidence for inspection. Failed loading releases the session lock.
- Validate tool argument types, keys, enums and bounds before native analysis in both CLI and MCP calls. Reject string booleans and booleans used as integers. Bound MCP request lines and expression/string inputs.
- Add input-integrity, poisoned-cache and input-validation regression tests, plus push/PR verification independent from publishing.
- Add checksum-pinned Chocolate Doom source preparation and an isolated target-build option. New manifests stay beside their new private builds; saved benchmark results are unchanged.
- Document filesystem permissions, runtime downloads, uninstall, the supplied example, client configuration and benchmark limits. Verify the example with a fresh Codex agent session using the installed candidate and retrieved evidence.

The 0.1.0 performance comparison has not been rerun for 0.1.1. These fixes do not establish new speed, cost or accuracy claims.

## 0.1.0 — initial release

Seven native-analysis tools, managed Java/Ghidra setup on Apple Silicon macOS, persistent analysis and content-checked evidence. Saved modified-Doom comparison against REA 6.7.0 with its bundled skill and community GhidraMCP.
