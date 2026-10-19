# Changelog

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
