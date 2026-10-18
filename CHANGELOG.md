# Changelog

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
