# The seven tools

All argument objects are closed: unknown keys, wrong JSON types, missing required fields, invalid enums and out-of-range numbers are rejected. A string `"false"` is not a boolean; a boolean is not accepted as an integer. Strings are limited to 10,000 characters. MCP request lines are limited to 1 MiB characters. Validation runs before Ghidra initialization.

| Tool | Required input | Optional input / bounds | Result |
|---|---|---|---|
| open_program | none | full: boolean | In MCP: starts/checks analysis and returns live status until ready. Once ready: captured-input hash, architecture, memory map, function count; full metadata on request |
| search | none | kind: strings/functions; pattern: string; offset >= 0; limit 1–200; full: boolean | Matching defined strings/functions, references and next page |
| inspect | addresses: 1–8 strings | mode: decompile/assembly/references/calls/all; full: boolean | Pseudocode, instructions, references or call graph |
| read_memory | address: string | length: 1–65,536; format: hex/utf8/both | Observed bytes at a virtual address |
| calculate | expression: string | Restricted expression AST, <= 2,000 nodes | Computed expression value; does not verify the expression's premises |
| decode_swift_string | words or address | words: two unsigned 64-bit integers or integer strings | Computed Swift small-string decode; pointer-backed layouts fail |
| read_evidence | id: returned 32-character hex ID | offset >= 0; limit 1–40,000 characters | Content-checked saved evidence, paged |

Pseudocode and recovered types/call graphs are **computed** static interpretations. Literal instruction bytes and memory reads are **facts**. Neither proves an interpretation of the program's intent. Indirect calls, undefined strings, unsupported Swift layouts and truncated previews can require more investigation. Full evidence retains the result behind a short preview.

## MCP analysis status

Version 0.1.2 keeps the same seven tools. The first binary-dependent request starts one owned analysis process, waiting up to five seconds for a quick/cached load. If initialization continues, `open_program` returns `classification: fact`, scope `analysis status; no program result`, and `data.analysis` with `state`, `stage`, `elapsed_seconds`, `stage_elapsed_seconds`, `worker_alive` and the captured input `sha256`. This live status has no evidence ID and is not a decompilation claim. Version 0.1.1 did not provide this live status.

Stages are coarse boundaries EAOS observes: `starting`, `importing`, `loading_cache`, `analyzing`, `saving`, then `ready`. They are not Ghidra's internal analyzer messages. Elapsed time and a live worker do not prove forward progress, provide a percentage, or establish time remaining. A failure retains its error and does not silently restart on status checks. After a busy-program-lock error, close the other process and explicitly call `open_program` again to retry. Other initialization failures require a server restart after addressing the error.

While initialization runs, `search`, `inspect`, `read_memory` and decoding at a program address return `isError: true` with `analysis` status instead of accessing partial analysis. Pure calculation, decoding supplied words, saved-evidence retrieval, `ping` and the catalog remain available. When ready, all original result/evidence formats are unchanged. Poll with `open_program` when asked or at a deliberate later checkpoint, not continuously. Native requests after readiness still execute serially.

The process belongs to this MCP server. Closing the client connection ends unfinished work; there is no detached job or resume guarantee. Do not promise continued analysis after client shutdown. A completed project is reused, and interrupted work may need to run again. No input program is executed. Terminal `eaos call` remains synchronous and waits for the requested result.

Read-only native analysis still parses untrusted input using Ghidra/Java/native code and is not an OS sandbox. See [SECURITY.md](../SECURITY.md). Initial analysis has no overall deadline. No per-analysis cancel tool is provided; closing the server ends its owned worker. Do not describe all expensive work as fully bounded.
