# The seven tools

All argument objects are closed: unknown keys, wrong JSON types, missing required fields, invalid enums and out-of-range numbers are rejected. A string `"false"` is not a boolean; a boolean is not accepted as an integer. Strings are limited to 10,000 characters. MCP request lines are limited to 1 MiB characters. Validation runs before Ghidra initialization.

| Tool | Required input | Optional input / bounds | Result |
|---|---|---|---|
| open_program | none | full: boolean | Captured-input hash, architecture, memory map, function count; full metadata on request |
| search | none | kind: strings/functions; pattern: string; offset >= 0; limit 1–200; full: boolean | Matching defined strings/functions, references and next page |
| inspect | addresses: 1–8 strings | mode: decompile/assembly/references/calls/all; full: boolean | Pseudocode, instructions, references or call graph |
| read_memory | address: string | length: 1–65,536; format: hex/utf8/both | Observed bytes at a virtual address |
| calculate | expression: string | Restricted expression AST, <= 2,000 nodes | Computed expression value; does not verify the expression's premises |
| decode_swift_string | words or address | words: two unsigned 64-bit integers or integer strings | Computed Swift small-string decode; pointer-backed layouts fail |
| read_evidence | id: returned 32-character hex ID | offset >= 0; limit 1–40,000 characters | Content-checked saved evidence, paged |

Pseudocode and recovered types/call graphs are **computed** static interpretations. Literal instruction bytes and memory reads are **facts**. Neither proves an interpretation of the program's intent. Indirect calls, undefined strings, unsupported Swift layouts and truncated previews can require more investigation. Full evidence retains the result behind a short preview.

Read-only native analysis does not execute the selected program. It still parses untrusted input using Ghidra/Java/native code and is not an OS sandbox. See [SECURITY.md](../SECURITY.md). The initial analysis can run for a long time; the current synchronous server does not provide cancellation or an overall analysis deadline. Clients can terminate the process. Do not describe all expensive work as fully bounded.
