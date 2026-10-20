# The seven tools

All argument objects are closed: unknown keys, wrong JSON types, missing required fields, invalid enums and out-of-range numbers are rejected. A string `"false"` is not a boolean; a boolean is not accepted as an integer. Strings are limited to 10,000 characters. MCP request lines are limited to 1 MiB characters. Validation runs before Ghidra initialization.

| Tool | Required input | Optional input / bounds | Result |
|---|---|---|---|
| open_program | none | full: boolean | In MCP: starts/checks analysis and returns live status until ready. Once ready: captured-input hash, architecture, memory map, function count; full metadata on request |
| search | none | kind: strings/functions; pattern: string; offset >= 0; limit 1–200; full: boolean | Defined strings/functions plus supported Go metadata names and literal matches, references and next page |
| inspect | addresses: 1–8 strings | mode: decompile/outline/assembly/references/calls/all; full; offset/column >= 0; limit 1–80; find or focus; context 0–20 | Outline first, then matching lines or focused snippets; bounded pages last |
| read_memory | address: string | length: 1–65,536; format: hex/utf8/both | Observed bytes at a virtual address |
| calculate | expression: string | Restricted expression AST, <= 2,000 nodes | Computed expression value; does not verify the expression's premises |
| decode_swift_string | words or address | words: two unsigned 64-bit integers or integer strings | Computed Swift small-string decode; pointer-backed layouts fail |
| read_evidence | id: returned 32-character hex ID | offset >= 0; limit 1–40,000 characters | Content-checked saved evidence, paged |

Pseudocode and recovered types/call graphs are **computed** static interpretations. Literal instruction bytes and memory reads are **facts**. Neither proves an interpretation of the program's intent. Indirect calls, undefined strings, unsupported Swift layouts and truncated previews can require more investigation. Full evidence retains the result behind a short preview.

## Focused inspection (unreleased)

The same seven tools now expose bounded inspection views. Released 0.1.4 does not include these changes yet.

- A single small function can return its code. Above 5,000 characters, the default is an outline, rather than a head preview: size, callees with call-site addresses, referenced text previews, return sites and error candidates. Error candidates are **name-based hints**, not proven error paths. Callees retain first-call order, with Go runtime/internal helpers last. Outline categories include totals and independent next offsets; `mode="outline"` with `offset` pages them.
- A request for multiple code functions returns outlines, even with `full=true`. Ask for one address to read code. This prevents eight whole functions arriving together.
- Start with the outline; use `find` or `focus` to narrow the investigation. Read sequential code pages only when those views are insufficient. `find={kind: "text", value: "<literal>"}` searches rendered lines case-insensitively, without regular expressions. `find={kind: "constant", value: "422"}` (or `"0x1a6"`) compares lexical decimal/hex integer tokens, ignoring quoted text and comments; it does not evaluate expressions, floating-point values, types, signed bit patterns or values built across instructions. It works on one function in `decompile` or `assembly` mode. It does not search referenced memory: use the top-level `search` or string `focus` for that.
- Search replies contain only matching lines with small context (two lines on each side by default), one hit per line, available instruction addresses and original line/column positions. No guessed address replaces an unmapped C line. Context and long text can be shortened to preserve the match within the reply budget. At most eight matching lines arrive per reply, further reduced by `limit` and a 6,000-character match-list budget. `find.next_offset` resumes **matching lines**, not code lines; repeat the same query, mode and function with that top-level `offset`. Totals describe rendered-line matches, not all runtime values. Empty matches do not prove the value is absent from the program. `find` cannot combine with `focus` or a column cursor.
- For one function, `full=true` returns one code page, up to 6,000 characters and `limit` lines (40 by default, at most 80). The first page of a large function also includes a compact outline. Follow the returned `next: {offset, column}` with the same function and mode. Offsets are zero-based; displayed line numbers are one-based. The column cursor preserves long single lines without lost or duplicated text. `next=null` means the end. Earlier code may be omitted when a page starts in the middle.
- `focus={kind: "address", value: "<instruction address>"}` selects a mapped instruction. `kind="string"` accepts a referenced text address or **text prefix**; a substring found only in adjacent packed text is not attributed to the earlier reference. `kind="call"` accepts a callee address or name fragment. Use `occurrence` (zero-based, inside `focus`) to move between matches, following `next_occurrence`. `context` defaults to six lines on either side; `limit` and the character budget can reduce that window.
- A focused snippet is surrounding pseudocode, **not a data-flow or control-flow slice**. Omitted checks can matter. Ghidra Clang tokens and pcode PCs supply the line mappings. When a matched instruction has no mapped line, the result explicitly returns a bounded **assembly-only** window. It never substitutes the nearest pseudocode line. A missing match is not proof of absence. Focus cannot leave the selected function.
- `mode="assembly"` also accepts all three focus kinds, returning a window around the actual matching instruction. Assembly focus uses instruction/data-reference metadata directly and does not require successful decompilation. Its match line number is an instruction-list index, not a C line. Search/focus selection is labelled `computed`; literal instruction bytes remain observations.
- Assembly, incoming references and caller/callee lists also page with `offset` and `limit`. Full evidence retains complete requested native lists. Code batches are bounded to 16,000 serialized data characters plus list separators; code pages are capped at 6,000 characters. Totals and continuation cursors survive list trimming.

Examples (use addresses discovered from your own target):

```json
{"addresses":["<function entry>"],"focus":{"kind":"string","value":"<text prefix>"},"context":10}
{"addresses":["<function entry>"],"focus":{"kind":"call","value":"<callee name>"},"context":6}
{"addresses":["<function entry>"],"find":{"kind":"constant","value":"422"},"context":2}
{"addresses":["<function entry>"],"mode":"assembly","find":{"kind":"text","value":"cmp"}}
{"addresses":["<function entry>"],"mode":"assembly","focus":{"kind":"address","value":"<instruction address>"}}
{"addresses":["<function entry>"],"full":true,"offset":80,"column":0,"limit":40}
```

Read-only text previews are at most 256 bytes; Go pointer/length candidates are explicitly labelled `guess`, not verified string objects; raw text previews are `fact` and reference/code interpretations remain `computed`. Outlines scan at most 100,000 instructions and retain at most 2,048 string-reference previews per function, with incomplete coverage reported. Optimized instructions and nonstandard string constructions may lack mappings or previews. Existing raw memory, assembly, call/reference inspection and content-checked evidence remain available. Full function code and line/address mappings are saved alongside each result, including the exact returned view. An in-process cache retains at most 64 function views / 32 MiB of serialized data (Python/Java overhead is additional); it does not modify Ghidra or prior evidence.

## MCP analysis status

Version 0.1.2 keeps the same seven tools. The first binary-dependent request starts one owned analysis process, waiting up to five seconds for a quick/cached load. If initialization continues, `open_program` returns `classification: fact`, scope `analysis status; no program result`, and `data.analysis` with `state`, `stage`, `elapsed_seconds`, `stage_elapsed_seconds`, `worker_alive` and the captured input `sha256`. This live status has no evidence ID and is not a decompilation claim. Version 0.1.1 did not provide this live status.

Stages are coarse boundaries EAOS observes: `starting`, `importing`, `loading_cache`, `analyzing`, `saving`, optionally `indexing_go`, then `ready`. They are not Ghidra's internal analyzer messages. Elapsed time and a live worker do not prove forward progress, provide a percentage, or establish time remaining. A failure retains its error and does not silently restart on status checks. After a busy-program-lock error, close the other process and explicitly call `open_program` again to retry. Other initialization failures require a server restart after addressing the error.

While initialization runs, `search`, `inspect`, `read_memory` and decoding at a program address return `isError: true` with `analysis` status instead of accessing partial analysis. Pure calculation, decoding supplied words, saved-evidence retrieval, `ping` and the catalog remain available. When ready, tools return their documented results. Poll with `open_program` when asked or at a deliberate later checkpoint, not continuously. Native requests after readiness still execute serially.

The process belongs to this MCP server. Closing the client connection ends unfinished work; there is no detached job or resume guarantee. Do not promise continued analysis after client shutdown. A completed project is reused, and interrupted work may need to run again. No input program is executed. Terminal `eaos call` remains synchronous and waits for the requested result.

Read-only native analysis still parses untrusted input using Ghidra/Java/native code and is not an OS sandbox. See [SECURITY.md](../SECURITY.md). Initial analysis has no overall deadline. No per-analysis cancel tool is provided; closing the server ends its owned worker. Do not describe all expensive work as fully bounded.

## Go discovery

The seven input schemas are unchanged. On detected Go programs, `open_program.data.go` reports the embedded compiler version when its inline build-info encoding is supported, metadata-name availability, parser version and literal-scan coverage. Unknown build-info versions do not establish that a binary is not Go. Go discovery does not replace Ghidra's version-specific type/ABI analysis.

`search(kind="functions", pattern="...")` merges recognized Go pclntab names and Ghidra functions by entry address. `source: go_pclntab` means a name was parsed from retained artifact metadata; it does not recover original source. Duplicate names at different entries remain separate. `inspect` enriches an analyzed function with its Go name and retains `ghidra_name`. A metadata entry without a Ghidra function is explicitly marked `analyzed_function: false`; inspection fails honestly rather than manufacturing pseudocode. Metadata offsets and table provenance are retained in full evidence.

For nonempty string patterns, Go search also scans initialized, read-only, non-executable blocks, excluding named pclntab. `source: literal_bytes` and `extent: match` identify a **matched slice**, not a complete Go string object. Go literals can be packed, contain zero bytes and occur inside longer strings. ASCII byte search is case-insensitive; other UTF-8 literals require exact bytes. Defined-string search retains its Unicode case folding. Empty patterns list only Ghidra-defined strings. Coverage describes this literal scan, not every possible string, function or runtime value in the application.

References come from Ghidra's stored reference manager at the actual matched address. They are computed static links, and can be empty even when a human can see address construction in assembly. No hidden whole-program decompilation or inferred reference pass runs during search. On a stripped Go 1.25.14 fixture, some discovered literals had no stored references; this remains a limitation. Raw match bytes are observable; address mapping, decoded names and reference interpretation are computed. Assembly with recovered Go names is therefore labelled computed as a whole.

Default search previews cap text at 256 characters and references at eight, preferring code references. Totals and truncation are explicit. `full=true` expands the result; `read_evidence` retrieves the saved record. Reference collection is capped at 4,096 per hit; `references_complete: false` makes the reported count a lower bound. Raw literal matches stop at 10,000 and report incomplete coverage; refine the query. Literal indexing and metadata scanning each have a 64 MiB budget, and metadata parsing accepts at most 500,000 entries and 4,096 bytes per name. Oversized or unsupported metadata produces an availability error while ordinary Ghidra capabilities remain usable.

Go name indices are stored beside the selected program in `eaos-analysis/<digest>/go-index-v1.json` with a checksum, bound to the captured target, metadata bytes and parser version. Existing Ghidra projects are reused; Go indexing does not increment `analysis_count` or rewrite historical evidence. Replaced invalid indices are retained alongside the cache. Closing the MCP server stops its owned indexing worker.

The parser recognizes Go 1.18 and 1.20 pclntab layout families, not every future compiler or executable mapping. Native integration has been checked on stripped darwin/arm64 fixtures compiled with Go 1.25.14 and 1.27.1. Multi-section text, obfuscation, absent metadata, unusual load mappings and unsupported layouts may fail discovery. No broader platform, decompilation-accuracy or agent-performance claim follows from those checks.
