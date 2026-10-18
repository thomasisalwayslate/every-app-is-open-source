# A real agent walkthrough

A fresh Codex CLI session used **gpt-6.1-sol, high effort**, connected over stdio MCP to the locally installed **0.1.1 candidate wheel** outside the checkout. It could use only EAOS: no shell, filesystem, web, skills or memories. The agent received the question, not the source or expected answer.

> What does quote(6) return? Explain both branches and show the function address and evidence. Retrieve that evidence with read_evidence to verify it.

| Step | Actual tool call | Observed result |
|---|---|---|
| 1 | `open_program {}` | Opened the selected Apple Silicon example; existing analysis reused. |
| 2 | `search {"kind":"functions","pattern":"quote","full":true}` | Found `_quote` at `0x100000460`. |
| 3 | `inspect {"addresses":["100000460"],"mode":"all","full":true}` | Returned assembly, pseudocode and saved evidence. |
| 4 | `read_evidence {"id":"fe8589bb2b826cf2f2f1b2d7ab19059d","limit":12000}` | Retrieved that evidence; its text matches the saved file. |

The agent's final answer:

> **Computed:** `quote(6)` returns **45** (`6 × 7 + 3`).
>
> Function: `_quote` at **`0x100000460`**. Its branches use a signed 32-bit comparison:
>
> - **`x < 4`:** returns `0x13`, or **19**.
> - **`x >= 4`:** returns **`7*x + 3`**, using 32-bit arithmetic.
>
> **Fact:** Saved evidence **`fe8589bb2b826cf2f2f1b2d7ab19059d`** was retrieved with `read_evidence` and verified. It contains the function’s assembly and recovered pseudocode supporting this computation.

[Full public-safe tool transcript](assets/client-walkthrough.json) · [Compile and try the same example](SETUP.md#first-result)

This is one successful client walkthrough, not an accuracy or speed benchmark or an independent first-time user test. The cache was already analyzed. Addresses vary with the compiler. The machine-local `file:` URI fields are omitted from the public transcript; tool arguments, content, evidence IDs and hashes are retained. The raw client log is preserved privately.
