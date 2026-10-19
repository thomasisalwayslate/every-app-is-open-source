# Connect an MCP client

Run setup and compile the example in [SETUP.md](SETUP.md) first. Replace `/absolute/path/to/program` with the selected binary; the server cannot switch targets during a session. These commands select version 0.1.2. For local wheel checks, replace the `--from` value with the absolute wheel path.

## Claude Code

```sh
claude mcp add --transport stdio --scope local eaos -- uvx --python 3.13 --from every-app-is-open-source==0.1.2 eaos mcp /absolute/path/to/program
claude mcp get eaos
```

This is a deliberate client configuration change made by you, separate from EAOS setup. Approve the server in the client and start a fresh conversation. Check that its seven tools are listed, then ask the example question. A local configuration applies to the current project.

## Codex

```sh
codex mcp add eaos -- uvx --python 3.13 --from every-app-is-open-source==0.1.2 eaos mcp /absolute/path/to/program
codex mcp get eaos
```

Equivalent TOML in your Codex config (use an absolute `uvx` command path if needed):

```toml
[mcp_servers.eaos]
command = "uvx"
args = ["--python", "3.13", "--from", "every-app-is-open-source==0.1.2", "eaos", "mcp", "/absolute/path/to/program"]
startup_timeout_sec = 30
tool_timeout_sec = 180
```

These configuration commands do not require a particular model. The historical benchmark used gpt-6.1-sol with high effort; configuring a different client does not replicate that benchmark. No EAOS installer edits either client's settings for you.

## Generic stdio MCP configuration

```json
{
  "mcpServers": {
    "eaos": {
      "command": "uvx",
      "args": ["--python", "3.13", "--from", "every-app-is-open-source==0.1.2", "eaos", "mcp", "/absolute/path/to/program"]
    }
  }
}
```

Normal stdout is JSON-RPC only; Java/Ghidra logs go to stderr. Analysis tools return JSON text with `classification`, `data`, `limitations`, and an evidence ID/URI. `read_evidence` returns `classification`, the ID/URI, saved text and paging fields. Failures use `isError: true` and an explicit failure scope. Evidence is local to the server's machine; a remote client cannot open its `file:` URIs directly, but can use `read_evidence` by ID.

A schema is available through `tools/list`; inputs are validated by the server before native work. See [TOOL-CONTRACT.md](TOOL-CONTRACT.md) for limits and interpretation.

## Ask about a running analysis

In 0.1.2, `open_program` returns a running status while initial analysis continues in a process owned by the MCP server. Once ready, it returns the program metadata and evidence. Keep the client open while analysis runs.

In the same client conversation, ask “Start analyzing this program; if it is still running, tell me and stop.” Later ask “What is happening with analysis? Check once.” The agent should call `open_program` once and report the observed stage and elapsed time, without inventing a percentage or repeatedly polling. Searching before readiness returns an explicit status-bearing tool error. Keep the client open until analysis finishes; closing it stops unfinished work.

Terminal pre-analysis remains available and synchronous. For a known long analysis, it still provides a way to finish and save the project before starting an AI conversation.

## Candidate verification scope

The historical 0.1.1 check exercised the installed wheel over real stdio MCP, all seven tools and evidence links, with a fresh extraction/build of Java/Ghidra from verified cached archives. Claude Code's `mcp get` health check reported **Connected** using a throwaway configuration directory. Codex's configuration parser accepted the equivalent temporary command/arguments. No normal client configuration was changed.

A separate fresh **Codex CLI agent session** using **gpt-6.1-sol, high effort** then answered the documented example through the installed wheel. It used `open_program`, `search`, `inspect` and `read_evidence`, returned **45**, and explained both branches at `0x100000460`. The retrieved evidence matched the saved file and target hash. The agent received no source or expected answer and had no shell, filesystem, network, skills or memory access. Analysis was already cached. See the [actual walkthrough and public-safe transcript](https://github.com/thomasisalwayslate/every-app-is-open-source/blob/main/docs/DEMO.md). This establishes one successful model/client walkthrough; it is not an independent first-time user test or a new benchmark.
