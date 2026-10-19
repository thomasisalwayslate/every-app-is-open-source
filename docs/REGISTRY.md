# MCP Registry listing

I keep the Registry metadata in [`server.json`](../server.json). It describes a local stdio server for native programs on Apple Silicon macOS. It does not add JavaScript, Android or other planned coverage.

## Before connecting

Install uv and Apple Command Line Tools, then run the published version's setup command. Setup manages Java and Ghidra and builds the native helpers. The server does not run setup automatically when a client connects.

`eaos` remains the short command. Starting with the prepared 0.1.3 package, `every-app-is-open-source` is an alias of the same entry point. Registry clients commonly launch a package by its identifier; the additional name makes that work.

The manifest produces this command after a client supplies the program path:

```sh
uvx --python 3.13 every-app-is-open-source@0.1.3 mcp /absolute/path/to/program
```

The program path is required. `EAOS_RUNTIME_DIR` is optional; if supplied, use the same directory for setup and the client. Analysis projects and evidence are saved beside the selected program.

## Publication gates

The manifest is prepared, not listed. **0.1.3 must be approved, released and tested on PyPI before submitting this metadata.** The published 0.1.2 package only provides `eaos` and cannot run the command above.

The Registry's unauthenticated `/v0.1/validate` endpoint can check schema and semantic validity without installing a tool or publishing a listing. That check does not establish package availability, namespace authorization, or successful installation by every Registry consumer.

After the package release and explicit installation approval, use the official `mcp-publisher` CLI. GitHub login is a separate interactive step; do not copy or paste account tokens into project files. Submission is a separate action after validation and login. Preparing a PR does not submit the server.

For future capabilities, release a tested package and publish a new Registry version with updated metadata. Published Registry versions are immutable; keep the server name stable.

References: [package verification](https://modelcontextprotocol.io/registry/package-types), [publishing](https://modelcontextprotocol.io/registry/quickstart), [versioning](https://modelcontextprotocol.io/registry/versioning).
