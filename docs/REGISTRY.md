# MCP Registry listing

I keep the Registry metadata in [`server.json`](../server.json). It describes a local stdio server for native programs on Apple Silicon macOS. The listing describes the launcher, not proof of analysis coverage. For the partial application-directory workflow in 0.1.9, configure the external `--workspace` explicitly as described in [SETUP.md](SETUP.md#application-directory-workflow); the default Registry path remains a standalone native program.

## Before connecting

Install uv and Apple Command Line Tools, then run the published version's setup command. Setup manages Java and Ghidra and builds the native helpers. The server does not run setup automatically when a client connects.

`eaos` remains the short command. Starting with the released 0.1.3 package, `every-app-is-open-source` is an alias of the same entry point. Registry clients commonly launch a package by its identifier; the additional name makes that work.

The checked-in manifest targets version 0.2.0. Preparing metadata does not publish it. PyPI release and Registry submission are separate steps; the manifest alone does not establish publication. Check the [PyPI version](https://pypi.org/project/every-app-is-open-source/0.2.0/) and [version-specific Registry entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.thomasisalwayslate%2Fevery-app-is-open-source/versions/0.2.0) for availability. The command below selects the manifest version; during release preparation, use the reviewed local wheel until it is published:

```sh
uvx --python 3.13 every-app-is-open-source@0.2.0 mcp /absolute/path/to/program
```

The program path is required. `EAOS_RUNTIME_DIR` is optional; if supplied, use the same directory for setup and the client. Analysis projects and evidence are saved beside the selected program.

## Published listing

Version **0.1.3** was published to the official MCP Registry on **2026-10-19**. The [version-specific entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.thomasisalwayslate%2Fevery-app-is-open-source/versions/0.1.3) and the latest-version endpoint were verified after publication, with active status and metadata matching the 0.1.3 `server.json` at publication. For newer versions, check the [latest-version endpoint](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.thomasisalwayslate%2Fevery-app-is-open-source/versions/latest) and the corresponding version-specific entry. A package release alone does not update that listing.

For that historical 0.1.3 verification, the published PyPI files matched the checked release artifacts. Its live package-name launch command passed the then-seven-tool native smoke check and saved-evidence checks outside the checkout, using previously verified Java/Ghidra runtimes. The published 0.1.2 package only provides `eaos` and cannot run the package-name command above.

## Future publication gates

The Registry's unauthenticated `/v0.1/validate` endpoint can check schema and semantic validity without installing a tool or publishing a listing. That check does not establish package availability, namespace authorization, or successful installation by every Registry consumer.

For each update, approve and release the package, verify its live launch command, then validate the reviewed metadata with the official `mcp-publisher` CLI. GitHub login is a separate interactive step when needed; do not copy or paste account tokens into project files. Submit only within the owner-approved release scope. Preparing a PR does not submit the server.

For future capabilities, release a tested package and publish a new Registry version with updated metadata. Published Registry versions are immutable; keep the server name stable.

References: [package verification](https://modelcontextprotocol.io/registry/package-types), [publishing](https://modelcontextprotocol.io/registry/quickstart), [versioning](https://modelcontextprotocol.io/registry/versioning).
