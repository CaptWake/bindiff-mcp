# bindiff-mcp

MCP server that gives reverse-engineering agents binary diffing: export binaries
to [BinExport](https://github.com/google/binexport) v2 and compare two builds
with [BinDiff](https://github.com/google/bindiff).

IDA is driven through [ida-nexus](https://pypi.org/project/ida-nexus/), so a
binary already open in the IDA GUI is exported from that database (renames and
annotations included); otherwise a headless idalib worker is spawned and
released again when the export finishes. Export and diff parsing reuse
[python-binexport](https://pypi.org/project/python-binexport/) and
[python-bindiff](https://pypi.org/project/python-bindiff/).

## Prerequisites

- IDA Pro 9.x with idalib enabled (`idapyswitch`), `IDADIR` pointing at the install
- The BinExport IDA plugin (`binexport12_ida.so`) in `$IDAUSR/plugins`
- The BinDiff differ (`bindiff`) in `PATH`, in `$BINDIFF_PATH`, default at
  `/opt/zynamics/BinDiff/bin`
- `libmagic` (used by python-binexport through python-magic)

## Install

```bash
uv pip install .
```

## Run

```bash
bindiff-mcp stdio                              # stdio transport (default)
bindiff-mcp http --host 127.0.0.1 --port 8745  # Streamable HTTP at /mcp
```

Register with Claude Code:

```bash
claude mcp add bindiff -- bindiff-mcp stdio
claude mcp add bindiff --transport http http://127.0.0.1:8745/mcp
```

## Tools

### `binexport(binary, output_results_dir=".")`

Exports `binary` to `<output_results_dir>/<binary name>.BinExport`. An export
that is at least as new as the binary is reused instead of re-analyzing it.
Returns JSON:

```json
{
  "binary": "/work/httpd",
  "binexport": "/work/out/httpd.BinExport",
  "reused": false,
  "name": "httpd",
  "architecture": "x86-64",
  "sha256": "...",
  "functions": 2317
}
```

### `bindiff_compare(primary_binary, secondary_binary, output_results_dir=".")`

Exports both binaries in parallel (into `primary/` and `secondary/`
subdirectories, so identical file names cannot collide), runs the differ, and
writes four JSON files into `output_results_dir`:

| File                     | Content                                                   |
| ------------------------ | --------------------------------------------------------- |
| `matched_similar.json`   | matched functions with similarity 1.0 (identical)          |
| `matched_different.json` | matched functions that changed, most divergent first       |
| `primary_only.json`      | functions only in the primary binary                       |
| `secondary_only.json`    | functions only in the secondary binary                     |

Match entries carry both addresses and names, the similarity and confidence
scores and the BinDiff algorithm that produced the match; unmatched entries
carry address, name and function type. The tool returns JSON with the overall
similarity and confidence, the `.BinDiff` database path, per-list counts and the
path of every file written.

## Environment

| Variable                     | Default | Meaning                                              |
| ---------------------------- | ------- | ---------------------------------------------------- |
| `BINDIFF_MCP_OPEN_TIMEOUT`   | `600`   | Seconds to wait for IDA to open a database           |
| `BINDIFF_MCP_EXPORT_TIMEOUT` | `1800`  | Seconds for one export, excluding autoanalysis       |
| `BINDIFF_PATH`               | —       | Directory containing the `bindiff` differ            |

