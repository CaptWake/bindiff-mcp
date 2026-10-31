# bindiff-mcp

MCP server that gives reverse-engineering agents binary diffing: export binaries
to [BinExport](https://github.com/google/binexport) v2 and compare two builds
with [BinDiff](https://github.com/google/bindiff).

IDA is driven through [ida-nexus](https://pypi.org/project/ida-nexus/), so a
binary already open in the IDA GUI is exported from that database (renames and
annotations included); otherwise a headless idalib worker is spawned and
released again when the export finishes. Exports and diffs are read at function
level only, using the schema of
[python-binexport](https://pypi.org/project/python-binexport/) and the
algorithm names of [python-bindiff](https://pypi.org/project/python-bindiff/);
basic block and instruction matches are never loaded.

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

IDA can spend tens of minutes analyzing a large binary, longer than MCP clients
wait for a response. `binexport` and `bindiff_compare` therefore run as jobs: a
call waits up to `wait_seconds` (default 20, at most 60) and returns either the
finished job or how far it has come:

```json
{
  "job_id": "5f0c2a9e41d7b3c8",
  "tool": "bindiff_compare",
  "status": "running",
  "elapsed_seconds": 20.0,
  "stage": "exporting",
  "exports": { "primary": "autoanalysis", "secondary": "exporting" },
  "next": "call bindiff_job with job_id \"5f0c2a9e41d7b3c8\" until the status is succeeded"
}
```

Poll `bindiff_job` until `status` is `succeeded`; the tool's output is then in
`result`. A failed job comes back as a tool error that names its stage.
Repeating a request for the same binaries (by SHA-256) and output directory
joins the job still running instead of exporting them again; one binary is
never exported by two jobs at once. At most `BINDIFF_MCP_MAX_JOBS` jobs run at
a time, and `BINDIFF_MCP_JOB_TIMEOUT` bounds every stage of a job. IDA cannot
interrupt an analysis, so an idalib worker still busy when its stage runs out
of time is killed and its unsaved database files are dropped; the next export
starts again from the binary or from the last saved `.i64`.

### `binexport(binary, output_results_dir=".", wait_seconds=20)`

Exports `binary` to `<output_results_dir>/<binary name>.BinExport`. An export
that is at least as new as the binary is reused instead of re-analyzing it.
The job's `result`:

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

### `bindiff_compare(primary_binary, secondary_binary, output_results_dir=".", wait_seconds=20)`

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
carry address, name and function type. The job's `result` holds the overall
similarity and confidence, the `.BinDiff` database path, per-list counts and the
path of every file written.

### `bindiff_job(job_id, wait_seconds=20)`

Waits up to `wait_seconds` for a job and returns it as above. Job records are
kept under `BINDIFF_MCP_STATE_DIR`, so a finished job can still be fetched after
a server restart; a job that was running when the server stopped is reported as
failed and has to be submitted again.

## Environment

| Variable                       | Default                      | Meaning                                                 |
| ------------------------------ | ---------------------------- | ------------------------------------------------------- |
| `BINDIFF_MCP_OPEN_TIMEOUT`     | `600`                        | Seconds to wait for IDA to open a database              |
| `BINDIFF_MCP_ANALYSIS_TIMEOUT` | `7200`                       | Seconds for the initial autoanalysis of one binary      |
| `BINDIFF_MCP_EXPORT_TIMEOUT`   | `1800`                       | Seconds for the BinExport step after autoanalysis       |
| `BINDIFF_MCP_JOB_TIMEOUT`      | `14400`                      | Seconds for a whole job once it starts; caps each stage |
| `BINDIFF_MCP_MAX_JOBS`         | `2`                          | Jobs run at once; each uses up to two idalib workers    |
| `BINDIFF_MCP_STATE_DIR`        | `~/.local/state/bindiff-mcp` | Job records; keep it on a persistent volume             |
| `BINDIFF_PATH`                 | —                            | Directory containing the `bindiff` differ               |

