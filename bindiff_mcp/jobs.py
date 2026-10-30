"""Background jobs: export and diff work that outlives a single MCP request.

IDA needs tens of minutes to analyze a large binary, far longer than an MCP
client waits for one response, and a client that gives up never receives the
result. A tool call therefore submits a job and waits at most ``wait_seconds``
for it; the client fetches the rest with ``bindiff_job``. An identical request
joins the job already running instead of exporting the same binaries again, and
every state change is recorded on disk so a finished result outlives a restart.
"""

from __future__ import annotations

import json
import math
import os
import queue
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bindiff_mcp.errors import BindiffMcpError, UnknownJobError
from bindiff_mcp.files import write_text_atomic
from bindiff_mcp.limits import JOB_TIMEOUT_SECONDS, MAX_JOBS, Deadline

#: Shorter than the 30 s request timeout common among MCP clients.
DEFAULT_WAIT_SECONDS = 20.0

#: Longer waits would bring back the silent, long-lived requests jobs replace.
MAX_WAIT_SECONDS = 60.0

QUEUED = "queued"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"

_JOB_ID = re.compile(r"[0-9a-f]{16}")


def _default_state_dir() -> Path:
    configured = os.environ.get("BINDIFF_MCP_STATE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "bindiff-mcp"


def _timestamp(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, UTC).isoformat(timespec="seconds")


@dataclass(eq=False)
class Job:
    """One submitted request. Fields change only through ``update``."""

    job_id: str
    tool: str
    key: str
    arguments: dict[str, str]
    submitted_at: float
    status: str = QUEUED
    stage: str = QUEUED
    exports: dict[str, str] = field(default_factory=dict)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    done: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **changes: Any) -> None:
        with self._lock:
            for name, value in changes.items():
                setattr(self, name, value)

    def set_export(self, part: str, state: str) -> None:
        with self._lock:
            self.exports = {**self.exports, part: state}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            end = self.finished_at if self.finished_at is not None else time.time()
            return {
                "job_id": self.job_id,
                "tool": self.tool,
                "status": self.status,
                "stage": self.stage,
                "exports": dict(self.exports),
                "arguments": dict(self.arguments),
                "submitted_at": _timestamp(self.submitted_at),
                "started_at": _timestamp(self.started_at),
                "finished_at": _timestamp(self.finished_at),
                "elapsed_seconds": round(end - self.submitted_at, 1),
                "result": self.result,
                "error": self.error,
            }


class JobContext:
    """What a running job gets: its deadline and a way to report progress."""

    def __init__(
        self, job: Job, deadline: Deadline, publish: Callable[[Job], None]
    ) -> None:
        self.deadline = deadline
        self._job = job
        self._publish = publish

    def stage(self, stage: str) -> None:
        self._job.update(stage=stage)
        self._publish(self._job)

    def export_progress(self, part: str) -> Callable[[str], None]:
        """Progress callback for the export of ``part`` (e.g. ``"primary"``)."""

        def report(state: str) -> None:
            self._job.set_export(part, state)
            self._publish(self._job)

        return report


@dataclass(frozen=True, slots=True)
class JobRequest:
    """A validated tool call: what to run and what makes it identical to another."""

    tool: str
    key: str
    arguments: dict[str, str]
    work: Callable[[JobContext], dict[str, Any]]


class JobManager:
    """Runs jobs on at most ``max_jobs`` worker threads and keeps their records."""

    def __init__(
        self,
        state_dir: Path,
        *,
        max_jobs: int = MAX_JOBS,
        job_timeout: float = JOB_TIMEOUT_SECONDS,
    ) -> None:
        self._records = state_dir / "jobs"
        self._max_jobs = max_jobs
        self._job_timeout = job_timeout
        self._lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._active: dict[str, Job] = {}
        self._queue: queue.SimpleQueue[tuple[Job, JobRequest]] = queue.SimpleQueue()
        self._workers = 0
        self._save_failed = False

    def submit(self, request: JobRequest) -> Job:
        """Queue ``request``, or return the unfinished job of an identical one."""
        with self._lock:
            active = self._active.get(request.key)
            if active is not None:
                return active
            job = Job(
                job_id=uuid.uuid4().hex[:16],
                tool=request.tool,
                key=request.key,
                arguments=request.arguments,
                submitted_at=time.time(),
            )
            self._jobs[job.job_id] = job
            self._active[request.key] = job
            if self._workers < self._max_jobs:
                self._workers += 1
                # Daemon threads: a job in progress must not hold the process
                # open once the server is told to stop.
                threading.Thread(
                    target=self._work,
                    name=f"bindiff-mcp-job-{self._workers}",
                    daemon=True,
                ).start()
        self._save(job)
        self._queue.put((job, request))
        return job

    def wait(self, job_id: str, seconds: float) -> dict[str, Any]:
        """Wait up to ``seconds`` for ``job_id`` to finish, then describe it."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return self._load(job_id)
        job.done.wait(_bounded_wait(seconds))
        return job.snapshot()

    def _work(self) -> None:
        while True:
            job, request = self._queue.get()
            self._run(job, request)

    def _run(self, job: Job, request: JobRequest) -> None:
        job.update(status=RUNNING, stage="starting", started_at=time.time())
        self._save(job)
        context = JobContext(job, Deadline.after(self._job_timeout), self._save)
        outcome: dict[str, Any]
        try:
            outcome = {
                "status": SUCCEEDED,
                "stage": "done",
                "result": request.work(context),
            }
        except BindiffMcpError as error:
            outcome = {"status": FAILED, "error": str(error)}
        except Exception as error:  # noqa: BLE001 -- a crashed job must still report
            outcome = {"status": FAILED, "error": f"{type(error).__name__}: {error}"}
        with self._lock:
            job.update(finished_at=time.time(), **outcome)
            if self._active.get(job.key) is job:
                del self._active[job.key]
        self._save(job)
        job.done.set()

    def _save(self, job: Job) -> None:
        with self._save_lock:
            record = job.snapshot()
            try:
                self._records.mkdir(parents=True, exist_ok=True)
                write_text_atomic(
                    self._records / f"{job.job_id}.json", json.dumps(record, indent=2)
                )
            except OSError as error:
                # Jobs still work in memory; only the restart record is lost.
                if not self._save_failed:
                    self._save_failed = True
                    print(
                        f"[bindiff-mcp] warning: cannot record jobs in "
                        f"{self._records}: {error}",
                        file=sys.stderr,
                    )

    def _load(self, job_id: str) -> dict[str, Any]:
        unknown = UnknownJobError(
            f"unknown job_id {job_id!r}; job ids come from binexport and bindiff_compare"
        )
        if not _JOB_ID.fullmatch(job_id):
            raise unknown
        try:
            record = json.loads(
                (self._records / f"{job_id}.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            raise unknown from error
        if record.get("status") in (QUEUED, RUNNING):
            # Recorded by a previous server process, which can no longer finish it.
            record["status"] = FAILED
            record["error"] = (
                "the server stopped before this job finished; submit the request again"
            )
        return record


def _bounded_wait(seconds: float) -> float:
    if math.isnan(seconds):
        return 0.0
    return min(max(seconds, 0.0), MAX_WAIT_SECONDS)


JOBS = JobManager(_default_state_dir())
