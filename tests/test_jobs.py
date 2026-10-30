"""Jobs: one per identical request, bounded waits and restart records."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from bindiff_mcp.errors import ExportError, UnknownJobError
from bindiff_mcp.jobs import (
    FAILED,
    RUNNING,
    SUCCEEDED,
    JobContext,
    JobManager,
    JobRequest,
)


def _request(
    work: Callable[[JobContext], dict[str, Any]], key: str = "same request"
) -> JobRequest:
    return JobRequest(tool="bindiff_compare", key=key, arguments={}, work=work)


class Gate:
    """Job work that runs until the test opens the gate."""

    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.started = threading.Event()
        self.open = threading.Event()
        self.calls = 0
        self.result = result if result is not None else {"similarity": 0.9}

    def __call__(self, context: JobContext) -> dict[str, Any]:
        self.calls += 1
        context.stage("diffing")
        self.started.set()
        assert self.open.wait(5)
        return self.result


def test_identical_requests_join_the_running_job(tmp_path: Path) -> None:
    jobs = JobManager(tmp_path)
    gate = Gate()

    first = jobs.submit(_request(gate))
    assert gate.started.wait(5)
    second = jobs.submit(_request(gate))
    gate.open.set()

    assert second is first
    assert jobs.wait(first.job_id, 5)["status"] == SUCCEEDED
    assert gate.calls == 1


def test_a_short_wait_reports_the_stage_and_a_later_one_the_result(
    tmp_path: Path,
) -> None:
    jobs = JobManager(tmp_path)
    gate = Gate({"counts": {"matched_different": 2}})
    job = jobs.submit(_request(gate))
    assert gate.started.wait(5)

    running = jobs.wait(job.job_id, 0.05)
    gate.open.set()
    finished = jobs.wait(job.job_id, 5)

    assert (running["status"], running["stage"]) == (RUNNING, "diffing")
    assert finished["status"] == SUCCEEDED
    assert finished["result"] == {"counts": {"matched_different": 2}}


def test_a_failed_job_reports_its_error_and_a_retry_starts_over(
    tmp_path: Path,
) -> None:
    jobs = JobManager(tmp_path)

    def fail(_context: JobContext) -> dict[str, Any]:
        raise ExportError("IDA could not open sample.bin")

    failed = jobs.submit(_request(fail))
    record = jobs.wait(failed.job_id, 5)
    gate = Gate()
    retry = jobs.submit(_request(gate))
    gate.open.set()

    assert record["status"] == FAILED
    assert record["error"] == "IDA could not open sample.bin"
    assert retry.job_id != failed.job_id
    assert jobs.wait(retry.job_id, 5)["status"] == SUCCEEDED


def test_finished_jobs_outlive_a_restart_and_unfinished_ones_say_so(
    tmp_path: Path,
) -> None:
    before = JobManager(tmp_path)
    done = Gate({"counts": {"matched_different": 3}})
    finished = before.submit(_request(done, key="finished"))
    done.open.set()
    assert before.wait(finished.job_id, 5)["status"] == SUCCEEDED
    stuck = Gate()
    unfinished = before.submit(_request(stuck, key="unfinished"))
    assert stuck.started.wait(5)

    # A restarted server shares only the state directory with the old one.
    after = JobManager(tmp_path)
    kept = after.wait(finished.job_id, 0)
    lost = after.wait(unfinished.job_id, 0)
    stuck.open.set()

    assert kept["status"] == SUCCEEDED
    assert kept["result"] == {"counts": {"matched_different": 3}}
    assert lost["status"] == FAILED
    assert "submit the request again" in lost["error"]


@pytest.mark.parametrize("job_id", ["0123456789abcdef", "../../jobs/x"])
def test_unknown_job_ids_are_rejected(tmp_path: Path, job_id: str) -> None:
    with pytest.raises(UnknownJobError):
        JobManager(tmp_path).wait(job_id, 0)
