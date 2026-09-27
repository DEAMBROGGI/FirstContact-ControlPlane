from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources


class JobDefinitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class JobDefinition:
    job_id: str
    version: int
    implementation: str
    parameters: dict
    result_schema: str
    digest: str


def _load(name: str) -> JobDefinition:
    raw = resources.files("control_plane.job_definitions").joinpath(name).read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return JobDefinition(
        job_id=str(payload["job_id"]),
        version=int(payload["version"]),
        implementation=str(payload["implementation"]),
        parameters=dict(payload.get("parameters") or {}),
        result_schema=str(payload["result_schema"]),
        digest=hashlib.sha256(canonical).hexdigest(),
    )


_DEFINITIONS = tuple(
    _load(name)
    for name in (
        "python-tests.json",
        "publisher-security.json",
        "codex-review-broker.json",
        "ui-build.json",
        "compose-config.json",
        "repository-integrity.json",
    )
)


def job_definition(job_id: str, version: int) -> JobDefinition:
    matches = [
        item
        for item in _DEFINITIONS
        if item.job_id == job_id and item.version == version
    ]
    if len(matches) != 1:
        raise JobDefinitionError(
            f"no unique job definition for {job_id}@{version}"
        )
    return matches[0]


def all_job_definitions() -> tuple[JobDefinition, ...]:
    return _DEFINITIONS
