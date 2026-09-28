from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources

from .job_registry import JobDefinition, job_definition


class ProfileError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DeliveryProfile:
    repository: str
    profile_id: str
    version: int
    required_jobs: tuple[str, ...]
    digest: str
    schema_version: int
    job_definitions: tuple[JobDefinition, ...]

    def definition_for(self, job_id: str) -> JobDefinition | None:
        matches = [
            item
            for item in self.job_definitions
            if item.job_id == job_id
        ]
        if len(matches) > 1:
            raise ProfileError(
                f"multiple job definitions for {job_id} in profile"
            )
        return matches[0] if matches else None


def _load(name: str) -> DeliveryProfile:
    raw = resources.files("control_plane.policies").joinpath(name).read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    schema_version = int(payload.get("schema_version", 1))
    required_jobs = tuple(str(item) for item in payload["required_jobs"])

    resolved: tuple[JobDefinition, ...] = ()
    if schema_version >= 2:
        versions = dict(payload.get("job_definition_versions") or {})
        if set(versions) != set(required_jobs):
            raise ProfileError(
                f"profile {payload['profile_id']}@{payload['version']} "
                "must pin one job definition version per required job"
            )
        resolved = tuple(
            job_definition(job_id, int(versions[job_id]))
            for job_id in required_jobs
        )
        digest_payload = {
            "profile": payload,
            "job_definition_digests": [
                {
                    "job_id": item.job_id,
                    "version": item.version,
                    "digest": item.digest,
                }
                for item in resolved
            ],
        }
    else:
        digest_payload = payload

    canonical = json.dumps(
        digest_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return DeliveryProfile(
        repository=str(payload["repository"]),
        profile_id=str(payload["profile_id"]),
        version=int(payload["version"]),
        required_jobs=required_jobs,
        digest=hashlib.sha256(canonical).hexdigest(),
        schema_version=schema_version,
        job_definitions=resolved,
    )


_PROFILE_FILES = (
    "firstcontact.json",
    "specialist.json",
    "controlplane.v1.json",
    "controlplane.v2.json",
    "controlplane.v3.json",
    "controlplane.json",
)
_PROFILES = tuple(_load(name) for name in _PROFILE_FILES)
_ACTIVE_BY_REPOSITORY = {
    "DEAMBROGGI/FirstContact": "firstcontact/default",
    "DEAMBROGGI/FirstContact-SpecialistAgent": "specialist/default",
    "DEAMBROGGI/FirstContact-ControlPlane": "controlplane/default",
}
_ACTIVE_VERSION = {
    "DEAMBROGGI/FirstContact": 1,
    "DEAMBROGGI/FirstContact-SpecialistAgent": 1,
    "DEAMBROGGI/FirstContact-ControlPlane": 4,
}


def profile_for_repository(repository: str) -> DeliveryProfile:
    expected_id = _ACTIVE_BY_REPOSITORY.get(repository)
    expected_version = _ACTIVE_VERSION.get(repository)
    matches = [
        item
        for item in _PROFILES
        if item.repository == repository
        and item.profile_id == expected_id
        and item.version == expected_version
    ]
    if len(matches) != 1:
        raise ProfileError(f"no unique active profile for {repository}")
    return matches[0]


def profile_for_identity(
    repository: str,
    profile_id: str,
    version: int,
    digest: str,
) -> DeliveryProfile:
    matches = [
        item
        for item in _PROFILES
        if item.repository == repository
        and item.profile_id == profile_id
        and item.version == version
        and item.digest == digest
    ]
    if len(matches) != 1:
        raise ProfileError(
            "candidate references unknown or mutated delivery profile"
        )
    return matches[0]


def all_profiles() -> tuple[DeliveryProfile, ...]:
    return _PROFILES
