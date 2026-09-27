from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources


class ProfileError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DeliveryProfile:
    repository: str
    profile_id: str
    version: int
    required_jobs: tuple[str, ...]
    digest: str


def _load(name: str) -> DeliveryProfile:
    raw = resources.files("control_plane.policies").joinpath(name).read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return DeliveryProfile(
        repository=payload["repository"],
        profile_id=payload["profile_id"],
        version=int(payload["version"]),
        required_jobs=tuple(payload["required_jobs"]),
        digest=hashlib.sha256(canonical).hexdigest(),
    )


_PROFILES = tuple(_load(name) for name in ("firstcontact.json", "specialist.json"))


def profile_for_repository(repository: str) -> DeliveryProfile:
    matches = [p for p in _PROFILES if p.repository == repository]
    if len(matches) != 1:
        raise ProfileError(f"no unique active profile for {repository}")
    return matches[0]


def all_profiles() -> tuple[DeliveryProfile, ...]:
    return _PROFILES
