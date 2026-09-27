# FirstContact Control Plane

Independent CI, admission, publication and review authority for FirstContact repositories.

## Core rule

Candidate commits are created outside the remote repository. Governed repositories do not receive a candidate until the control plane admits its exact Git identity under an immutable validation profile.

The control plane then owns publication, exact-head review state, mergeability calculation and deterministic Issue/PR/Project projection.

## Current P0 slice

Issue #2 implements the first vertical slice:

```text
Publication
  -> Candidate exact identity
  -> versioned DeliveryProfile
  -> append-only validation events
  -> ADMITTED | VALIDATION_FAILED
  -> publication boundary (disabled by default)
  -> exact-head review
  -> mergeability
  -> deterministic desired lifecycle projection
```

The GitHub publisher is intentionally disabled in this slice. No API route can push or merge code.

## Local development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
pytest

docker compose up --build
```

API: http://localhost:8080/api/v1/health
UI: http://localhost:5173

## Governed repositories

Initial profile registry:

- `DEAMBROGGI/FirstContact`
- `DEAMBROGGI/FirstContact-SpecialistAgent`

They are configuration/policy inputs. The core is repository-neutral.


## Git candidate quarantine

Issue #4 removes caller-declared Git identities from the production candidate path.

A candidate upload is a Git bundle that advertises exactly:

```text
refs/controlplane/base
refs/controlplane/head
```

A local producer can create one without pushing anything remotely:

```powershell
git update-ref refs/controlplane/base <base-sha>
git update-ref refs/controlplane/head <head-sha>
git bundle create candidate.bundle refs/controlplane/base refs/controlplane/head
git update-ref -d refs/controlplane/base
git update-ref -d refs/controlplane/head
```

Submit the bundle to:

```text
POST /api/v1/publications/{publicationId}/candidate-bundle
multipart field: bundle
```

The server computes the bundle SHA-256, imports it into its own bare quarantine,
derives base/head/tree itself, proves ancestry, runs Git integrity checks and
only then creates the Candidate. The legacy caller-declared SHA endpoint is not
available.

The publisher remains disabled.
