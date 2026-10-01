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
- `DEAMBROGGI/FirstContact-ControlPlane` (self-governance/dogfooding)

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


## Implementer handoff to Plane

Governed implementers, including Codex, do not push implementation commits directly to the canonical PR branch. A local commit becomes a governed candidate only after the implementer creates a Git bundle advertising exactly `refs/controlplane/base` and `refs/controlplane/head` and uploads it to `POST /api/v1/publications/{publicationId}/candidate-bundle` as multipart field `bundle`.

Plane imports the bundle into its own quarantine and derives the base/head/tree and candidate identity itself. It then runs the configured validation/admission lifecycle before the publisher writes the candidate to the canonical PR. Therefore a local commit or a GitHub branch push performed by the implementer is not a valid Plane implementation submission.


## GitHub App publisher

Issue #6 adds the exclusive repository publication boundary.

The endpoint is bodyless:

```text
POST /api/v1/internal/publications/{publicationId}/publish
```

Repository, exact candidate head, quarantine repository, base branch and target
branch are derived by the server. A caller cannot provide any of them.

Repository publication uses a GitHub App installation token. The token is
requested just-in-time for one repository with only `contents:write` and
`pull_requests:write`, expires at GitHub's installation-token boundary, and is
never persisted. Git uses an askpass helper so the installation token is not
present in process arguments.

Local configuration contains only the GitHub App id and an absolute path to a
PEM stored outside the repository:

```env
CONTROL_PLANE_PUBLISHER_MODE=github-app
CONTROL_PLANE_GITHUB_APP_ID=<app-id>
CONTROL_PLANE_GITHUB_APP_PRIVATE_KEY_PATH=C:\absolute\secure\path\app.pem
```

The default remains `CONTROL_PLANE_PUBLISHER_MODE=disabled`.


## Native Codex Code Review broker

Issue #10 governs native Codex Code Review as a pre-review gate.

The Control Plane owns the governed invocation. API clients cannot provide
review text or reserved `@codex` mentions. For an exact published head the
broker acquires a persistent dispatch lease before it emits `@codex review`.

Live characterization established two separate GitHub identities:

- repository publication uses a repository-scoped GitHub App installation token;
- native Codex invocation must be user-attributed. GitHub App bot-authored
  `@codex review` comments are ignored by Codex, while a user-attributed
  trigger is accepted.

The Codex trigger uses a dedicated fine-grained user token supplied only at
runtime. It is used only to create the governed trigger comment. Before posting,
the broker calls `GET /user` and checks that the token belongs to the configured
login. The separate publisher GitHub App installation token continues to
perform repository reads and publication.

Configuration:

```env
CONTROL_PLANE_CODEX_REVIEW_MODE=disabled
CONTROL_PLANE_CODEX_REVIEW_ACTORS=chatgpt-codex-connector[bot]
CONTROL_PLANE_CODEX_REVIEW_USER_TOKEN=
CONTROL_PLANE_CODEX_REVIEW_TRIGGER_LOGIN=DEAMBROGGI
```

Create the fine-grained token later for user `DEAMBROGGI`, restrict it to the
selected governed repositories, and grant **Pull requests: Read and write** with
**Contents: no access**. GitHub documents the required [pull request comment
permission](https://docs.github.com/en/rest/issues/comments#create-an-issue-comment)
and the `github_pat_` [fine-grained token prefix](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github).
Provide it to the API process through `CONTROL_PLANE_CODEX_REVIEW_USER_TOKEN`.
Do not put a real token in the repository or pass it in a command argument.
`SecretStr` masks it in settings representations; the provider keeps it in
memory, verifies its owner before dispatch, and does not add it to event data.

Modes are `disabled`, `advisory`, and `required`. In `required` mode a
human APPROVED decision cannot be recorded until the exact-head native Codex
review has completed with PASS. A human may still record CHANGES_REQUIRED.
While Codex is RUNNING, human review is locked. Advisory findings are recorded
without moving the publication out of IN_REVIEW.

The broker accepts only evidence bound to the governed trigger and exact head.
It rejects unmanaged `@codex` invocations, stale/foreign actors and ambiguous
review evidence. GitHub pagination is exhausted before deciding PASS.

Native completion is recognized in either form observed/documented by Codex:

- a Codex pull-request review, with inline comments normalized as findings;
- a Codex thumbs-up reaction on the governed trigger when there are no findings.

The observed native actor for this repository is
`chatgpt-codex-connector[bot]`. It remains an explicit allowlist value rather
than a hard-coded trust assumption.

Delivery profiles are immutable historical contracts. A candidate continues to
validate against its pinned profile id/version/digest even after a newer profile
becomes active. Admission-critical jobs in schema-v2 profiles are additionally
bound to versioned JobDefinitions and their digests.
