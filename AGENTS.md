# FirstContact Control Plane — contribution contract

- `master` is stable. Implementation uses one Issue-bound feature branch and PR.
- Never self-approve or self-merge.
- The control plane is the future remote-write authority; do not add alternate GitHub push paths.
- Candidate execution never receives control-plane writer or GitHub credentials.
- Persist authoritative history as append-only events. Do not replace event history with mutable status fields.
- Every candidate is bound to exact base/head/tree SHA plus immutable profile id/version/digest.
- Review decisions are valid only for the exact published head they name.
- Mergeability is computed by the control plane, not asserted by a reviewer/client.
- Repository lifecycle and GitHub Project state are projections of control-plane publication state.
- Do not expose arbitrary shell, arbitrary REST/GraphQL passthrough or generic filesystem writes through the API/MCP.
- New validation capability enters through a versioned JobDefinition/Profile contract and tests.
- Fail closed on missing, stale, ambiguous or corrupt evidence.
- PostgreSQL is the production persistence target; tests may use isolated SQLite for domain/API fixtures.
- Qdrant is not part of authoritative state and must never become required for admission or publication.
- Repository publication credentials are GitHub App installation tokens only; do not add PAT-based Git push paths.
- Never persist or log GitHub App PEM contents or installation tokens; token material may exist only in bounded publisher memory/child environment.
- `@codex` mentions on governed GitHub surfaces are reserved to the internal Codex Review Broker; never accept them from API clients or candidate-controlled metadata.
- Native Codex Code Review is an automated pre-review gate only; it never substitutes for the required independent human approval.
- Codex review invocation credentials are separate from publisher credentials: use a dedicated user-attributed fine-grained token at runtime with `Pull requests: Read and write` and no `Contents` access; never use it for publication.
- A native Codex result is acceptable only when correlated to the broker-owned trigger and exact head; pre-existing or concurrent unmanaged `@codex` invocations make the review ambiguous and must fail closed.
## Implementer / Codex delivery contract

- An implementer, including Codex, may create commits locally, but must never push a candidate commit directly to a governed repository, canonical publication branch, or canonical pull request. The Control Plane is the only remote-write authority for governed publication.
- After implementation, the implementer must deliver the exact candidate as a Git bundle to the Control Plane candidate-upload endpoint: `POST /api/v1/publications/{publication_id}/candidate-bundle` using multipart field `bundle`.
- The bundle must advertise exactly `refs/controlplane/base` and `refs/controlplane/head`. Create those temporary refs locally and build the bundle; do not push them to GitHub.
- The Control Plane, not the implementer, derives and verifies base/head/tree, bundle digest, ancestry, Git integrity, candidate identity, validation admission, and publication readiness. Caller-supplied SHAs are not evidence of candidate identity.
- A local commit is not an implementation submission and does not exist in the authoritative Control Plane ledger until the candidate bundle is accepted through the endpoint and the resulting candidate is admitted/published by the governed lifecycle.
- The implementer must report the Control Plane publication/candidate response and stop at the governed handoff. Do not use `git push`, GitHub Contents API writes, direct PR branch mutation, or any alternate GitHub write path to deliver implementation code.
- The canonical sequence is: claim work -> implement/test locally -> create candidate bundle -> submit bundle to Plane -> wait for validation/admission/publication -> only then proceed to the governed successor review flow.
- If the Control Plane endpoint is unavailable or rejects the bundle, leave the local commit intact for retry and report the failure; do not bypass Plane by pushing the commit directly.
