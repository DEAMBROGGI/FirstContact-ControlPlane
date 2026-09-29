# Remediation work package workflow

This document describes the provider-neutral lifecycle for implementing and
closing findings accepted from a completed review. It applies to implementation
issues linked to a canonical Control Plane publication.

## Authority and records

`RemediationWorkPackageRow` holds immutable identity and linkage: repository,
implementation issue number, publication, source review run, and reviewed head.
It does not hold an authoritative mutable status.

`RemediationEventRow` is the authoritative history. Events are append-only,
ordered per work package, idempotency-keyed, and linked by a SHA-256 hash chain.
The API view folds those events into the current work-package state and finding
projections. The projection can be rebuilt from the event ledger.

`RemediationDispatchRow` is coordination state only. Its expiring leases prevent
concurrent workers from starting the same external action. It is not evidence
that an action happened. A GitHub artifact becomes authoritative only after its
receipt event is appended.

The implementation issue number is a projection link and can be absent when the
batch is first recorded. A package without an issue number cannot be claimed.
The Control Plane creates or recovers the marked issue, records
`IMPLEMENTATION_ISSUE_LINKED`, then projects its parent relationship, labels,
and Project V2 lifecycle. This lets ledger decisions exist before GitHub
materialization.

Every candidate, validation, review, and finding verification remains bound to
the exact publication and commit SHA recorded in its event. Candidate code runs
without Control Plane writer or GitHub credentials. Publication remains the
Control Plane's responsibility.

## State machine

```text
READY --implementer claim--> IN_PROGRESS -> IMPLEMENTED -> VERIFYING
                               ^                              |      |
                               |                              |      +--> DONE
                 REWORK_REQUIRED <-- any accepted PERSISTS ---+
READY --all findings REJECTED / decision-only finalization--> VERIFYING
```

- `READY`: the package is linked to the current published head and a completed
  source review; its provider finding set is checked against that immutable run,
  and Principal Reviewer decisions are recorded for every finding.
- `IN_PROGRESS`: an implementer claimed the package.
- `IMPLEMENTED`: an implementation attempt from the linked publication was
  submitted with its exact candidate/head, summary, and evidence digest.
- `VERIFYING`: either a completed review of the exact successor head was bound,
  or an all-rejected package entered decision-only finalization on its source
  head.
- `REWORK_REQUIRED`: all accepted findings were verified for the current
  successor, and at least one returned `PERSISTS`. The Control Plane appends this
  transition automatically; the batch can be claimed again for another
  implementation attempt.
- `DONE`: every accepted finding was verified absent, every rejected finding
  has its recorded Principal Reviewer disposition, required GitHub receipts and
  summary exist, the implementation issue is closed, and completion was
  appended.

An accepted finding whose successor verification says `PERSISTS` remains open
for closure and blocks materialization and completion. Once every accepted
finding has a result for that successor, any `PERSISTS` result moves the whole
package to `REWORK_REQUIRED`. This applies to mixed results too: previous
`ABSENT` findings are re-opened for the next attempt, and no reaction, reply,
thread resolution, summary, or issue closure is materialized from that mixed
attempt. The old implementation, review, and verification remain in the
append-only event ledger and in each finding's `verification_history`; the next
attempt records new events and new current verification without editing history.

## Commands and events

All routes below require the internal Control Plane token. Each modifying command
requires a caller-provided `idempotency_key`.

| Command | Route | Event / result |
| --- | --- | --- |
| Create package | `POST /api/v1/internal/remediation/work-packages` | `WORK_PACKAGE_CREATED` |
| Read package | `GET /api/v1/internal/remediation/work-packages/{id}` | Folded view |
| Read history | `GET /api/v1/internal/remediation/work-packages/{id}/events` | Ordered event ledger |
| Claim from READY or REWORK_REQUIRED | `POST .../{id}/claim` | `WORK_PACKAGE_CLAIMED` |
| Submit implementation | `POST .../{id}/implementation` | `IMPLEMENTATION_SUBMITTED` |
| Bind successor review | `POST .../{id}/successor-review` | `SUCCESSOR_REVIEW_STARTED` |
| Start rejected-only finalization | `POST .../{id}/rejected-finalization` | `REJECTED_FINDINGS_FINALIZATION_STARTED` |
| Verify a finding | `POST .../{id}/findings/{finding_id}/verification` | `FINDING_VERIFIED` |
| Materialize and complete | `POST .../{id}/materialize` | Artifact, summary, issue-close, and completion events |

The remaining event types are `GITHUB_ARTIFACT_MATERIALIZED`,
`WORK_PACKAGE_SUMMARY_MATERIALIZED`, `IMPLEMENTATION_ISSUE_CLOSED`, and
`WORK_PACKAGE_COMPLETED`. A fully verified successor with at least one
`PERSISTS` result appends `WORK_PACKAGE_REWORK_REQUIRED` automatically.
Automated issue creation adds
`IMPLEMENTATION_ISSUE_LINKED` after marker readback.

Replaying a command with the same key and same canonical payload returns the
existing result. Reusing a key with a different command or payload is rejected.
Package identity is deterministic for publication, source review run, and
implementation issue; an automatic batch uses a stable pending identity until
its issue link is recorded. Database uniqueness also prevents the same issue from
being linked to multiple packages or the same source review from creating
multiple packages.

## Exact lifecycle

1. Create a package from the completed source review, its exact published head,
   provider-neutral finding identities, source references, and Principal
   Reviewer decisions. Provider finding ids, review ids, and identities must
   exactly match the immutable source Review Run: omission, duplicates, invented
   ids, and provider mismatches fail closed. Explicit `CONTROL_PLANE` findings
   may be added without replacing provider findings. Creation also fails if the
   review is not complete/current or does not match the publication head. When
   an issue number is omitted, the
   Control Plane creates or reuses a Fix Issue using the work-package marker,
   links it as a sub-issue of the parent, and applies `type:fix`, `priority:*`,
   and `status:ready` labels plus `Lifecycle = Ready`.
2. Claim the package from `READY`, or reclaim it from `REWORK_REQUIRED`. A retry
   by the same implementer is idempotent; another claim cannot silently replace
   it.
3. For accepted findings, submit a candidate through the existing quarantine and
   admission path. The submission must identify the publication's current
   candidate and its exact head. The normal validations and publisher then
   publish that candidate to the same canonical pull request.
4. Bind a terminal automated review attempt to the exact published successor
   head. `PASS` and `CHANGES_REQUIRED` bind directly. `UNAVAILABLE` may bind
   only with an explicit Principal Reviewer fallback actor and bounded reason
   recorded in the same `SUCCESSOR_REVIEW_STARTED` event; the provider result
   remains `UNAVAILABLE` and is never rewritten as `PASS`. Every later
   `FINDING_VERIFIED` event for that fallback must be attributed to exactly the
   recorded fallback reviewer; another caller identity cannot inherit that
   authority. The head and candidate must equal the work package's latest
   submitted implementation and remain the publication's current candidate and
   published head; another candidate's review cannot be borrowed. A Principal
   Reviewer records each accepted finding as `ABSENT` or `PERSISTS`, with the
   review run, head, reviewer, and evidence retained in the ledger.
5. If every finding was rejected, use decision-only finalization from `READY`.
   It is valid only while the source review and source head remain current; it
   does not fabricate an implementation or successor review.
6. Materialization rechecks the canonical PR number, open state, head/base
   branches, exact current head, review run, and the same terminal-review
   predicate used by the domain before each external action. `UNAVAILABLE`
   remains materializable only when the persisted successor fallback is present;
   an unbound unavailable attempt fails closed. It records receipts only after
   readback or provider confirmation.
7. Once all finding closure evidence and thread receipts are present, the
   Control Plane posts one work-package summary and re-locks the Publication.
   It appends authoritative `WORK_PACKAGE_COMPLETED` only while the exact review
   run and remote/review head remain current. Only after that commit may the
   orchestrator close the implementation Issue and project `Done`. A crash after
   authoritative completion is recovered by retrying only those terminal GitHub
   projections.

Claim, implementation submission, successor verification, and completion
reconcile the managed status label and Project #4's `Lifecycle` field. The projection vocabulary is `Ready`,
`In Progress`, `Review`, and `Done`: `IMPLEMENTED`, `VERIFYING`, and
`REWORK_REQUIRED` map to `status:review` plus `Lifecycle = Review`; no
`Verifying` Project option or `status:verifying` label is used. Cross-links
include the parent issue, canonical PR, source review run, and remediation batch
marker. The Project V2 number is configured with
`CONTROL_PLANE_REMEDIATION_PROJECT_NUMBER`, and its field name is explicitly
configured by `CONTROL_PLANE_REMEDIATION_PROJECT_LIFECYCLE_FIELD=Lifecycle`.
Project #4 is user-owned, so its GraphQL mutations use the separate runtime
secret `CONTROL_PLANE_REMEDIATION_PROJECT_TOKEN`. For the current private
repository + user-owned Project combination, GitHub requires a dedicated classic
PAT with `project` plus `repo` scope so the Project mutation can resolve private
Issue content. It is never reused for normal Issues or pull-request operations,
which continue to use the GitHub App installation token. Review-thread resolution
uses the additional user secret `CONTROL_PLANE_REMEDIATION_THREAD_TOKEN`, because
GitHub returns `Resource not accessible by integration` for `resolveReviewThread`
with the installation token. The Project, thread-resolution and Codex trigger
credentials are pairwise distinct. Project owner lookup uses GraphQL
`repositoryOwner(login:)` with User/Organization fragments so an invalid
organization lookup cannot poison a valid user-owned Project response. An empty Project credential
makes projection fail closed after retaining the ledger event for retry. The
Project adapter reads the item before adding it and reads back mutation results,
so retries recover without duplicate Project items.

## Accepted and rejected findings

An `ACCEPTED` finding requires an exact successor review verification of
`ABSENT` before closure. A `PERSISTS` result prevents completion and returns the
batch to rework once all accepted findings have been checked for that attempt.
Its requested reaction may be `+1` or `none`; a provider thread, when present, gets a reply
that points to the successor evidence and is resolved after the receipt is
recorded.

A `REJECTED` finding requires a Principal Reviewer reason. It does not require
code changes or successor review when every finding in the package is rejected.
Its requested reaction may be `-1` or `none`; a provider thread, when present,
gets a reply stating the recorded disposition and is resolved. A finding with
no provider thread cannot request a reaction or thread action. Internal findings
are represented in the same package and ledger but do not create provider
thread artifacts.

## Retry and recovery

Database command retries are protected by event idempotency keys and immutable
event identity. External calls never hold a database row lock while waiting on
GitHub. A short-lived dispatch lease coordinates each reaction, reply,
resolution, summary, and issue-close action.

If a response is lost after GitHub accepted an operation, retry recovers its
identity before creating another artifact: reactions use the provider's
same-actor/same-content idempotent operation; replies and summaries carry
package-specific hidden markers and are read back from paginated comments;
thread resolution looks up the exact provider comment and treats an already
resolved thread as complete; issue closure reads back the issue state. Lease
expiry/release permits recovery, while the event ledger remains the source of
truth. Ambiguous duplicates, unexpected actors, changed PR identity/head, or
failed readback stop the workflow closed.

## Provider adapter boundary

The domain package accepts a provider name, provider review id, provider thread
id, and stable normalized finding identity. Provider-specific parsing and
review-correlation rules belong in an adapter that produces this input and
proves the source review belongs to the exact publication head. The adapter
must not change the work-package state machine or ledger format.

An adapter integration must:

- keep provider credentials separate from publication credentials;
- bind review decisions and comments to an exact completed review and head;
- preserve stable provider ids without narrowing them to 32-bit integers;
- map accepted/rejected dispositions explicitly and retain Principal Reviewer
  actor, reason, and evidence;
- fail closed for unmanaged, concurrent, stale, or ambiguously correlated
  provider activity;
- use bounded provider operations rather than generic REST, GraphQL, shell, or
  filesystem passthrough;
- test duplicate delivery, lost responses, retries, exact-head changes, and
  provider identity mismatches.

The Codex Review Broker remains one provider adapter. Its trigger and correlation
rules do not define the generic remediation package contract.

## Onboarding checklist for another API or repository

- Register the repository identity, GitHub App installation, canonical parent
  issue workflow, target branch, and one-publication/one-canonical-PR policy.
- Select versioned validation profiles and JobDefinitions. Candidate execution
  receives no Control Plane writer or GitHub credentials.
- Provide a provider adapter that submits one completed exact-head Review Run
  and stable finding identities. Keep provider trigger/correlation rules inside
  that adapter; reject stale, unmanaged, concurrent, or ambiguous reviews.
- Have the Principal Reviewer submit only finding decisions, priority,
  rejection reason when needed, and desired reaction. The Control Plane creates
  or reuses the batch and projects its Fix Issue, links, labels, and Project V2
  state.
- Use the existing quarantine, validation, admission, and publisher path to
  publish a successor to the same canonical PR. Bind the successor review and
  each finding verification to the exact published HEAD.
- Configure `CONTROL_PLANE_REMEDIATION_PROJECT_NUMBER` and
  `CONTROL_PLANE_REMEDIATION_PROJECT_LIFECYCLE_FIELD=Lifecycle` for Project #4.
  Grant the GitHub App only required repository `issues:write` /
  `pull_requests:write` permissions. Configure the dedicated
  `CONTROL_PLANE_REMEDIATION_PROJECT_TOKEN` runtime secret. For a user-owned
  Project containing private-repository Issues, the current GitHub classic PAT
  contract requires `project` + `repo`; do not reuse the Codex trigger credential.
  Configure `CONTROL_PLANE_REMEDIATION_THREAD_TOKEN` separately for review-thread
  resolution; for the current private repository a dedicated classic PAT with
  `repo` is sufficient. Do not reuse the Project or Codex trigger credentials.
- Route issue, label, Project, reaction, reply, thread-resolution, summary, and
  closure effects through Control Plane commands. Do not add direct-write
  helpers in the consumer API or candidate.
- Run provider adapter tests for duplicate delivery, lost responses, retries,
  actor/id mismatches, exact-head changes, and ambiguous concurrent activity;
  run the shared Control Plane and publisher regression gates before enabling
  the integration.

### Review/remediation safety invariants proven by dogfood

- A candidate cannot be submitted while an automated review is `RUNNING` or while
  any remediation package for that Publication is `VERIFYING`. Publication and
  remediation verification acquire locks in Publication -> work-package order,
  preventing a successor from stranding exact-head verification on an older HEAD.
- Immediately before emitting a governed provider trigger, the broker re-reads
  the canonical PR and verifies number, base/head refs, and exact head SHA again.
  A direct remote PR move therefore fails before the trigger side effect.
- Human `APPROVED` fails closed while any remediation package for the Publication
  is unfinished, even when the exact-head automated review itself reports PASS.
- Final remediation completion re-locks the Publication and revalidates the
  current review run and exact remote/review head before appending authoritative
  `DONE`. Terminal GitHub `Done` labels/Project state and Issue closure are
  retryable projections performed only after that authoritative commit.
- A rejected-only package preserves the provider `CHANGES_REQUIRED` evidence but
  appends an explicit same-head `REMEDIATION_CLEARED` Publication event in the
  authoritative completion transaction. Terminal GitHub closure/projection then
  converges from `DONE` without fabricating a provider PASS.
- Client-controlled text that can be persisted/materialized is rejected when it
  contains the reserved `@codex` automation mention.
- Required automated review remains fail-closed when the provider is unavailable.
  Emergency implementation may continue and be validated locally, but no PASS is
  synthesized and no governed merge gate is satisfied until independent review
  evidence is available or a separately audited future override policy applies.

Publication preflight recovery is compensating and append-only. The publisher
checks the canonical base SHA at admission preflight, again at the remote write
boundary, and again before recording `REMOTE_PUBLISHED`. If an ADMITTED
candidate is rejected because the configured base no longer matches the remote
base, Plane appends `CANDIDATE_REJECTED` with
`REMOTE_BASE_MOVED_AFTER_ADMISSION` and returns the Publication to
`VALIDATION_FAILED`. A remediation package already bound to that candidate uses
`WORK_PACKAGE_REWORK_REQUIRED -> IN_PROGRESS` before a corrected candidate is
submitted. Prior candidate, validation and implementation events are retained;
no candidate identity or prior event is overwritten.

Project V2 item discovery is bounded but fail-closed: reaching the configured
100-page safety cap while GitHub still reports `hasNextPage=true` is not treated
as authoritative absence. No add mutation is permitted until the scan proves
that pagination is exhausted.

### Dispatch fencing discovered by deep review

Expiring dispatch leases are recovery metadata, not sufficient mutation fences on
their own. Before an irreversible provider/GitHub write, Plane re-locks the
authoritative dispatch row under the current lease id and holds the database
transaction lock across the final bounded write plus receipt persistence. A worker
whose lease expired and was superseded therefore cannot continue into the remote
side effect. Long discovery may occur before this final fence; ownership is
revalidated immediately afterward.

This applies to Codex trigger dispatch and remediation artifact dispatch. Recovery
workers may reclaim expired leases, but stale workers fail before mutation and may
not mark an active replacement dispatch unavailable.

A trigger POST with an uncertain transport result is recovered under the same
fence before any unavailable outcome is appended. Plane re-reads issue comments
for the exact run/head marker and authorized trigger actor. Exactly one match is
recorded as the durable receipt; zero/unreadable/ambiguous evidence leaves the run
RUNNING and retryable instead of treating a lost response as provider failure.

### Post-write publication compensation

If the canonical base moves after the final pre-write read but before the governed
branch mutation, the post-write check detects the drift. Before rejecting the
candidate, Plane compensates the remote branch under an exact force-with-lease:
restore the previous governed head for successors, or delete the just-created
branch for an initial publication. Compensation is accepted only if the remote ref
still equals the rejected candidate SHA, and its readback must converge before
`CANDIDATE_REJECTED` is appended. This prevents a rejected candidate from becoming
an orphan remote head that blocks the next publication.


## Plane-first Principal Review source

Plane-first reviewers use an authoritative two-event review contract rather than
creating GitHub findings first and reconstructing them later:

1. `PLANE_REVIEW_RECORDED` persists the exact review run, reviewer identity,
   reviewed HEAD, compact review body, and stable finding metadata before any
   external write.
2. `PlaneReviewPublisher` materializes one native GitHub pull-request review on
   that exact HEAD. Every inline finding carries a stable recovery marker.
3. GitHub review/comment receipts are read back and only then persisted as
   `PLANE_REVIEW_MATERIALIZED`.
4. `create_work_package()` accepts that materialized source under provider
   `PLANE_REVIEW`, preserving the Plane finding id and normalized identity while
   treating GitHub review/comment ids strictly as correlation evidence.

The publisher is replay-safe: a lost response after GitHub accepted the review
is recovered through the stable review/finding markers rather than issuing a
second review. Current PR/head identity and reviewer-controlled reserved
automation mentions fail closed. Native Codex continues through its own adapter;
neither source may masquerade as the other.
