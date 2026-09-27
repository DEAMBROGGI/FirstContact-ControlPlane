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
