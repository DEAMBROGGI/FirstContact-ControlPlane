# FirstContact Control Plane - Arquitectura tecnica

> Estado: baseline de arquitectura + target de orquestacion de remediaciones
> Repositorio: DEAMBROGGI/FirstContact-ControlPlane
> Dogfood canonico: Issue #10 / PR #13

## 1. Objetivo

Este documento define quien invoca la API, quien toma decisiones, quien define estados y que elementos externos son solo proyecciones/evidencia.

Principios:

1. El ledger del Control Plane es la fuente de verdad.
2. Los callers envian comandos e intencion; nunca setean estados directamente.
3. GitHub y Codex entregan evidencia externa, no autoridad de dominio.
4. HEAD exacto es la unidad de evidencia.
5. Un Issue logico mantiene una Publication activa, una branch gobernada y un PR canonico.
6. Un Review Run produce un conjunto de findings que se remedia como un solo batch.
7. Principal Reviewer decide; Control Plane orquesta.
8. El Implementador trabaja desde un unico Implementation Fix Issue READY.
9. Toda materializacion en GitHub debe ser idempotente.
10. Codex PASS nunca equivale a Human APPROVE.

## 2. Responsabilidades

| Actor | Invoca | Decide | No decide |
|---|---|---|---|
| Consumer / Source | creacion/reuso, candidate | intencion | estado Publication |
| CI / Validator | resultado job | PASS/FAIL de su job | admision final |
| Principal Reviewer | decisiones sobre findings | ACCEPTED/REJECTED, prioridad, motivo | GitHub side-effects |
| General Implementer | claim + implementation complete | termino implementacion desde su perspectiva | aceptacion/verificacion finding |
| Human Reviewer | APPROVE / REQUEST_CHANGES | decision humana exact-head | resultado Codex |
| Codex / provider | review/comments | provider findings | lifecycle Control Plane |
| Control Plane Domain | comandos internos | todos los estados autoritativos | contenido del provider |
| GitHub Orchestrator | materializacion | ninguna decision de negocio | politica |
| Publisher | publicacion gobernada | ninguna admision | aceptacion candidate |

## 3. Regla de autoridad

~~~text
Actor / evidencia
      |
      v
Comando a Control Plane
      |
      v
Lock del aggregate + re-fold
      |
      v
Validacion de transicion / exact HEAD / idempotencia
      |
      v
Evento inmutable
      |
      v
Fold -> estado autoritativo
      |
      v
Proyeccion externa opcional
~~~

Ningun write externo se transforma por si solo en estado de dominio.

## 4. Identidades

~~~mermaid
flowchart LR
    I["Issue / Work Item<br/>intencion"] --> P["Publication<br/>aggregate lifecycle"]
    P --> PR["PR canonico<br/>historia de implementacion"]
    P --> A["HEAD A<br/>candidate revision"]
    P --> B["HEAD B<br/>candidate revision"]
    B --> RR["Review Run<br/>exact HEAD"]
    RR --> F["Findings"]
    F --> D["Principal Review Decisions"]
    D --> RB["Remediation Batch"]
    RB --> GI["GitHub Implementation Fix Issue<br/>proyeccion"]
    style P stroke-width:3px
    style RR stroke-width:3px
    style RB stroke-width:3px
~~~

Semantica:
- Issue = objetivo logico.
- Publication = lifecycle completo del Issue/PR.
- PR = conversacion e historia.
- HEAD = revision inmutable.
- Review Run = evaluacion de un HEAD.
- Finding = evidencia normalizada.
- Principal Review Decision = decision humana autoritativa sobre un finding.
- Remediation Batch = paquete unico de trabajo.
- Implementation Fix Issue = superficie de trabajo/proyeccion, no fuente de verdad.

## 5. API actual implementada

| Endpoint | Caller | Responsabilidad |
|---|---|---|
| POST /api/v1/publications | source/orchestrator | crear o reutilizar Publication activa |
| POST /api/v1/publications/{id}/candidate-bundle | implementer/source | importar candidate y pasar a VALIDATING |
| POST /api/v1/internal/publications/{id}/validations | validator | registrar evidencia de jobs |
| POST /api/v1/publications/{id}/publish | orchestrator | publicar candidate admitido con CAS |
| POST /api/v1/publications/{id}/codex-review/request | orchestrator | solicitar review exact-head |
| POST /api/v1/publications/{id}/codex-review/reconcile | orchestrator | reconciliar provider evidence |
| POST /api/v1/publications/{id}/reviews | Human Review UI | APPROVE / REQUEST_CHANGES exact-head |
| POST /api/v1/internal/publications/{id}/mergeability | checker | mergeability exact-head |
| POST /api/v1/internal/publications/{id}/merge | Plane | execute governed exact-head merge |
| POST /api/v1/internal/publications/{id}/merge/reconcile | reconciler | recover/audit GitHub merged state |
| GET /api/v1/publications/{id} | UI/orchestrator | view autoritativa |
| GET /api/v1/publications/{id}/events | audit/UI | event history |
| POST /api/v1/internal/remediation/work-packages | Control Plane orchestrator | persistir decisiones ya tomadas y crear/reusar batch; si falta Issue, crear/reutilizar y proyectar Fix Issue |
| GET /api/v1/internal/remediation/work-packages/{id} | UI/orchestrator | proyeccion plegada del ledger |
| GET /api/v1/internal/remediation/work-packages/{id}/events | audit/UI | eventos de remediation |
| POST .../{id}/claim | General Implementer | READY/REWORK_REQUIRED -> IN_PROGRESS + sincronizar Issue/Project |
| POST .../{id}/implementation | General Implementer | registrar candidate, HEAD y evidencia; labels `status:review` y Lifecycle = Review |
| POST .../{id}/successor-review | orchestrator | enlazar review exact-head y proyectar VERIFYING |
| POST .../{id}/rejected-finalization | orchestrator | iniciar cierre sin candidate solo si todo fue REJECTED |
| POST .../{id}/findings/{finding_id}/verification | Principal Reviewer | registrar ABSENT/PERSISTS y evidencia exact-head |
| POST .../{id}/materialize | orchestrator | replies, reactions, Resolve Conversation, resumen, cierre y DONE |

Todos los comandos internos requieren el token del Control Plane y claves de idempotencia. Las operaciones externas usan scopes acotados de GitHub App; no hay passthrough REST/GraphQL.

## 6. Maquina de estados Publication

~~~mermaid
stateDiagram-v2
    [*] --> CREATED
    CREATED --> VALIDATING: CANDIDATE_SUBMITTED
    VALIDATION_FAILED --> VALIDATING: successor candidate
    IN_REVIEW --> VALIDATING: successor candidate
    CHANGES_REQUIRED --> VALIDATING: successor candidate
    APPROVED --> VALIDATING: successor candidate
    READY_TO_MERGE --> VALIDATING: successor candidate

    VALIDATING --> VALIDATION_FAILED: validation required FAIL
    VALIDATING --> ADMITTED: required jobs PASS
    ADMITTED --> IN_REVIEW: REMOTE_PUBLISHED exact HEAD

    IN_REVIEW --> CHANGES_REQUIRED: Codex findings / Human REQUEST_CHANGES
    IN_REVIEW --> APPROVED: Codex PASS + Human APPROVE
    APPROVED --> READY_TO_MERGE: mergeability PASS
    READY_TO_MERGE --> MERGED: governed merge

    CREATED --> SUPERSEDED: legacy aggregate retirement
    IN_REVIEW --> SUPERSEDED: legacy aggregate retirement
    CHANGES_REQUIRED --> SUPERSEDED: legacy aggregate retirement
    APPROVED --> SUPERSEDED: legacy aggregate retirement

    MERGED --> [*]
    SUPERSEDED --> [*]
~~~

### Quien define la transicion

El caller nunca envia state=APPROVED, state=DONE, etc.

1. caller invoca un comando;
2. service adquiere PublicationRow FOR UPDATE;
3. re-fold del stream bajo lock;
4. valida estado, HEAD y evidencia;
5. append del evento;
6. fold_events deriva el nuevo estado;
7. commit.

## 7. Candidate -> Publish -> Codex

~~~mermaid
sequenceDiagram
    autonumber
    participant C as Consumer / Implementer
    participant API as Control Plane API
    participant DB as Domain / Ledger
    participant CI as Validators
    participant PUB as Publisher
    participant GH as GitHub
    participant CX as Codex

    C->>API: Submit candidate
    API->>DB: CANDIDATE_SUBMITTED
    Note over DB: Publication = VALIDATING

    loop profile jobs
        CI->>API: validation(PASS/FAIL, evidence)
        API->>DB: VALIDATION_RECORDED
    end

    alt all required PASS
        DB->>DB: CANDIDATE_ADMITTED
        Note over DB: ADMITTED
    else validation failed
        DB->>DB: CANDIDATE_REJECTED
        Note over DB: VALIDATION_FAILED
    end

    C->>API: Publish
    API->>PUB: publish(publication)
    PUB->>GH: exact-old-head CAS fast-forward
    GH-->>PUB: branch/PR exact readback
    API->>DB: REMOTE_PUBLISHED
    Note over DB: IN_REVIEW

    C->>API: Request Codex Review
    API->>GH: verify canonical PR + exact HEAD
    API->>DB: CODEX_REVIEW_REQUESTED(expected verified HEAD)
    Note over DB: Automated Review = RUNNING

    API->>GH: user-attributed @codex review
    API->>DB: CODEX_REVIEW_TRIGGERED

    CX->>GH: native review + inline findings
    C->>API: Reconcile
    API->>GH: read review/comments/reactions
    API->>DB: CODEX_REVIEW_COMPLETED

    alt findings
        Note over DB: Publication = CHANGES_REQUIRED
    else clean review
        Note over DB: Publication = IN_REVIEW<br/>Automated Review = PASS
    end
~~~

## 8. Maquina de estado del Automated Review

~~~mermaid
stateDiagram-v2
    [*] --> NONE
    NONE --> RUNNING: CODEX_REVIEW_REQUESTED exact HEAD
    RUNNING --> PASS: terminal provider evidence + 0 findings
    RUNNING --> CHANGES_REQUIRED: terminal provider evidence + findings
    RUNNING --> UNAVAILABLE: trigger/provider unavailable

    PASS --> NONE: successor candidate
    CHANGES_REQUIRED --> NONE: successor candidate
    UNAVAILABLE --> NONE: successor candidate

    note right of RUNNING
      bound to publication
      PR
      exact HEAD
      run_id
      trigger comment
      provider actor
    end note
~~~

## 9. Principal Reviewer vs Orquestacion

El Principal Reviewer NO debe crear Issues, cross-links, labels, reactions, replies, ni resolver conversaciones.

Solo registra:
- finding_id;
- decision = ACCEPTED | REJECTED;
- priority;
- reason obligatorio si REJECTED;
- desired_feedback = +1 | -1 | none.

Todo side-effect GitHub posterior es responsabilidad de la API/orchestrator.

## 10. Flujo objetivo de remediacion

~~~mermaid
flowchart TD
    A["Review Run finaliza<br/>CODEX_REVIEW_COMPLETED almacena findings"] --> B["Principal Reviewer envia decisiones al orchestrator"]
    B --> C{"Decision por finding"}
    C -->|ACCEPTED| D["Decision ACCEPTED<br/>desired +1 o none"]
    C -->|REJECTED + reason| E["Decision REJECTED<br/>desired -1 o none"]
    D --> F{"Todos decididos?"}
    E --> F
    F -->|No| B
    F -->|Si| G["API crea Remediation Batch<br/>WORK_PACKAGE_CREATED guarda decisions"]
    G --> H["API crea GitHub type:fix Issue<br/>status:ready + cross-links"]
    H --> I["Implementer claim via API<br/>IN_PROGRESS"]
    I --> J["Implementer reporta implementation + candidate"]
    J --> K["API valida/admite/publica successor HEAD<br/>IMPLEMENTED -> VERIFYING"]
    K --> L["API dispara UNA successor Review"]
    L --> M{"Verificacion exact-head"}

    M -->|"accepted finding desaparece"| N["VERIFIED_ABSENT"]
    M -->|"accepted finding persiste"| O["PERSISTS; permanece abierto"]
    M -->|"finding nuevo"| P["usar persisted review finding para proximo batch tras decision"]

    N --> Q["API: resolution reply + stored reaction + Resolve Conversation"]
    E --> R["API finaliza rechazo: reason + stored -1 + Resolve Conversation"]

    Q --> S{"Todos cerrados?"}
    R --> S
    S -->|Si| T["API summary<br/>authoritative Batch DONE<br/>then close/project fix Issue"]
    S -->|No u O| U["Batch permanece VERIFYING / REWORK_REQUIRED<br/>sin summary ni cierre"]
~~~

Las referencias PR -> Fix Issue y Parent Issue -> Fix Issue son proyecciones automaticas de la API, no decisiones del reviewer.

## 11. API implementada para remediation (#14)

| Command | Caller | Intencion | Evento / proyeccion |
|---|---|---|---|
| POST /api/v1/internal/remediation/work-packages | Control Plane orchestrator | persistir decisiones enviadas por Principal Reviewer y crear/reusar batch | WORK_PACKAGE_CREATED; opcionalmente IMPLEMENTATION_ISSUE_LINKED |
| GET /api/v1/internal/remediation/work-packages/{id} | UI/orchestrator | leer estado plegado | no muta ledger |
| GET /api/v1/internal/remediation/work-packages/{id}/events | audit/UI | leer historial append-only | no muta ledger |
| POST .../{id}/claim | General Implementer | comenzar/reanudar trabajo | WORK_PACKAGE_CLAIMED; labels y Lifecycle = In Progress |
| POST .../{id}/implementation | General Implementer | reportar candidate/HEAD/evidencia | IMPLEMENTATION_SUBMITTED; labels `status:review` y Lifecycle = Review |
| POST .../{id}/successor-review | orchestrator | enlazar run y candidate exactos | SUCCESSOR_REVIEW_STARTED; labels `status:review` y Lifecycle = Review |
| POST .../{id}/rejected-finalization | orchestrator | iniciar cierre solo para decisiones REJECTED | REJECTED_FINDINGS_FINALIZATION_STARTED |
| POST .../{id}/findings/{finding_id}/verification | Principal Reviewer | registrar resultado con evidencia; un PERSISTS tras completar el set activa rework | FINDING_VERIFIED / WORK_PACKAGE_REWORK_REQUIRED |
| POST .../{id}/materialize | orchestrator | reconciliar efectos GitHub | GITHUB_ARTIFACT_MATERIALIZED, WORK_PACKAGE_SUMMARY_MATERIALIZED, IMPLEMENTATION_ISSUE_CLOSED, WORK_PACKAGE_COMPLETED |

El caller envia intencion/evidencia; no puede setear directamente DONE o READY. Si no se proporciona `implementation_issue_number`, primero se persiste el batch READY; luego la API busca el marker determinista, crea/reutiliza el Fix Issue, registra su numero en `IMPLEMENTATION_ISSUE_LINKED`, lo agrega como sub-issue del objetivo padre y sincroniza labels y Project V2. Los retries leen el marker antes de crear otro Issue.

## 12. Maquina de estados Remediation Batch

~~~mermaid
stateDiagram-v2
    [*] --> READY: all findings adjudicated
    READY --> IN_PROGRESS: implementer claim
    IN_PROGRESS --> IMPLEMENTED: implementation submitted
    IMPLEMENTED --> VERIFYING: exact submitted candidate/head published + reviewed
    VERIFYING --> DONE: all findings verified/materialized
    VERIFYING --> REWORK_REQUIRED: all accepted findings checked; any PERSISTS
    REWORK_REQUIRED --> IN_PROGRESS: implementer reclaims package
    READY --> VERIFYING: all findings REJECTED; decision-only finalization
    DONE --> [*]

    note right of READY
      GitHub projection:
      type:fix
      status:ready
    end note
    note right of VERIFYING
      PERSISTS blocks materialization and closure
      mixed ABSENT/PERSISTS reopens all accepted findings
      every attempt's events remain immutable
    end note
    note right of REWORK_REQUIRED
      next claim and implementation create a new attempt
      next review must match that attempt's exact candidate/head
      GitHub projection remains status:review / Lifecycle = Review
    end note
~~~

## 13. Maquina de estados Finding

~~~mermaid
stateDiagram-v2
    [*] --> AWAITING_VERIFICATION: accepted
    [*] --> REJECTED_BY_PRINCIPAL: rejected + reason
    AWAITING_VERIFICATION --> VERIFIED_ABSENT: successor exact-head review
    AWAITING_VERIFICATION --> PERSISTS: successor review still finds issue
    VERIFIED_ABSENT --> MATERIALIZED_RESOLVED: API reply + stored reaction + resolve
    REJECTED_BY_PRINCIPAL --> MATERIALIZED_REJECTED: API reason + stored reaction + resolve
    MATERIALIZED_RESOLVED --> [*]
    MATERIALIZED_REJECTED --> [*]
~~~

## 14. Principal Reviewer -> Implementer -> Verification

~~~mermaid
sequenceDiagram
    autonumber
    participant PRV as Principal Reviewer
    participant UI as Control Plane UI
    participant API as Control Plane API
    participant DB as Ledger
    participant GH as GitHub
    participant IMP as General Implementer
    participant CX as Review Provider

    API->>DB: Persist provider findings
    Note over DB: Findings = DETECTED

    PRV->>UI: Accept/reject findings
    UI->>API: principal decisions
    API->>DB: persist decisions

    API->>DB: WORK_PACKAGE_CREATED
    Note over DB: Batch = READY; ledger owns identity and decisions
    API->>GH: find marker or create type:fix issue + labels
    API->>GH: link as parent sub-issue + Lifecycle = Ready
    GH-->>API: issue id / node id
    API->>DB: IMPLEMENTATION_ISSUE_LINKED

    IMP->>API: claim batch
    API->>DB: READY -> IN_PROGRESS
    API->>GH: project status:in-progress

    IMP->>API: implementation complete + candidate ref + summary
    API->>DB: IN_PROGRESS -> IMPLEMENTED

    API->>API: validate/admit/publish successor
    API->>DB: Batch -> VERIFYING
    API->>CX: one successor exact-head review
    CX-->>API: provider evidence
    API->>DB: verify prior findings

    alt prior accepted findings resolved
        API->>GH: per-finding resolution reply
        API->>GH: materialize stored +1/-1
        API->>GH: Resolve Conversation
        API->>DB: materialization complete
        API->>GH: summary comment + close fix issue
        API->>DB: Batch -> DONE
    else any accepted finding persists
        API->>DB: append WORK_PACKAGE_REWORK_REQUIRED
        Note over DB: retain prior attempt; reset only the current verification projection
        API->>GH: keep all threads open; no reaction/reply/resolution or close
        IMP->>API: reclaim and submit a new implementation attempt
        API->>DB: append WORK_PACKAGE_CLAIMED + IMPLEMENTATION_SUBMITTED
        API->>CX: bind a review to the exact new implementation head
    end
~~~

## 15. Human Review

~~~mermaid
sequenceDiagram
    autonumber
    participant H as Human Reviewer
    participant UI as Control Plane UI
    participant API as Control Plane API
    participant DB as Domain
    participant M as Mergeability

    H->>UI: open current Publication
    UI->>API: read current exact-head state
    API-->>UI: HEAD + Codex + remediation state

    alt Codex required not PASS or remediation open
        UI-->>H: approval unavailable
    else eligible
        H->>UI: APPROVE / REQUEST_CHANGES
        UI->>API: review(reviewed_head_sha, decision)
        API->>DB: lock + re-fold + exact-head validation
        alt APPROVE
            Note over DB: Publication -> APPROVED
            M->>API: mergeability(head_sha)
            API->>DB: exact-head mergeability
            Note over DB: READY_TO_MERGE
        else REQUEST_CHANGES
            Note over DB: CHANGES_REQUIRED
        end
    end
~~~

La UI solo es command surface. La API revalida todo server-side.

## 16. Modelo de proyeccion GitHub

~~~mermaid
flowchart LR
    DB["Control Plane Ledger<br/>AUTHORITATIVE"] -->|project| GI["GitHub Issue"]
    DB -->|project| GPR["GitHub PR"]
    DB -->|materialize| TH["Review Thread"]
    DB -->|materialize| RX["Reaction +1/-1"]
    DB -->|materialize closure| RS["Resolve Conversation"]
    DB -->|project lifecycle| LB["Labels/status"]
    GI -. external ids .-> DB
    GPR -. exact-head readback .-> DB
    TH -. provider ids .-> DB
    style DB stroke-width:4px
~~~

Invariantes de proyeccion:
- IDs externos se persisten despues de crear el objeto.
- retries reutilizan IDs/correlation keys.
- reaction GitHub no prueba decision; la decision esta en ledger.
- Resolve Conversation no prueba verificacion; la prueba es successor review.
- cross-links son API-generated projections.

## 17. Idempotencia

| Efecto | Correlation key |
|---|---|
| Review Run | publication_id + head_sha + attempt |
| Finding | provider + run_id + provider_comment_id |
| Principal Decision | finding_id |
| Remediation Batch | publication_id + review_run_id + issue link; deterministic pending id before issue creation |
| GitHub Fix Issue | remediation_batch_id hidden marker |
| Reaction | finding_id + desired_reaction |
| Resolution Reply | finding_id + verified_successor_run_id |
| Resolve Conversation | finding_id + verified_successor_run_id |
| General Summary | remediation_batch_id + finalization_version |

## 18. Failure / Recovery

| Fallo | Comportamiento requerido |
|---|---|
| GitHub write OK, DB persistence falla | readback por marker/correlation, no duplicar |
| Provider result stale HEAD | evidencia historica, no current |
| successor gana mientras se solicita review | expected-head under lock rechaza stale request |
| PR/ref readback stale | bounded read-only retry, nunca segundo push |
| Principal Decision retry | idempotente si identica; cambio requiere command auditado |
| Implementer completion retry | mismo batch/candidate digest = idempotente |
| Thread resolution retry | reconocer already-resolved |
| Nuevo finding durante verification | persistir para proximo batch |

## 19. Estado actual vs target

| Capability | Estado |
|---|---|
| Publication event ledger | Implementado |
| exact-head candidate lifecycle | Implementado |
| same Publication / same PR successors | Implementado |
| publisher CAS + recovery | Implementado |
| user-attributed Codex trigger | Implementado / dogfood live |
| Review Run correlation | Implementado |
| findings persistence | Implementado |
| Human exact-head review API | Implementado |
| Principal Review Decision and Remediation Batch ledger | Implementado en #14 |
| automatic Implementation Fix Issue with marker recovery | Implementado en #14 |
| parent sub-issue and managed labels | Implementado en #14 |
| Project V2 lifecycle projection | Implementado y smoke live validado; Project #4 usa field `Lifecycle`, option `Review` para IMPLEMENTED/VERIFYING/REWORK_REQUIRED y label `status:review`; configura `CONTROL_PLANE_REMEDIATION_PROJECT_NUMBER`, `CONTROL_PLANE_REMEDIATION_PROJECT_LIFECYCLE_FIELD` y el secreto dedicado `CONTROL_PLANE_REMEDIATION_PROJECT_TOKEN`; para Project personal + repo privado el PAT classic requiere `project` + `repo`; lookup por `repositoryOwner` |
| implementer claim/completion API | Implementado en #14 |
| reaction/reply/Resolve Conversation materialization | Reactions/replies e Issues usan GitHub App; GitHub no permite `resolveReviewThread` con installation token en este repositorio, por lo que Resolve Conversation usa el secreto de usuario dedicado `CONTROL_PLANE_REMEDIATION_THREAD_TOKEN`; Project V2 usa `CONTROL_PLANE_REMEDIATION_PROJECT_TOKEN`. Los tres caminos quedan separados del PAT de Codex |
| verified finding closure | Implementado en #14; requiere successor review corriente y verificacion del Principal Reviewer |
| remediation UI | posterior al contrato domain/API |
| reusable integration guide | entregable #14 |

## 20. Politica estabilizada para remediation

1. Un batch solo pasa a READY con decision explicita para cada finding. La
   decision y el motivo obligatorio de REJECTED quedan en el primer evento.
2. Las decisiones son inmutables en este contrato. Un cambio posterior necesita
   un futuro comando de amendment auditado; no se edita el evento original.
3. REJECTED puede finalizarse sin candidate/successor review solo cuando todos
   los findings del batch fueron rechazados con motivo.
4. ACCEPTED se verifica contra un successor Review Run completado y el exact
   published HEAD. El Principal Reviewer registra ABSENT o PERSISTS con run,
   HEAD y evidencia.
5. Un finding PERSISTS sigue abierto en el mismo batch y bloquea materializacion
   y DONE. Cuando todos los findings ACCEPTED tienen resultado, cualquier
   PERSISTS agrega `WORK_PACKAGE_REWORK_REQUIRED`; la API permite reclamar un
   nuevo intento y mantiene inmutables los eventos anteriores.
6. Findings nuevos que aparecen durante successor review se guardan para el
   siguiente batch; no se agregan retrospectivamente al batch actual.
7. Human APPROVE sigue bloqueado mientras Codex requerido no sea PASS o haya
   remediation abierta.
8. El paquete y su ledger son provider-neutral. El adaptador Codex conserva el
   trigger/correlation exact-head, pero no redefine el ciclo generico.
9. Una caida de GitHub no borra eventos. Cada side effect usa lease, relectura
   de identidad/correlation y recibo antes de considerarse materializado.
10. Project #4 usa el campo `Lifecycle` y sus opciones existentes. IMPLEMENTED,
    VERIFYING y REWORK_REQUIRED se proyectan como `status:review` / `Review`;
    el nombre se configura mediante
    `CONTROL_PLANE_REMEDIATION_PROJECT_LIFECYCLE_FIELD=Lifecycle`.

## 21. Integracion para otra API/repositorio

El repositorio consumidor aporta/configura:

1. repo identity + GitHub App installation;
2. validation profile + JobDefinitions versionados;
3. candidate producer;
4. Issue/work-item logico;
5. provider adapter/config;
6. human review authorization/UI;
7. publisher branch policy;
8. mergeability adapter;
9. integracion Review Run/Finding/Decision/Batch.
10. `CONTROL_PLANE_REMEDIATION_PROJECT_NUMBER`, GitHub App con `issues:write` y
    `pull_requests:write`, y `CONTROL_PLANE_REMEDIATION_PROJECT_TOKEN` dedicado
    a Project V2. Para el Project personal actual con Issues de repo privado,
    GitHub requiere PAT classic `project` + `repo`; no se reutiliza para Codex.
11. un validador CI reproducible que emita evidencia ligada al candidate exacto.

La API consumidora NO implementa su propia:
- maquina de findings;
- creacion de remediation issues;
- reactions/resolution;
- exact-head gate logic.

Esas responsabilidades pertenecen al Control Plane.

## 22. Dogfood actual

~~~text
Issue #10
  -> Publication cb83c3e6-a5a2-4ca6-80eb-4343506a6383
  -> PR #13
  -> HEAD 9c169ae0b4b9235bc6fff8a2148e17c1054b5b65
  -> Review Run 1e1b5f1a-efbf-5275-a431-74cc21528579
  -> 4 Codex P1
  -> 1 internal dogfood P1 BIGINT
  -> Implementation Fix Issue #14
  -> Remediation Batch 70abf930-6eab-5a93-bf62-30bcaf4ea37b (IN_PROGRESS)
~~~

El codigo y la documentacion de #14 implementan este contrato en el working
tree. El batch dogfood sigue IN_PROGRESS hasta que un candidate sea admitido y
publicado por el Control Plane, un successor review exact-head verifique los
findings y la API materialice sus recibos. El Issue #14 y sus links manuales son
bootstrap; no son el modelo operativo para batches nuevos.

## 23. Definition of Done arquitectonico

La arquitectura queda apta para integrar otra API solo cuando:
- las capacidades de #14 esten implementadas y verificadas con la instalacion GitHub App configurada;
- #14 atraviese su propio workflow;
- successor review verifique los findings actuales;
- reactions/replies/Resolve Conversation sean producidos por la API;
- fix Issue cierre programaticamente;
- human review + merge finalicen en el PR canonico;
- este documento se actualice contra endpoints/eventos reales;
- un segundo repositorio valide el onboarding checklist.


### Governed merge execution and reconciliation

Once a Publication is `READY_TO_MERGE`, Plane owns the final write boundary.
The merge command must re-read the canonical PR, verify repository/PR/base/head
identity, re-read the base ref, require it to equal the admitted candidate
`base_sha`, and only then send GitHub the exact governed HEAD as the expected
merge SHA.
GitHub's response is evidence only after a second readback proves the PR is
merged. Plane uses the dedicated merged-status endpoint as the authoritative
boolean. The merge commit SHA is taken from the PR payload when available and
recovered from the native `merged` issue event when the installation-token PR
payload omits it. If both sources expose a SHA, they must match exactly.

The authoritative ledger receipt is:

~~~text
MERGED
  head_sha
  pull_request_number
  merge_commit_sha
  source = PLANE_MERGE | GITHUB_RECONCILE
~~~

`MERGED` is idempotent for one exact receipt and remains terminal.

If GitHub already reports the exact canonical PR merged while Plane is still
`READY_TO_MERGE`, the reconciler records the same receipt with
`source=GITHUB_RECONCILE`. This covers a process restart, an uncertain merge
response, and the PR #13 dogfood case without a manual `append_event(MERGED)`.

If GitHub reports an exact-head merge while Plane was not `READY_TO_MERGE`,
the reconciler persists `MERGE_POLICY_VIOLATION` and leaves the Publication
in its prior lifecycle state. That violation permanently taints the current
Publication for governed merge: later mergeability recording cannot manufacture
`READY_TO_MERGE`, and reconciliation cannot convert the same external merge
into a governed `MERGED` receipt. Recovery requires an explicit new governed
Publication rather than laundering the out-of-band merge.

~~~mermaid
sequenceDiagram
    autonumber
    participant P as Plane
    participant DB as Ledger
    participant GH as GitHub

    P->>DB: read READY_TO_MERGE + exact PR/HEAD
    P->>GH: GET canonical PR
    GH-->>P: open + exact HEAD
    P->>GH: merge(expected_head_sha)
    GH-->>P: merge response
    P->>GH: GET canonical PR
    GH-->>P: merged + merge_commit_sha
    P->>DB: MERGED(exact receipt)
~~~

## 24. Human Merge Override / Break-glass

El merge tiene dos caminos validos y auditables.

~~~mermaid
flowchart TD
    A["PR exact HEAD publicado"] --> B{"Control Plane Merge Gate"}

    B -->|"todos los gates PASS"| C["READY_TO_MERGE"]
    C --> D["GOVERNED_MERGE"]

    B -->|"gates pendientes"| E["NO merge-ready"]
    E --> F{"Humano con MERGE_OVERRIDE_AUTHORIZE?"}
    F -->|No| G["Merge bloqueado por politica Control Plane"]
    F -->|Si| H["API muestra blockers actuales"]
    H --> I["Humano confirma exact HEAD + reason"]
    I --> J["HUMAN_MERGE_AUTHORIZED<br/>one-shot / exact-head"]
    J --> K{"Ejecucion"}
    K -->|"Control Plane"| L["API ejecuta merge"]
    K -->|"GitHub manual"| M["Humano pulsa Merge en GitHub"]
    L --> N["MERGE_COMPLETED<br/>mode=HUMAN_OVERRIDE"]
    M --> O["Reconciler verifica authorization"]
    O -->|valida| N
    O -->|ausente/invalida| P["UNAUTHORIZED_EXTERNAL_MERGE"]

    N --> Q["Publication = MERGED"]
    Q --> R["Plan mantiene findings/remediation/dependencies pendientes"]
~~~

### Diferencia entre Human Review y Human Merge Override

~~~text
Human Review APPROVE
    = evaluacion de calidad/correctitud del exact HEAD

Human Merge Override
    = aceptacion explicita del riesgo de gates pendientes
      para permitir el merge de ese exact HEAD
~~~

Una decision no implica automaticamente la otra.

### Estado persistido

El ledger debe conservar:

- merge_mode = GOVERNED | HUMAN_OVERRIDE;
- authorization_id;
- authenticated actor;
- exact publication/pr/head;
- timestamp;
- reason obligatorio;
- snapshot de gates pendientes aceptados;
- merge commit SHA;
- GitHub merge actor;
- authorization consumed/expired/revoked state.

### Exact-head / one-shot

La autorizacion:
- vale para un solo exact HEAD;
- se invalida con successor HEAD;
- se consume en un solo merge;
- puede expirar;
- puede revocarse antes de ser consumida.

### Secuencia de override

~~~mermaid
sequenceDiagram
    autonumber
    participant H as Authorized Human
    participant UI as Control Plane UI
    participant API as Control Plane API
    participant DB as Ledger
    participant GH as GitHub
    participant PLAN as Plan

    H->>UI: Request merge override
    UI->>API: authorize(expected_head_sha, reason)
    API->>DB: read current exact-head gates
    API-->>UI: blockers + exact HEAD confirmation
    H->>UI: Confirm
    UI->>API: confirm authorization
    API->>DB: HUMAN_MERGE_AUTHORIZED
    Note over DB: one-shot, exact-head

    alt Merge through Control Plane
        H->>API: merge using authorization
        API->>GH: merge expected exact HEAD
        GH-->>API: merge commit
        API->>DB: MERGE_COMPLETED(mode=HUMAN_OVERRIDE)
    else Human merges in GitHub
        H->>GH: Merge pull request
        GH-->>API: merged state observed by reconciler
        API->>DB: validate unconsumed authorization
        API->>DB: MERGE_COMPLETED(mode=HUMAN_OVERRIDE)
    end

    API->>PLAN: recalculate remaining work
    Note over PLAN: unresolved findings/remediation remain open
~~~

### Regla de escape

El override permite salir de un bloqueo operativo sin falsificar el estado del proceso.

El merge no transforma automaticamente:
- findings abiertos en resueltos;
- remediation abierta en DONE;
- dependencias pendientes en completas;
- parent work item en DONE.

Plan recalcula el trabajo restante despues del merge y puede moverlo a follow-up work packages/delivery revisions.

### Merge externo sin autorizacion

Si GitHub reporta un merge mientras:
- Control Plane Merge Gate = false; y
- no existe HUMAN_MERGE_AUTHORIZED valido para ese exact HEAD;

registrar:

UNAUTHORIZED_EXTERNAL_MERGE

No reinterpretarlo como governed/human-authorized merge.


## 25. Session-independent operation

The Control Plane must eliminate dependency on conversational memory for workflow continuity.

A role starts from authoritative state, not from a prior chat transcript.

~~~mermaid
flowchart LR
    PLAN["Plan / Control Plane<br/>authoritative work state"] --> R1["Principal Reviewer session"]
    PLAN --> R2["General Implementer session"]
    PLAN --> R3["Human Reviewer session"]

    R1 -->|submit decisions| PLAN
    R2 -->|claim-next / implementation-complete| PLAN
    R3 -->|approve / request-changes| PLAN

    PLAN --> NEXT["derive next eligible work / role"]

    style PLAN stroke-width:4px
~~~

Required behavior:

- a new implementer session can call claim-next and receive a complete work context;
- a new Principal Reviewer session can request next-review and receive the exact Review Run/findings;
- a new Human Reviewer session receives only exact-head eligible work;
- no workflow obligation exists only in chat/history/memory;
- work context and acceptance criteria are persisted/versioned for audit;
- GitHub projections can be reconstructed from the ledger;
- session restart does not change lifecycle truth.

The objective is that any authorized agent/human can continue the workflow from the current Control Plane state without instructions such as "continue the previous conversation".

## 26. Deferred GitHub-native enforcement backlog

GitHub-native required-check / ruleset enforcement and mapping of GitHub bypass permissions to Control Plane RBAC are intentionally deferred to backlog **#16**.

Current critical-path responsibilities remain in #15:

- authoritative Control Plane Merge Gate semantics;
- GOVERNED_MERGE;
- HUMAN_OVERRIDE_MERGE;
- exact-head one-shot authorization;
- merge audit/reconciliation;
- Plan lifecycle/dependency/delivery orchestration.

Deferred to #16:

- GitHub required-check enforcement;
- branch protection/rulesets;
- GitHub plan/platform prerequisites;
- native bypass-permission integration;
- reusable RBAC mapping for platform enforcement.

#16 is related but non-blocking and has no current Milestone.


## 27. Validation execution model

The business API owns its product tests; Plane owns orchestration and evidence.

~~~mermaid
flowchart LR
    SRC["API / Publisher<br/>submit candidate intent"] --> CP["Control Plane"]
    CP --> RM["Repository Manifest"]
    CP --> VP["Validation Profile"]
    VP --> JD["Versioned JobDefinitions"]

    JD --> R1["Controlled source/build runner"]
    JD --> R2["Ephemeral integration environment"]
    JD --> R3["External environment validator"]
    JD --> R4["External executor callback<br/>only when required"]

    R1 --> EV["Evidence bound to exact candidate"]
    R2 --> EV
    R3 --> EV
    R4 --> EV
    EV --> G{"Required jobs PASS?"}
    G -->|Yes| AD["Candidate ADMITTED"]
    G -->|No| RJ["VALIDATION_FAILED"]

    AD --> LIFE["Plane continues publication/review/remediation lifecycle"]
~~~

Default model:
- tests/scripts/contracts live in the application repository;
- the repository declares what to run;
- Plane executes them against the immutable candidate using reusable runners;
- APIs do not expose privileged HTTP endpoints merely to run individual tests.

Only tests that genuinely require a running environment use an endpoint/environment adapter.

The source application requests intent such as "publish candidate X"; it does not orchestrate CI steps or lifecycle states.


## 28. Candidate validation and repository policy changes

Validation separates the authoritative active policy from the source tree being tested.

~~~mermaid
flowchart TD
    AP["Plane DB<br/>ACTIVE repository config vN"] --> JOBS["Required JobDefinitions"]
    C["Candidate exact HEAD B<br/>code + tests + contracts"] --> RUN["Controlled validation runner"]
    JOBS --> RUN
    RUN --> EV["Exact-head evidence"]

    C --> D{"Controlled config changed?"}
    D -->|No| EV
    D -->|Yes| P["Repository Config Proposal<br/>vN -> proposed vN+1"]
    P --> CUR["Current-policy lane<br/>vN obligations"]
    P --> PRO["Prospective-policy lane<br/>proposed vN+1 on B"]
    CUR --> DEC["Policy migration decision"]
    PRO --> DEC
    DEC --> MERGE["Merge config/code to default branch"]
    MERGE --> SYNC["Plane config sync + digest readback"]
    SYNC --> ACT["Activate immutable vN+1<br/>future Publications"]
~~~

Key invariants:

- active policy comes from Plane DB and was previously synchronized/approved from the default branch;
- source code, test code, scripts and contracts are executed from the exact candidate HEAD, never from master;
- changing tests does not by itself let the candidate redefine required gates;
- changing the repository manifest/profile/job bindings creates an explicit config proposal;
- a candidate cannot remove a required gate and then use that weaker proposed policy to self-admit;
- controlled policy migrations prove the old policy on the base, the proposed policy on the candidate, persist the semantic diff and require an explicit authorized decision when obligations are removed/replaced;
- proposed config becomes ACTIVE only after it reaches the default branch and Plane reads back the expected digest;
- existing Publications remain pinned to the configuration version/digest with which they started.

## 29. Provider unavailability and emergency implementation

Provider availability is not lifecycle authority. If Codex implementation or
Codex Code Review is unavailable, the authoritative work package remains in the
Control Plane ledger. An explicitly audited fallback implementer may continue the
implementation and local validation, but role separation still applies: the same
actor must not self-approve the resulting implementation.

For a required automated review, unavailability is fail-closed. The system does
not manufacture PASS evidence, does not satisfy the Human Review prerequisite,
and does not advance the governed merge gate. Existing `CODEX_REVIEW_UNAVAILABLE`
evidence records trigger-level failures; provider non-response remains RUNNING
until a bounded timeout/availability policy is introduced. This timeout policy is
a concrete future hardening item and must not be emulated by chat memory.

The #17 dogfood also established these exact-head invariants: candidate submission
is rejected while automated review is RUNNING; Human APPROVED is rejected while
any Publication remediation package is unfinished; work-package DONE revalidates
the current Publication review/head under lock; and rejected-only adjudication
uses `REMEDIATION_CLEARED` to restore same-head Human Review without rewriting the
provider result.

Publication preflight recovery is compensating and append-only: if an ADMITTED
candidate is rejected before any remote push because the configured base no
longer matches the remote base, Plane appends `CANDIDATE_REJECTED` with
`REMOTE_BASE_MOVED_AFTER_ADMISSION` and returns the Publication to
`VALIDATION_FAILED`. A remediation package already bound to that candidate uses
`WORK_PACKAGE_REWORK_REQUIRED -> IN_PROGRESS` before a corrected candidate is
submitted. Prior candidate, validation and implementation events are retained;
no candidate identity or prior event is overwritten.

## Deep-review concurrency invariants

- Candidate submission and remediation verification serialize with a deterministic
  Publication -> work-package lock order. A Publication cannot advance while any
  package is `VERIFYING`.
- Publisher base identity is re-read at the remote write boundary and again before
  `REMOTE_PUBLISHED`; a moved base cannot become authoritative publication evidence.
- `WORK_PACKAGE_COMPLETED` is authoritative. GitHub Issue closure, managed `Done`
  labels, and Project `Done` are retryable projections that occur only afterward.
- Project V2 bounded scans fail closed if the page cap is reached with unread pages;
  incomplete observation never authorizes `addProjectV2ItemById`.
- Codex/provider trigger dispatch performs a final canonical PR exact-head readback
  immediately before posting the reserved trigger comment.

## Dispatch fencing and remote compensation

- Lease expiry never authorizes a stale worker to perform an irreversible remote
  side effect. The final mutation phase is fenced by row ownership held through
  remote write and receipt persistence.
- Provider trigger dispatch and remediation artifact dispatch share that rule;
  takeover is allowed only before the stale owner enters the fenced mutation
  section.
- An uncertain provider-trigger POST is not terminal evidence of unavailability.
  Before releasing the fenced dispatch, Plane re-reads issue comments and recovers
  exactly one authorized marker for the same run/head when GitHub accepted the
  write but the response was lost. If readback cannot prove either outcome, the
  run remains recoverable/RUNNING rather than being rewritten as unavailable.
- Publication base drift detected after a successful branch push triggers exact-ref
  compensation before candidate rejection. The previous governed ref is restored
  (or the initial ref removed) only while the remote ref still equals the rejected
  candidate SHA.


---

## Plan-owned work graph and deterministic claim-next

The generic work scheduler is a separate authoritative aggregate from Publication and
Remediation. GitHub Issues/Project fields remain projections; they are not used to
decide whether work is executable.

### Authoritative lifecycle

```text
BACKLOG
  -> BLOCKED
  -> READY
  -> IN_PROGRESS
  -> REVIEW
  -> DONE

SUSPENDED is an explicit pause state.
```

The effective state is reconstructed from the hash-chained work-item ledger plus
the immutable work graph:

- `READY` requires release, no suspension, no hard dependency that is not
  `DONE`, and no required child that is not `DONE`;
- `IN_PROGRESS` exists only after an atomic claim;
- implementation completion produces `REVIEW`, never `DONE`;
- `DONE` requires a separate authoritative completion command;
- parent state is derived from required children on every read rather than being
  manually copied from GitHub labels.

A non-executable parent becomes `REVIEW` once it is released and every required
descendant blocker is complete, leaving the parent-specific acceptance gate
explicit.

### Deterministic queue

The executable queue orders candidates by:

1. priority (`P0` before `P1`, represented as numeric 0..4);
2. topology depth derived from hard dependencies and required-child blockers;
3. explicit rank;
4. stable work-item id.

Topology depth is zero for work with no blockers and increases by one beyond the
deepest blocker. This preserves blocker-before-dependent ordering even after an
upstream item reaches `DONE` and the dependent becomes `READY`.

Unsatisfied dependencies are derived as `BLOCKED` and therefore never enter the
claimable set. PostgreSQL claim-next obtains a repository-scoped advisory
transaction lock and then row-locks the selected item before re-reading state and
appending `WORK_CLAIMED`. Hard-dependency mutations acquire that same
repository-scoped transaction lock before the target row lock and before the
cycle check/write. This prevents opposite concurrent edges from both validating
against the same pre-write graph, and preserves one lock order between scheduling
and graph mutation. Specific-item claims also row-lock and re-read before
mutation.

Every claim carries a server-policy lease id and UTC expiry. An active implementer
may renew the same lease identity. When the lease expires before implementation
completion, the effective state derives back to `READY`; the stale actor can no
longer submit implementation evidence, and a new claim with a new idempotency key
may recover the work. The expired claim remains in the hash-chained ledger for
audit rather than being deleted or rewritten.

### Fresh-session context

Each work item records its immutable versioned context snapshot and SHA-256 digest
inside the hash-chained `WORK_CREATED` ledger event. The relational context
columns are only a read/index projection and are verified against that event on
every reconstruction; projection drift fails closed. Required parent/child
blocking is likewise derived from the child creation ledgers rather than trusted
from a mutable projection alone.

A new implementer session receives the same context together with:

```text
state
blockers
dependencies
required_children
implementer
next_role
next_action
```

The initial next-action vocabulary is deliberately provider-neutral:

```text
WAIT_RELEASE
WAIT_DEPENDENCIES
CLAIM_WORK
IMPLEMENT
WAIT_REVIEW
DONE
SUSPENDED
```

The GitHub Webhook/Event Gateway roadmap consumes this derived contract after
review/provider events: the webhook wakes Plane, Plane re-reads authoritative
GitHub state, applies a legal domain transition, then asks the work/orchestration
layer for the next role/action. The webhook payload itself never becomes
lifecycle authority.

### API slice

```text
POST /api/v1/internal/work-items
POST /api/v1/internal/work-items/{id}/dependencies

GET  /api/v1/work/next
POST /api/v1/work/claim-next

GET  /api/v1/work-items/{id}
GET  /api/v1/work-items/{id}/events
POST /api/v1/work-items/{id}/claim
POST /api/v1/work-items/{id}/claim/renew
POST /api/v1/work-items/{id}/claim/release
POST /api/v1/work-items/{id}/implementation

POST /api/v1/internal/work-items/{id}/release
POST /api/v1/internal/work-items/{id}/complete
POST /api/v1/internal/work-items/{id}/suspend
POST /api/v1/internal/work-items/{id}/resume
```

Every mutating command is idempotency-keyed where caller retries are possible.
Lifecycle reconstruction verifies the per-item event hash chain before returning
state.
