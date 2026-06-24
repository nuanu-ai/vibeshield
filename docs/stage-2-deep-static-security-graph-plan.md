# Stage 2 - Deep Static v1: Security Graph + Hypotheses

VibeShield already gives the owner a small Fix Pack from deterministic Quick
Scan facts. Deep Static v1 adds the missing context: whether a finding is merely
present, or whether code, dependency, CI, and IaC facts support a realistic
static attack path.

Stage 2 builds a deterministic Security Graph and static hypotheses on top of the
current Quick Scan. The app is not started; package scripts, tests, builds,
migrations, and framework runtime behavior are not executed. Direct findings stay
direct; a hypothesis is added only when the graph can show the path and the
coverage behind the claim.

Done looks like one line in the report: "Don't ship yet - this public route can
pass a user-controlled URL into an outbound HTTP client, and no destination
allowlist was observed on that path. Here is the static path and the validation
recipe."

## Decisions

What Stage 2 builds and where the boundaries are.

- Deep Static is explicit in the CLI: `vibeshield scan <repo> --deep`. A scan
  without `--deep` keeps the Stage 1 Quick Scan behavior and report shape.
- One canonical entity, **SecurityGraph**, is the source of truth for Deep Static
  correlation. `repository-map.json` is a derived human view, not a pipeline
  truth source.
- One `ProgramAnalysisBackend` behind an interface; the first backend is Atom.
  The interface stays language-agnostic so a heavier backend (Joern) fits later
  without changing callers. v1 prioritizes JavaScript/TypeScript and Python
  extraction quality, where the audience lives; languages the backend cannot
  analyze well are reported as `language_support` coverage degradation with the
  language named.
- Boundaries are generic: HTTP route, GraphQL operation, RPC method, CLI command,
  queue consumer, webhook, scheduled job, file parser, upload handler, and CI
  trigger. Framework-specific packs can raise coverage later without changing the
  graph model.
- Five deterministic correlation rule families: external input to dangerous
  operation, Quick SAST finding to reachable path, dependency vulnerability to
  usage path, CI supply-chain path, and secret impact chain.
- Static hypotheses use only these statuses: `candidate`, `statically_supported`,
  `statically_contradicted`, `inconclusive`. `confirmed` is reserved for the
  later runtime-validation stage.
- One new model-backed stage, `hypotheses.enrich`; Stage 1 remediation stays in
  place for direct Fix Pack actions.
- Direct findings and attack hypotheses are separate result types. A published
  production secret can stay a direct finding while also supporting an impact
  chain; the report groups a direct finding and a linked hypothesis into one
  remediation action when that avoids duplicate work for the owner.
- Framework-specific authorization is the next enrichment, not part of v1. BOLA
  may appear only as an experimental candidate, and only when the graph already
  observes principal source, request-derived object ID, data access, and
  ownership or tenant control facts.
- Two stages only (2A foundation, 2B hypotheses + report). The four gates are the
  only checkpoints; no further slicing.
- The full vertical path comes first: source -> CPG -> graph -> rules -> static
  validation -> enrich -> report. Wiring Quick Scan findings into the graph as
  corroborated/weakened/contradicted context and richer action grouping is the
  deferrable part: in v1, import findings as nodes only where a rule needs them
  and keep the contextual-status UX thin.
- Acceptance is by real-run demonstration on a real repo, not by precision or
  recall metrics. Quantitative quality measurement (eval corpus, false-positive
  gates) is a deliberate later phase; implementation cost is not the constraint
  here, getting the whole path real is.

## Invariants

Constraints that hold across every stage and gate. They are correctness and
safety rules that shape the code now, not quality tuning.

- **Do not touch resume** - semantics, commands, or roadmap text - while
  implementing Stage 2.
- **One Microsandbox per run, network on.** Deep Static reads the same source
  snapshot as Quick Scan and never starts the scanned app.
- **No repo code execution, including during the CPG build.** No package scripts,
  installs, builds, or migrations run on the scanned repo. Intra-repo cross-file
  analysis needs no dependency install; if the backend wants dependency
  resolution, fetch metadata only and disable lifecycle scripts (for example
  `--ignore-scripts`). Following into third-party package code (for
  `affected_symbol_reachable`) is deferred and shows as a coverage gap, never a
  silent omission.
- **Quick Scan findings are immutable.** Deep Static never rewrites finding
  severity, evidence, or fingerprints; it writes separate contextual records.
- **The model cannot create or change facts.** `hypotheses.enrich` cannot
  introduce a new graph path, finding, status, static confidence, priority, or
  verdict; it only rewords, and its output is schema- and ref-validated. The
  evidence snippets it receives are repo-derived and untrusted: treat them as
  data, not instructions. Injection cannot escalate a result because every
  result-determining field is deterministic.
- **Storage split.** SQLite holds the security-relevant graph projection and
  hypothesis records. The full CPG/IR is a content-addressed artifact, never
  mutable run state. The source tree is not stored.
- **Deterministic graph.** Node and edge `stableKey`/`id` are derived from
  content (repo path, symbol, line range, kind), not from backend-assigned or
  run-to-run ids. The same snapshot produces the same graph, hypotheses, ids, and
  order, so caching, the derived `repository-map.json`, and the "model on vs off,
  identical ids" gate hold. A `graphVersion` bump rebuilds old graphs rather than
  mixing schema versions.
- **Analysis budgets with graceful degradation.** The CPG build and bounded path
  search run under explicit time, memory, and graph-size budgets. On exceeding a
  budget, Deep Static degrades to `partial`/`degraded` coverage with a reason and
  still returns the Quick Scan Fix Pack; it never hangs, OOMs the run, or drops
  the whole scan.
- **Truthful wording.** Claims say "not observed on the analyzed path", never
  "absent" or "the app has no X" unless the graph proves that exact claim.
- **No fabricated facts.** Backend output comes only from the real backend binary
  or a test fake explicitly injected in tests. Product code never fabricates CPG,
  graph, flow, or hypothesis evidence to make a report look complete.

## The thread

```
vibeshield scan <github-url | local-git-root> --deep
  source.resolve              existing Stage 1 source acquisition
  snapshot.manifest           existing Stage 1 manifest over the scanned bytes
  inventory.detect            existing Stage 1 inventory
  scan.*                      existing Stage 1 Quick Scan checks
  findings.normalize          existing Evidence -> Finding contracts
  findings.correlate          existing Stage 1 clusters
  actions.rank                existing deterministic actions + verdict
  remediation.generate        existing Fix Pack wording, catalog fallback
  quick.graph-import          immutable Quick Scan findings -> graph nodes/edges
  program-analysis.model      Atom builds CPG/IR and stores the full artifact
  program-analysis.extract    entities, boundaries, calls, flows, component usage
  security-graph.compose      one SecurityGraph projection in SQLite
  graph.correlate             direct finding context + hypothesis candidates
  hypotheses.static-validate  supported / contradicted / inconclusive
  hypotheses.enrich           one bounded agent call, catalog fallback
  report.compose              one SecurityAssessment with deep sections
  report.render               report.json / .md / .html + short terminal receipt
```

Every new stage runs from the existing `StageRegistry` and records attempts and
artifacts in the existing SQLite + blob-store path. Deep Static adds graph tables
and artifacts; it does not create a second run identity.

## Implementation tasks

Grouped by gate. Each task is meant to be opened alone - In / Do / Out / Done.
Contracts referenced here are defined in "Contracts" below. A gate closes when
the owner runs the real command on a real repo and sees its result, with raw
proof that the real analysis backend or scanner produced the relevant facts.
Stage 2 is done when both stages and all four gates close.

### Stage 2A - Security Graph foundation

This stage proves the hard part first: a real static analysis backend can produce
an evidence-backed graph path that the product can use, not just a plausible
file full of inferred facts.

#### Gate 1 - one real static path from boundary to sink

Closes when: `vibeshield scan <real-repo-with-a-static-path> --deep` shows a
Deep Static section where an external boundary reaches a dangerous operation
through at least one cross-file call edge, with the CPG/IR raw artifact stored
and every displayed path step backed by graph evidence.

Status:

- [ ] **Gate 1 acceptance.** A live Microsandbox run on a real fixture or owner
  repo shows one boundary-to-sink path in `report.html` and `report.json`;
  `deep-coverage` reports boundary, call graph, and flow coverage; the raw
  Atom/CPG artifact is stored as a blob; no path step is created without a
  `SecurityGraphEdge` and evidence.
- [ ] **SecurityGraph contracts + storage.** In: Stage 1 domain contracts and
  SQLite store. Do: add `SecurityGraph`, `SecurityGraphNode`,
  `SecurityGraphEdge`, `SecurityFlow`, and `GraphCoverage` contracts; add SQLite
  tables for `nodes`, `edges`, `flows`, and `coverage`; validate ids, evidence
  refs, producer refs, path safety, and coverage states. Out: persisted graph
  projection and test fixtures. Done: a graph with a missing evidence id,
  outside-snapshot path, duplicate stable id, or dangling edge is rejected.
- [ ] **ProgramAnalysisBackend port + Atom adapter.** In: source dir inside
  Microsandbox and the manifest. Do: define `ProgramAnalysisBackend`
  (`buildModel`, `extractEntities`, `extractBoundaries`, `extractCallEdges`,
  `extractFlows`, `extractComponentUsage`, `reportCoverage`); implement the Atom
  adapter as a thin argv/parser wrapper; store the full CPG/IR as a CAS artifact.
  Out: raw backend artifact, normalized extraction artifacts, backend coverage.
  Done: a live run proves Atom ran in the sandbox, produced parseable output, and
  fails clearly instead of inventing entities when Atom is unavailable.
- [ ] **Code entities, boundaries, calls, and flows.** In: Atom extraction output
  plus manifest file hashes. Do: normalize functions, methods, modules,
  boundaries, sources, sinks, call edges, and cross-file flows into graph nodes
  and edges; record observed controls such as allowlists, auth guards, validators,
  and sanitizers when the backend or rule extractor can point to evidence. Out:
  graph projection with boundary, call, flow, source, sink, and control facts.
  Done: the owner can inspect one route -> handler -> helper -> sink path and one
  negative fixture where a missing edge keeps the path out of the report.
- [ ] **Deep coverage truth.** In: manifest, inventory, backend coverage, and
  parser outcomes. Do: compute coverage for boundaries, call graph, data flows,
  component usage, CI/IaC context, and unsupported languages; mark `checked`,
  `skipped`, `failed`, `degraded`, or `partial` with reasons. Out:
  `deepCoverage` in SQLite and the report export. Done: killing the backend marks
  Deep Static incomplete while preserving the Quick Scan Fix Pack.

#### Gate 2 - Quick Scan findings become graph context

Closes when: `vibeshield scan <real-repo-with-secret-dependency-ci-iac> --deep`
keeps the same Quick Scan findings and Fix Pack actions, imports every finding
into the Security Graph, and shows whether each finding is standalone,
corroborated, weakened, contradicted, or linked to a hypothesis.

Status:

- [ ] **Gate 2 acceptance.** A live fixture matrix shows Quick Scan findings in
  the normal Fix Pack and in the graph context; a secret remains a direct "Fix
  now" action; a dependency finding receives `present`, `imported`, `used`, or
  `reachable_from_boundary`; a CI or IaC finding contributes context without
  duplicating remediation actions.
- [ ] **Quick Scan graph import.** In: Stage 1 `Evidence`, `Finding`,
  `FindingCluster`, SBOM, dependency, GitHub Actions, and IaC outputs. Do:
  import `Finding`, `Secret`, `VulnerableComponent`, `CIWeakness`,
  `InfraWeakness`, `BuildStep`, and `Resource` nodes; connect them through
  `located_in`, `affects`, `uses`, `depends_on`, `exposes`, and `supported_by`
  edges. Out: graph nodes/edges for every Quick Scan finding. Done: every
  imported finding resolves back to the immutable Stage 1 finding id and evidence
  ids.
- [ ] **Component usage + dependency reachability.** In: SBOM, dependency scanner
  output, import/call graph facts, and optional affected-symbol data when present.
  Do: compute reachability levels `present`, `imported`, `used`,
  `reachable_from_boundary`, and `affected_symbol_reachable`; store unknown
  affected-symbol reachability as unknown, not as no. Out:
  `ComponentReachability` records and graph edges from code to components. Done:
  a dependency present only in the lockfile does not get boundary reachability,
  while an imported package used on a public path does.
- [ ] **CI/IaC context projection.** In: actionlint, zizmor, trivy config,
  workflow files, Dockerfiles, deployment manifests, and graph boundaries. Do:
  normalize CI triggers, build steps, action pins, token permissions, artifact
  writes, public ingress, and exposed resources into graph nodes and edges. Out:
  CI/IaC graph context linked to findings and boundaries. Done: an unpinned action
  on `pull_request` with write-capable token and artifact publication forms a
  traversable graph path.
- [ ] **Finding contextual assessment.** In: immutable findings plus graph facts.
  Do: compute `standalone`, `corroborated`, `weakened`, `contradicted`, and
  `linked_to_hypothesis`; keep original findings unchanged and write separate
  contextual records. Out: contextual assessment per finding. Done: a report can
  show "finding corroborated by reachable code path" without changing the
  finding's original severity or fingerprint.

### Stage 2B - Static hypotheses and owner-facing result

This stage turns the graph into testable hypotheses and a report section the
owner can act on. It still does not execute the application.

#### Gate 3 - deterministic hypotheses from graph evidence

Closes when: `vibeshield scan <real-repo-with-deep-fixtures> --deep` produces
static hypotheses for all five rule families, and a negative fixture proves that
missing or contradicted graph evidence yields `inconclusive` or
`statically_contradicted` instead of a high-confidence claim.

Status:

- [ ] **Gate 3 acceptance.** A live fixture matrix produces at least one
  hypothesis for external input to dangerous operation, SAST reachable path,
  dependency usage path, CI supply-chain path, and secret impact chain; every
  hypothesis cites bounded graph paths and coverage; a control or missing edge
  fixture blocks promotion.
- [ ] **Correlation rule engine.** In: `SecurityGraph`, contextual findings,
  coverage, and rule definitions. Do: implement deterministic rule evaluation
  with bounded path search, rule-specific required edge types, required node
  kinds, observed controls, contradiction checks, and max path length. Out:
  `HypothesisCandidate`s with supporting and contradicting graph refs. Done: the
  same graph produces stable candidates in stable order without any model call.
- [ ] **Five rule families.** In: rule engine and graph facts. Do: implement:
  external input -> dangerous operation; Quick SAST finding -> reachable path;
  vulnerable component -> imported/used/reachable path; untrusted CI trigger ->
  mutable build dependency -> privileged credential -> artifact or repository
  write; secret finding -> configuration reference -> privileged integration ->
  exposed service or build job. Out: candidate hypotheses for each family. Done:
  each rule has a positive and negative fixture that fails if evidence is guessed.
- [ ] **Static hypothesis validator.** In: candidates, graph paths, observed
  controls, contradictions, and coverage. Do: assign `candidate`,
  `statically_supported`, `statically_contradicted`, or `inconclusive`; compute
  static confidence from evidence strength and coverage, not from model wording.
  Out: validated `StaticHypothesis` records. Done: wording says "destination
  allowlist was not observed on the analyzed path", never "the app has no
  allowlist" unless the graph proves that exact claim.
- [ ] **Validation recipes.** In: validated hypotheses, boundaries, required
  principals/resources, and observed test factories/seeds/auth fixtures when
  present. Do: write structured future runtime validation recipes with required
  fixtures, steps, expected result, and safety notes. Out: `ValidationRecipe`
  records linked to hypotheses. Done: a BOLA-like candidate can describe
  principal A/B and resource ownership requirements without claiming runtime
  confirmation.

#### Gate 4 - enriched report and usable `--deep` UX

Closes when: the owner runs `vibeshield scan <real-repo> --deep` and sees the
same prioritized Fix Pack plus a concise "Likely attack paths" section with
static confidence, runtime validation requirement, deep coverage, remediation,
coding-agent prompt, and validation recipe; turning the model off keeps the same
findings, hypotheses, priorities, and verdict.

Status:

- [ ] **Gate 4 acceptance.** A live run with the model on and off keeps identical
  finding ids, hypothesis ids, static statuses, action candidates, priorities,
  and verdict; the model only improves explanation, remediation wording, prompts,
  and recipes; invalid model output falls back to deterministic templates.
- [ ] **hypotheses.enrich.** In: top bounded `StaticHypothesis` records, graph
  paths, Quick Scan findings, evidence snippets, observed controls, coverage
  gaps, and catalog entries. Do: make one bounded model call through the existing
  model-provider port; validate ids, graph refs, paths, and schema; fall back to
  deterministic templates on missing key, timeout, invalid JSON, or semantic
  failure. Out: enriched attack description, assumptions, impact, remediation,
  coding-agent prompt, acceptance criteria, and validation recipe text. Done: the
  model cannot introduce a new path, finding, status, priority, or verdict.
- [ ] **Action grouping.** In: direct findings, contextual assessments,
  hypotheses, and remediation keys. Do: group direct findings and linked
  hypotheses into one owner-facing remediation action when they describe the same
  work; preserve separate machine-readable ids. Out: report action groups without
  duplicate owner work. Done: a secret action can include impact context while
  still leading with "rotate the key".
- [ ] **Report contracts and renderers.** In: `SecurityAssessment`,
  `StaticHypothesis`, `FindingContextAssessment`, `DeepCoverage`, and enriched
  text. Do: extend `report.json`, Markdown, and HTML with Fix now, Likely attack
  paths, Deep analysis coverage, Quick finding context statuses, and validation
  recipes. Out: `report.json`, `report.md`, and `report.html` with deep sections.
  Done: the terminal stays short, while HTML/Markdown show paths and recipes
  without requiring the owner to understand graph tables.
- [ ] **CLI flag and degradation.** In: existing scan command and stage registry.
  Do: add `--deep`; when Deep Static fails, keep completed Quick Scan results,
  mark Deep Static coverage failed or degraded, and never present a backend error
  as a supported hypothesis. Out: usable CLI and truthful failure behavior. Done:
  the owner can run Quick Scan normally, opt into Deep Static, and see useful
  partial output when the deep backend fails.
- [ ] **repository-map.json derived view.** In: `SecurityGraph` and coverage. Do:
  render a compact human-oriented map view from graph facts only; include
  boundaries, key code entities, integrations, data stores, CI/IaC resources,
  coverage, and fact gaps. Out: `repository-map.json` as a derived artifact.
  Done: deleting the derived file and re-rendering it from SQLite produces the
  same view for the same run.

## Contracts

Minimal on purpose - enough to keep graph facts, hypotheses, and reports
coherent.

- **SecurityGraph**: `id`, `runId`, `snapshotId`, `graphVersion`, `nodes`,
  `edges`, `flows`, `coverage`, `createdAt`.
- **SecurityGraphNode**: `id`, `kind`, `stableKey`, `label`, `repoPath?`,
  `lineRange?`, `symbol?`, `properties`, `evidenceIds`, `producer`,
  `producerVersion`, `confidence`, `coverageState`.
- **Node kinds**: `Boundary`, `CodeEntity`, `Source`, `Sink`, `Control`,
  `Flow`, `Component`, `Finding`, `Secret`, `BuildStep`, `InfraResource`,
  `ExternalService`, `DataStore`, `Resource`.
- **SecurityGraphEdge**: `id`, `kind`, `fromNodeId`, `toNodeId`, `properties`,
  `evidenceIds`, `producer`, `producerVersion`, `confidence`, `coverageState`.
- **Edge kinds**: `contains`, `imports`, `calls`, `registers`, `receives`,
  `flows_to`, `uses`, `reads`, `writes`, `protected_by`, `exposes`,
  `depends_on`, `located_in`, `affects`, `supported_by`, `contradicted_by`.
- **SecurityFlow**: `id`, `sourceNodeId`, `sinkNodeId`, `pathEdgeIds`,
  `controlNodeIds`, `coverageState`, `confidence`, `evidenceIds`.
- **GraphCoverage**: `area` (`boundaries`, `call_graph`, `data_flow`,
  `dependency_usage`, `ci_iac`, `language_support`), `state`, `coveredCount?`,
  `totalCount?`, `reason?`, `producer`, `producerVersion`.
- **ProgramAnalysisBackend**: `buildModel(sourceDir, manifest)`,
  `extractEntities(modelRef)`, `extractBoundaries(modelRef)`,
  `extractCallEdges(modelRef)`, `extractFlows(modelRef)`,
  `extractComponentUsage(modelRef)`, `reportCoverage(modelRef)`.
- **Boundary**: `id`, `boundaryType`, `routeOrName`, `method?`, `handlerNodeId?`,
  `sourceNodeIds`, `evidenceIds`, `coverageState`.
- **ComponentReachability**: `componentId`, `packageName`, `version?`,
  `findingIds`, `level` (`present`, `imported`, `used`,
  `reachable_from_boundary`, `affected_symbol_reachable`), `pathEdgeIds`,
  `affectedSymbol?`, `evidenceIds`, `coverageState`.
- **FindingContextAssessment**: `findingId`, `status` (`standalone`,
  `corroborated`, `weakened`, `contradicted`, `linked_to_hypothesis`),
  `graphNodeIds`, `graphEdgeIds`, `hypothesisIds`, `reason`, `coverageState`.
- **HypothesisCandidate**: `id`, `ruleId`, `family`, `title`, `findingIds`,
  `supportingNodeIds`, `supportingEdgeIds`, `contradictingNodeIds`,
  `contradictingEdgeIds`, `coverageRefs`, `requiredValidation`, `candidateReason`.
- **StaticHypothesis**: `id`, `candidateId`, `status`,
  `staticConfidence`, `title`, `pathSummary`, `supportingEvidenceIds`,
  `contradictingEvidenceIds`, `coverageState`, `runtimeValidationRequired`.
- **ValidationRecipe**: `id`, `hypothesisId`, `requiredFixtures`, `steps`,
  `expectedResult`, `safetyNotes`, `materializationHints`, `knownGaps`.
- **DeepSecurityAssessment extension**: `deepCoverage`,
  `findingContextAssessments`, `staticHypotheses`, `validationRecipes`,
  `repositoryMapArtifactRef?`, `limitations`.
- **Verdict and ranking**: Quick Scan verdict and blocking direct findings remain
  rule-computed before model enrichment. Static hypotheses can increase action
  priority only through deterministic rule outputs and recorded graph evidence.
- **hypotheses.enrich**: one bounded model call over OpenRouter through the
  existing model-provider port; input is bounded hypotheses, graph paths, evidence
  snippets, controls, coverage gaps, and catalog entries; output is validated
  structured JSON. Invalid output falls back to deterministic templates.
- **Semantic validators**: graph refs resolve; evidence ids resolve; paths stay
  inside the snapshot; line ranges are valid; graph paths contain real connected
  edges; every hypothesis references a rule id; every supported hypothesis has at
  least one bounded path or CI/IaC chain; contradictions are displayed when they
  determine status.
- **Storage**: SQLite stores graph projection and hypothesis records. Blob store
  stores raw Atom/CPG artifact, redacted backend logs, repository-map derived
  view, and rendered reports. The source tree itself is still not stored.

## Out of scope

Not in Stage 2 (tracked in the roadmap, not here): resume; framework-specific
authorization and ORM/data-access packs; runtime validation that materializes
validation recipes and uses the `confirmed` status; a second backend (Joern)
behind `ProgramAnalysisBackend`; richer affected-symbol reachability from
advisory databases; framework query packs; offline/no-egress isolation and SaaS
storage hardening; PDF report, private repos, zip upload, GitHub App, web UI, and
continuous monitoring.

## Open

- Which real repo or fixture proves Gate 1 with a boundary -> cross-file call ->
  dangerous sink path.
- Exact Atom command, version pin, output format, and raw artifact shape to store
  as CAS proof.
- Which fixture proves all five deterministic rule families without turning the
  test suite into a fake scanner.
- How much of `repository-map.json` should be owner-visible versus kept as a
  debugging artifact.
- Model context and budget cap for `hypotheses.enrich`.
- Whether `--deep` should be hidden behind an experimental label in CLI help for
  the first owner runs.
- CPG build and path-search budget caps (time, memory, node and edge count) and
  the repo size beyond which Deep Static degrades instead of running.
- How much cross-file flow quality is lost by building the CPG without installing
  dependencies, and whether that is acceptable for JS/TS and Python in v1.
