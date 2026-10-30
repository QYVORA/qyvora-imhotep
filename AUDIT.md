# qyvora-imhotep — Capability and Domain Audit

**Status:** `AUDIT COMPLETE` · **Audit date:** 2026-10-21 · **Mode:** audit only, no implementation
**Governing prompt:** `products/QYVORA-AI/PROMPT.md` (§13 Deliverable A; §5 is *not applicable* to this domain — see §5 below)

---

## 1. Framework identity and intended domain

| Field | Value | Evidence |
|---|---|---|
| Name | `imhotep` | `internal/version`, `bin/imhotep version -o json` |
| Module | `github.com/QYVORA/qyvora-imhotep` | `go.mod:1` |
| Go directive | `go 1.26.5` | `go.mod:3` |
| Version / commit | `v0.1.0` / `e6f9dbc` | `bin/imhotep version -o json` |
| Build | `go1.27.1`, linux/amd64, `2026-10-21T01:21:55Z` | same |
| Domain | **Offline cloud security posture analysis**: IAM, storage, network, containers, secrets and misconfiguration risk from snapshot files and deterministic simulations | `internal/cli/cli.go:179`, `internal/capabilities/capabilities.go:80-89` |
| Safety boundary | Live cloud-provider collection is **deliberately not implemented and refused honestly** | `internal/safety/safety.go:53-67`, `internal/cli/cli.go:594-604` |

Imhotep is one of the 14 QYVORA frameworks. It implements the shared contract natively (no `shared/qyvora-common` import; see §10).

## 2. Audit scope and evidence sources

**Evidence actually consulted**

- Source tree: `cmd/`, `internal/` (28 packages: `analysis`, `banner`, `capabilities`, `cli`, `cloud`, `config`, `containers`, `discovery`, `errors`, `events`, `evidence`, `exitcode`, `iam`, `misconfig`, `network`, `output`, `pipeline`, `reporting`, `risk`, `rules`, `rules/builtin`, `safety`, `secrets`, `selfupdate`, `storage`, `target`, `validation`, `version`), `pkg/models`.
- Documentation: `README.md` (5 580 B), `docs/README.md` (documentation index), plus the zero-byte inventory in §12; `.github/workflows`, `.goreleaser.yaml`, `Makefile`, `SECURITY.md`, `LICENSE`, `NOTICE`.
- Pre-captured help: `docs/audit/help/imhotep.txt`.
- Contracts: `shared/qyvora-common/contract/contract.go`, `shared/qyvora-common/conformance/runner.go`, `knowledge/.../QYVORA-TOOL-OUTPUT-SPEC.md`.
- Live binary probes (offline only — simulation/snapshot analysis, never a provider endpoint) and `go test` / `go vet`, recorded in §13.

**Not done (by constraint):** no cloud provider API was contacted (the tool refuses this by design and was never pointed at credentials); no device, network or Bluetooth target was touched.

## 3. Existing capability inventory

**CLI (tier grammar)** — verified with `--help`:

- `recon` — `assess`, `snapshot`, `providers`, `rules`, `target`
- `exploit` — exists but is empty by design: `exploit has no modules in this framework (assessment is offline and read-only)` → **exit 2**
- `report` — default re-renders latest result; sub-commands `findings`, `evidence`
- flat — `version`, `capabilities`, `updates`, `completion`, `script`
- hidden backward-compatible aliases for the pre-tier paths (`assess`, `snapshot`, `providers`, `rules`, `target`, `findings`, `evidence`) — `internal/cli/cli.go:281-296`
- global flags: `-o/--output` (terminal|json|yaml|markdown|html), `--no-color`, `-q`, `--events` (stdout|stderr|off|file), `--allow-shellout`

**Targets** (`internal/cli/cli.go:565-592`, `internal/target/manager.go`): `snapshot` file, built-in `simulation`, `provider` (declared then refused). State persists to `~/.config/qyvora/imhotep/targets.json`.

**Safety model** (`internal/safety/safety.go`): every operation carries class, risk, noise level, `auth_required`, `confirm`, `changes_state`, `reversible`. `imhotep.live.provider` is `Implemented() == false` and every call path derives an honest refusal (`cli.go:594-604`) instead of faking capability.

**Preflight validation** (`internal/validation/validation.go:29-73`): checks `target.present`, `snapshot.exists` / `snapshot.provided`, and for provider targets emits `live.implemented = false` with `Ready=false` → assess refuses with exit 2.

**Pipeline** (`internal/pipeline/pipeline.go:68-90` + `internal/analysis/analyst.go`): `provider → discovery → inventory → analysis → risk`, with stage lifecycle events, first-error abort, and a per-run cache (`Step.Cached`) so stages/rules do not re-read the same snapshot.

**Inputs** (`internal/cloud/`): `snapshot.go` (248 lines) parses offline provider snapshots; `simulate.go` (115 lines) emits a deterministic built-in dataset (AWS-shaped `acme-000000000000` scope).

**Rules — 14 registered** (`internal/rules/builtin/builtin.go:23-41`, `metadata(...)` at lines 80-392):

| Domain | IDs |
|---|---|
| IAM | `IAM-001` wildcard action, `IAM-002` wildcard resource scope |
| Storage | `STG-001` public read, `STG-002` public write, `STG-003` unencrypted at rest |
| Network | `NET-001` admin port internet-exposed, `NET-002` public database, `NET-003` public compute |
| Data | `DBE-001` unencrypted database at rest |
| Containers | `CNT-001` privileged, `CNT-002` host network, `CNT-003` mutable image tag, `CNT-004` runs as root |
| Secrets | `SEC-001` hardcoded secret material |

**Evidence & redaction**: `evidence.json` per run (`cli.go:475,514`); secrets are redacted on a **deep copy at the render surface** and again in the persisted `result.json` (`cli.go:521-522`, `898-912`), so reports are redacted while the canonical run stays intact.

**Reporting**: five formats (terminal/JSON/YAML/Markdown/HTML) written via `internal/reporting`; latest result persisted as `report.dir/result.json` (`cli.go:912`).

**Operational**: JSONL event stream (§2 envelope, default `stderr`), viper config (`QYVORA_` prefix, `internal/config/config.go:47-63`), profiles `quick|standard|deep`, `.qs` script engine gated by `--allow-shellout` / `QYVORA_ALLOW_SHELLOUT` (`internal/cli/script.go:31-34`), `updates`, self-update, `capabilities` document.

**Retired**: per-tool TUI/REPL is `//go:build ignore` (`internal/cli/tui.go:1`) — bare `imhotep` prints help and exits 0.

## 4. Capability status matrix

| # | Capability | Status | Evidence |
|---|---|---|---|
| 1 | Offline cloud snapshot analysis | IMPLEMENTED | E2E run: 12 assets, 15 findings, score 100 |
| 2 | Deterministic simulation dataset | IMPLEMENTED | `cloud/simulate.go`; `--sim` run |
| 3 | IAM policy parsing + rules | IMPLEMENTED (2 rules) | `iam/policy.go`, `builtin.go:80-110` |
| 4 | Storage exposure rules | IMPLEMENTED (3) | `storage/storage.go`, `builtin.go:138-186` |
| 5 | Network configuration rules | IMPLEMENTED (3) | `network/network.go`, `builtin.go:212-267` |
| 6 | Container/K8s rules | IMPLEMENTED (4) | `containers/manifest.go`, `builtin.go:317-359` |
| 7 | Secret exposure detection + redaction | IMPLEMENTED | `secrets/scan.go`, `RedactSecretData` |
| 8 | Misconfiguration overview rules | IMPLEMENTED (`DBE-001`) | `misconfig/overview.go` |
| 9 | Risk scoring (score + level) | IMPLEMENTED | observed `score 100`, `level critical` |
| 10 | Evidence store + report artifacts | IMPLEMENTED | `evidence.json`, `result.json`, `reporting.Write` |
| 11 | Machine-readable `capabilities` contract | IMPLEMENTED (rich) but **schema diverges** from `contract.CapabilityManifest` | §10 |
| 12 | Exit-code contract 0/1/2/130 | IMPLEMENTED | `internal/exitcode`; probes §13 |
| 13 | Exit code 3 (`ExitUnsupported`) | **MISSING** | `internal/exitcode` declares only 0/1/2/130; `capabilities.exit_codes` omits it |
| 14 | Honest refusal of live collection | IMPLEMENTED | `refuseLive` → exit 2, `safety.Implemented()` |
| 15 | Live provider API collection (AWS/Azure/GCP) | **MISSING** (declared `Implemented: false`) | `capabilities.go:88-89` |
| 16 | Interactive console / TUI | NOT APPLICABLE (retired fleet-wide) | `//go:build ignore`; bare → help |
| 17 | `exploit` tier modules | NOT APPLICABLE (offline read-only domain; empty tier exits 2 with explanation) | `cli.go:287-291` |
| 18 | Android/device assessment | NOT APPLICABLE — different framework's domain (§5) | — |
| 19 | `--no-report` fully suppressing artifacts | PARTIALLY IMPLEMENTED | skips `reporting.Write` (`cli.go:534`) but `evidence.json` + `result.json` still written (`475,514,533`) |
| 20 | Shell-out in scripts | IMPLEMENTED but **disabled by default** (safe default) | `script.go:31-34`, `--allow-shellout` |

## 5. Reconnaissance and discovery findings

**Android/domain applicability (PROMPT §5): `NOT APPLICABLE (justified)`.** Imhotep's target types are `snapshot`, `simulation` and `provider` (`internal/validation/validation.go:42-71`); there is no USB/ADB/Bluetooth/APK/wireless code path and no device concept in `pkg/models` beyond the generic `Target`. Applying the Android technique matrix to this framework would be a category error. Android assessment is `qyvora-jabari`'s domain (audited in `frameworks/qyvora-jabari/AUDIT.md`).

**Cloud-domain reconnaissance findings:**

- Discovery is **asset extraction from an input file**, not network discovery: the `discovery` stage enumerates parsed snapshot assets and emits `asset.discovered` events, capped by `analysis.max_assets` (default 10 000, `config.go:66`).
- Provider detection (`provider` stage) reads provider identity/scope/region from the snapshot header — no API call, no credential use.
- Provider targets are refused *before* any collection attempt: preflight `live.implemented=false` → `Ready=false` → exit 2 (`validation.go:59-67`, `cli.go:454-458`).
- No scanning, no host/network probing of any kind exists in this framework (`rg Dial|net\.Dial` finds no connection code in the analysis path).

## 6. Analysis and assessment findings

- `analysis.Stages(reg, flags, maxAssets)` wires `provider → discovery → inventory → analysis → risk` (`internal/analysis/analyst.go`), with the shared `Step` cache preventing repeated snapshot parses.
- Rule execution is registry-driven with duplicate-ID atomic rejection (`internal/rules/registry.go`, `registry_test.go:130-140`) and profile/ severity filtering (`rules.go:200-280`).
- **Redaction discipline is a genuine strength**: deep-copy redaction at render and persist (`cli.go:521-522`, `902-906`) keeps raw secret evidence out of reports without corrupting run state.
- Output is the spec-documented "shared shape" (`QYVORA-TOOL-OUTPUT-SPEC.md` §6: `id, framework, target, level, profile, score, started_at, completed_at, sim, events, evidence, findings, assets` + `summary`) — verified byte-level in §13.
- Profiles gate severity reporting (`severityAllows`, `rules.go:280`); `config.MaxAssets` bounds work.

## 7. Exploitation-related capability findings

- **Not applicable by design and honestly declared.** `exploit` is registered so the tier is discoverable, and its `RunE` returns exit 2 with an explicit explanation rather than a blank help page (`internal/cli/cli.go:287-291`) — verified at runtime.
- The safety registry reserves `OpLiveProvider` with `AuthRequired: true, Confirm: true` (`safety.go:53-59`) but marks it not implemented, so the highest-risk operation can never execute.
- No state-changing operation exists: every implemented operation is `ChangesState=false, Reversible=true, Risk S1, NoiseLevel passive` (`safety.go:40-52`).
- No PoC/exploit-validation module, no credential use, no write path to cloud resources.

## 8. High-level implementation candidates

| # | Candidate | Why it matters | Prerequisites | Priority |
|---|---|---|---|---|
| H1 | **Live provider collection** (read-only describe/list APIs, explicit opt-in) | the framework's declared gap: `cloud.live Implemented:false`; today users must bring their own export | provider SDKs, credential handling, confirmation/safety wiring | **P1** (domain-defining) |
| H2 | **Fix documentation debt** (populate or remove 31 zero-byte files; correct `docs/README.md` index; fix README quickstart) | docs are the orchestrator's and user's source of truth (§12) | none | **P1** |
| H3 | **Snapshot format coverage** (Terraform state, CloudFormation export, SCP/organization exports, Kubernetes manifests as first-class inputs) | widens the offline input surface without any live access | parser work only | **P2** |
| H4 | **Emit `contract.CapabilityManifest`** from `capabilities` + declare exit code 3 | removes an orchestration inconsistency (§10) | contract alignment | **P2** |
| H5 | **Rule-pack coverage** (public exposure via load balancer/CDN, encryption-at-rest gaps in more services, IAM condition analysis, CI/CD key hygiene) | more findings per snapshot at zero operational risk | snapshot schema coverage | **P2** |
| H6 | **`--no-report` semantics**: either suppress `result.json`/`evidence.json` too, or document that only the formatted report is skipped | honesty of a documented flag | small CLI change | **P3** |
| H7 | **Positional-argument handling for `assess`** (reject unknown args instead of silently using the persisted current target) | see §12 sharp edge | `Args:` validator | **P2** |

## 9. Low-level deferred technique inventory

**Low-level techniques relevant to Imhotep's cloud domain.**

| Technique | Objective | Required hardware / access / environment | Feasibility here | Status | Reason deferred / conditions to revisit |
|---|---|---|---|---|---|
| Cloud control-plane access requiring production credentials (live API enumeration beyond read-only) | Real-time posture of live estates | production/cloud credentials, approval workflow, audit trail, rate-limit handling | Not feasible in this phase (and refused by the tool) | **DEFERRED — SPECIALISED PREREQUISITES** | needs org-approved credential custody + safety review; revisit with H1 |
| Hosted-account/organization-level discovery (cross-account enumeration, org tree walking) | Blast-radius mapping | organization administrative privileges, multi-account trust relationships | Not feasible | **DEFERRED — SPECIALISED PREREQUISITES** | exceptional privileges; scope agreements |
| Compromise-validation against live cloud resources (e.g. controlled proof of an exposure) | Confirm exploitability | production-side change approvals, blast-radius control, rollback | Not feasible | **DEFERRED — SPECIALISED PREREQUISITES** | state-changing by nature; requires explicit authorization regime |
| Firmware/hardware and Android-specific techniques (JTAG, UART, chip-off, RF/SDR, baseband, Bluetooth, ADB) | Device-layer assessment | as enumerated in `frameworks/qyvora-jabari/AUDIT.md` §9 | Not applicable to this framework's domain | **DEFERRED — SPECIALISED PREREQUISITES** (and domain-owned by Jabari) | would be misassigned here; tracked in the Jabari audit |

No Android technique (PROMPT §5) is implemented, or implementable, in this framework; this is recorded as *deferred + out of domain*, never as "irrelevant".

## 10. Common-layer conformance

| Dimension | Status | Evidence |
|---|---|---|
| Identity/version metadata (full §4 set) | **SHARED** | `version -o json` matches the spec (note: `v0.1.0` carries a `v` prefix, unlike `jabari`'s `0.1.0`) |
| Exit codes 0/1/2 | **SHARED** | verified: bad flag → 2, bad command → 2, empty report state → 1, success → 0 |
| Exit code 130 | **SHARED** | `internal/exitcode.Interrupted`; SIGINT via `signal.NotifyContext` |
| Exit code 3 | **MISSING** | `internal/exitcode` has no `Unsupported`; live refusal is reported as **usage (2)** (`cli.go:598`) |
| JSONL event envelope §2 | **SHARED** | `schema_version 1.0`, `timestamp`, `execution_id`, `framework`, `level`, `event`, `data` captured |
| Severity/confidence vocabularies | **SHARED** | `capabilities.json` declares both sets |
| Report JSON shape | **SHARED** (spec §6 "amanirenas, sundiata, timbuktu, kush, imhotep (shared shape)") | verified keys on a real run |
| Capability manifest shape | **INCONSISTENT** | richer than `contract.CapabilityManifest` in metadata (exit codes, formats, verbs, auth model) but its `commands[]` carry `{name, summary, output_modes, sim_support}` instead of the contract's `{inputs, outputs, dangerous, authorization, emits, deterministic}` |
| `capabilities.exit_codes` completeness | **MISSING** (`unsupported: 3`) | `capabilities.go:60-62` |
| Script engine + `--allow-shellout` gate | **SHARED / DUPLICATED** | same flag/env name as Jabari |
| Self-update | **DUPLICATED** (own `internal/selfupdate`) | both repos |
| Safety-operation registry (risk/auth/confirm metadata) | **FRAMEWORK-SPECIFIC** — Imhotep only; a strong pattern other frameworks could adopt | `internal/safety/safety.go` |
| Conformance runner checks | **SHARED** | ran against this binary — §13 |
| Retired TUI/session linkage | **SHARED** | source `//go:build ignore`; binary check UNVERIFIED (stripped) |

**Conformance verdict: PARTIALLY CONFORMANT.** Identity, exit codes (0/1/2/130), events, vocabularies and report shape all conform and were executed; capability-manifest schema diverges from the shared contract and exit code 3 is undeclared/unimplemented.

## 11. AI orchestration readiness

| Requirement | Status | Evidence |
|---|---|---|
| Stable framework identity | CONFORMANT | `version -o json` |
| Version/compatibility metadata | CONFORMANT | full build block |
| Machine-readable capability discovery | PARTIALLY CONFORMANT | `capabilities -o json` declares capabilities, commands, formats, verbs, auth model, exit codes — but not the shared per-command contract fields |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | flags are documented in help; `assess` takes no positional args but silently ignores them (§12) |
| Predictable exit codes/errors | PARTIALLY CONFORMANT | 0/1/2 verified; 3 absent; refusal reported as usage 2 |
| Structured results & evidence | CONFORMANT | spec §6 shared shape; `result.json` + `evidence.json` |
| Prerequisite declarations | CONFORMANT | preflight `Plan{Checks, Ready}` is machine-readable; snapshot existence checked before work |
| Permission/authorization requirements | CONFORMANT | offline ops declared `AuthRequired:false`; live op declared required but unimplemented (`capabilities.authorization_model`) |
| Timeouts & cancellation | CONFORMANT | context-driven; interrupt → 130 |
| Safe execution defaults | **CONFORMANT (exemplary)** | read-only, offline, no shell-out by default, secrets redacted, live contact refused |
| Read-only vs state-changing distinction | CONFORMANT | `OperationMetadata.ChangesState/Reversible/Confirm` |
| Risk classification of operations | CONFORMANT | `RiskS1/S2` + `NoiseLevel` per operation |
| Log/result correlation | CONFORMANT | `execution_id` shared by events and result |
| Honest unsupported reporting | CONFORMANT | `Implemented:false`, `live.implemented` preflight failure, `exploit` tier explanation |
| Conformance-runner green | PARTIALLY CONFORMANT | 5/6 pass; `tui-retired` UNVERIFIED (stripped binary) |

**Recommended future architecture (proposal only):** have `capabilities -o json` emit `contract.CapabilityManifest` as its `commands` array (adding `inputs`, `outputs`, `dangerous`, `authorization`, `emits`, `deterministic`), add `unsupported: 3` to `exit_codes`, and register an exit-3 path for "understood but unimplemented" requests so an orchestrator can skip rather than retry.

## 12. CLI, repository-layout, and documentation findings

**CLI** — clean and verified: tier grammar with discoverable empty `exploit` tier; hidden pre-grammar aliases keep old invocations working; unknown flag/command → 2; invalid `-o xml` → 2; empty report state → 1 with a clear message; bare invocation → help, exit 0.

**One behavioural sharp edge (P2):** `assess` declares no `Args:` validator (only `ExactArgs(2)` exists at an unrelated call site, `cli.go:629`). Consequence, verified: `imhotep assess snapshot.sim.json` (a command **documented in `README.md:60`**) silently ignores the positional argument and evaluates the *persisted current target* instead — during this audit it resolved to a stale snapshot target from a previous session in `~/.config/qyvora/imhotep/targets.json` and failed with `snapshot file not found: /tmp/opencode/rep/snap.json` (exit 2). An orchestrator could assess the wrong asset.

**Layout** — modular and tidy; `bin/` gitignored; tracked root files `LICENSE` (MIT, 1 070 B), `NOTICE`, `SECURITY.md` are populated.

**Documentation problems (P1)**

1. **31 zero-byte placeholder files** tracked in git: root `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SUPPORT.md`; `configs/config.example.yaml`; `examples/basic.json`, `examples/basic.yaml`; **all four** `scripts/{build,install,release,test}.sh`; and 19 `docs/*.md` (`Architecture`, `Cloud-Providers`, `Configuration`, `Console`, `Container-Security`, `Development`, `Evidence`, `Getting-Started`, `IAM`, `Installation`, `Misconfigurations`, `Network-Security`, `Reporting`, `Roadmap`, `Secrets`, `Security-Model`, `Storage`, `Targets`, `Validation`). `docs/CLI.md` (1 078 B) and `docs/README.md` (2 304 B) are populated.
2. **`docs/README.md` is itself stale**: it states "26 Markdown files … zero-byte placeholders" and lists `LICENSE`, `NOTICE`, `SECURITY.md` and `docs/CLI.md` as placeholders — all four are now non-empty, while the true count is **31** (including config/examples/scripts files it does not list).
3. **`README.md` quickstart is wrong**: `imhotep snapshot --sim` → **exit 2, `unknown flag: --sim`** (the command takes only `--out`); `imhotep assess snapshot.sim.json` → silent-argument bug above; and the "Interactive console (REPL)" block documents a retired interface (bare `imhotep` prints help).
4. `README.md:53`'s claim `imhotep assess --sim  # risk 100/100 (critical)` **is correct** (verified: score 100, level critical).

**Repository hygiene** — clean; `git status` unchanged before/after the audit (no tracked or untracked additions; `bin/` ignored).

## 13. Testing and verification findings

**Commands actually executed (all non-destructive and offline):**

| Check | Result |
|---|---|
| `go vet ./...` | **exit 0**, no findings |
| `go test ./... -count=1 -timeout 180s` | **PASS** — **21 packages `ok`, 9 with no test files, 0 failures** (measured twice) |
| `bin/imhotep version -o json` | exit 0, `v0.1.0` + full §4 metadata |
| `bin/imhotep capabilities -o json` | exit 0 (exit-code/format/verb/severity/confidence/capability/command document) |
| `bin/imhotep --badflag` / `bogus-command` | **exit 2 / exit 2** |
| `bin/imhotep recon assess --sim -o json` (artifacts redirected to `/tmp`) | **exit 0**; 12 assets, **15 findings**, `score 100`, `level critical`; JSONL events on stderr conform to §2; report written to `--report-dir` |
| `assess -o {terminal,json,yaml,markdown,html}` | **exit 0 each** (0 / 25 208 / 22 126 / 22 137 / 34 173 B; terminal+`-q` intentionally emits nothing) |
| `assess -o xml` | **exit 2** |
| `report` / `findings` / `evidence` with no prior state | **exit 1** each — `loading report state: open reports/result.json: no such file or directory` |
| `exploit` | **exit 2** — honest "no modules in this framework" message |
| `recon providers -o json` | exit 0 — 3 providers, `live: true, implemented: false, note: snapshot only` |
| `recon rules -o json` | exit 0 — rule metadata incl. severity/confidence/recommendation |
| `snapshot --sim` | **exit 2 — `unknown flag: --sim`** (README documents this exact command) |
| `assess snapshot.sim.json` (README-documented form) | **exit 2** — positional arg ignored; stale persisted target used (§12) |
| bare `imhotep </dev/null` | exit 0, prints banner + help (no REPL) |
| Shared conformance runner (`qyvora-conformance -bin …`) | **5/6 checks PASS**: `version-semver`, `version-exit0`, `usage-exit-2`, `unknown-cmd-exit-2`, `capabilities`; **`tui-retired` = UNVERIFIED** — *stripped ELF* ("no symbol section"), not a detected violation; source confirms `internal/cli/tui.go:1 //go:build ignore` |

**Cross-checks against historical/ecosystem claims**

- Ecosystem claim "14/14 frameworks conformant (2026-10-19)" holds for the behavioural contract measured here (5/6 runner checks, with the sixth unverifiable on stripped binaries) but should not be read as schema conformance of `capabilities` to `contract.CapabilityManifest` (§10).
- Output-spec §6 grouping of Imhotep into the shared report shape: **confirmed** by execution.
- Interactive console/REPL retirement: **confirmed** in this repo (`//go:build ignore`, bare → help) — although `README.md` still advertises it (§12).

**Coverage gaps**

- No test files in `capabilities`, `discovery`, `errors`, `exitcode`, `reporting`, `rules/builtin`, `safety`, `version`, `cmd/imhotep` — notably **`rules/builtin` (the 14 shipped rules) and `safety` (the refusal contract) are untested at package level**, though `analysis` tests exercise rules end-to-end (`analysis_test.go` registers `builtin.All()`).
- No integration test asserts the *refusal* path (provider target → exit 2) or the `--no-report` semantics.
- No fixture covers a real third-party snapshot export (only the built-in simulation and unit-level sample documents).

**Effect on the working tree:** `git status` identical before and after; no tracked file, dependency, lockfile or config changed; no writes to `~/.config/qyvora/` (state file mtime unchanged); all generated artifacts were redirected to `/tmp/opencode`.

## 14. Prioritized gaps and recommendations

**P0 — Critical:** none found. No unsafe default, no secret leak path, no state-changing operation reachable by accident.

| ID | Priority | Gap | Evidence | Recommended action (future phase) |
|---|---|---|---|---|
| G1 | **P1** | Live cloud collection unimplemented (honestly refused) — the framework cannot assess a *live* estate | `capabilities.go:88-89`, `safety.go:53-67` | H1: read-only describe/list collection behind the existing safety/confirm machinery |
| G2 | **P1** | 31 zero-byte tracked files + stale documentation index + wrong README quickstart | §12 items 1-3 | Populate or delete placeholders; correct `docs/README.md`; fix quickstart commands |
| G3 | **P2** | `assess` silently ignores positional args and can assess a stale persisted target | verified exit 2 on README's own example | Add an `Args:` validator (reject unexpected args) |
| G4 | **P2** | `capabilities` does not emit `contract.CapabilityManifest`; `exit_codes` omits 3; exit 3 unimplemented | §10 | Align schema; report "understood but unsupported" as 3 |
| G5 | **P2** | `rules/builtin` and `safety` have no package-level tests | §13 | Unit-test the refusal path and each rule's positive/negative case |
| G6 | **P3** | `--no-report` still writes `result.json`/`evidence.json` | `cli.go:475,514,533-534` | Document or extend the flag |
| G7 | **P3** | Version string carries a `v` prefix (`v0.1.0`) where `jabari` emits `0.1.0` | `version -o json` | Pick one convention fleet-wide |

## 15. Dependencies, prerequisites, and unresolved questions

**Runtime dependencies:** `spf13/cobra`, `spf13/viper`, plus internal packages. **No external binaries required** — unlike Jabari there is no `adb`/cloud-CLI dependency; analysis is pure offline parsing.

**Prerequisites for use:** a snapshot file (`--snapshot <path>`) or `--sim`; optionally `--profile`, `--report-dir`, `--events`. No credentials, no authorization prompt for offline work (declared in `capabilities.authorization_model`).

**Unresolved questions**

1. Is live collection (H1) intended to stay permanently out of scope, or is it a roadmap item with no documentation? (`docs/Roadmap.md` is zero-byte, so the intent is unrecorded.)
2. Which snapshot schemas are officially supported? Only AWS-shaped policy/asset shapes are evident in `iam/policy.go` and `cloud/snapshot.go`; Azure/GCP support is asserted in package docs but not covered by fixtures.
3. Should the fleet adopt exit 3 for "refused/unimplemented" (Jabari uses 3 for authorization refusal; Imhotep uses 2)? The spec permits both readings but they should not diverge.
4. Should `capabilities` be the single machine contract (per `contract.CapabilityManifest`) with Imhotep's extra metadata nested inside it?
5. Are the 31 placeholders intended to be filled from canonical docs, or removed to stop them being cited as documentation?

## 16. Statement of compliance

**No feature implementation was performed.** This document results from read-only source inspection, help/capability introspection, offline simulation analysis, and existing test/vet runs. No application code, test, configuration, dependency, lockfile, workflow or existing documentation was modified; no cloud provider, device or network endpoint was contacted; no specialist capability was implemented; and the only file created by this audit is this `AUDIT.md`.
