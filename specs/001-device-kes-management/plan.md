# Implementation Plan: Device-Protected KES Management

**Branch**: `001-device-kes-management` | **Date**: 2026-10-23 | **Spec**: [spec.md](spec.md)

**Input**: `specs/001-device-kes-management/spec.md`

**Planning status**: Phase 0 research and Phase 1 design complete. No implementation, hardware provisioning, production-security qualification or public-network acceptance is claimed. This command does not create `tasks.md`.

## Summary

Build a greenfield Rust KES platform on Pico 2, shared by up to 32 device-backed pools on one Linux host. A bounded local daemon multiplexes authenticated USB requests; device firmware generates, evolves, persists and signs Sum6KES state. Each pool has one active/current-expired generation and one staged replacement, independent credential/certificate/replay state, immutable recipient-encrypted generation-time backup, and unattended routine rotation through its configured pool authority.

Provide device-only generation as `kes-forge key-gen-KES` in the Rust operator CLI, with existing device-generation flags and no era/`node` prefix, old command alias or host-generation fallback. Add native node/consensus external-signing integration, not kes-agent key delivery; no cardano-cli source modifications or fork are required. Preserve existing file-based and single-pool kes-agent behavior. One bulk node must mix file-backed and device-backed pools without runtime USB faults blocking healthy file-backed forging. Preserve existing KES telemetry from host public context plus confirmed device evolution; no telemetry-only device storage or clock.

**Required unmodified CLI baseline: cardano-cli-11.4.0.0**, commit `25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`, for external certificate issuance, conventional key/query operations and the independent compatibility oracle. Node compatibility baseline: cardano-node-11.1.3; node/consensus patches remain required. Their API/consensus dependency graphs differ and remain separate. The installed CLI reporting 11.2.3.1 is not accepted as the requested baseline. Exact pins and inspected local-fork revisions are recorded in [research R1](research.md).

## Technical Context

**Language/Version**: Rust edition 2024, rustc/Cargo 1.99.1; no_std firmware and shared bounded core. Native Haskell changes follow existing node/consensus conventions; CLI source remains unmodified. GHC 9.6.7 / Cabal 3.12.1.0 selected for reproducible native builds, with separate pinned solver plans.

**Primary Dependencies**: Reviewed adaptation of `kes-summed-ed25519 =0.2.1` for no_std/bounded/cooperative operation; `embassy-rp =0.10.0` RP235xA HAL plus Embassy USB; `hpke =0.13.0`; RustCrypto/Dalek/zeroize pins in research R5. Retain Cargo package `cardano-kes-forge`; explicitly name the operator binary `kes-forge` at `src/main.rs` and the daemon binary `kes-forged`. Package/project and executable names are distinct compatibility surfaces: do not rename directories, node source `cardano-kes-forge`, protocol/crypto domains or package identity. Add focused workspace members rather than a general HSM framework. No Pico HSM application linkage/port, PIN/MKEK model, imported private keys or hardware-dependent secret fallback.

**Storage**: Device-specific OTP trust roots; authenticated double-bank per-pool flash snapshots with COMMIT/cleanup ordering and immutable public/backup objects. Proposed 4 MiB budget: 3,152 KiB reserved total, 944 KiB spare; per-pool: 32 KiB. Host stores restricted credentials/public descriptors/encrypted backups; recipient private material and recovered plaintext live only on authorized separate backup workstation. Detailed transactions/retention in [data-model.md](data-model.md).

**Testing**: Cargo behavior tests, proptest 1.11.0, cargo-mutants 27.0.0, cargo-llvm-cov 0.9.1, cargo-fuzz 0.13.1 / nightly-2026-10-22, Criterion 0.8.2, explicit Clippy `cognitive_complexity` enforcement (threshold 25), independent CLI 11.4 and node 11.1.3 crypto/file oracles, real daemon/socket/node smokes, physical power interruption/load/security campaigns and public-network/operator trials. Nine inspected Observatory sensors plus project-specific gates, including G12's comprehension-risk complexity check, are defined in [quality-gates.md](contracts/quality-gates.md). Clippy is a code-complexity heuristic, not proof of human comprehension; independent review/operator trials remain required. Tools/gates are proposed until configured, sensitivity-proven and maintainer-approved; no passing application readings invented.

**Target Platform**: Linux x86_64 primary and separate Linux backup/recovery system; stock-clock Raspberry Pi Pico 2 RP2350 A4-or-later, secure Arm Cortex-M33, `thumbv8m.main-none-eabihf`, detected 4 MiB flash / 520 KiB SRAM. Development is explicitly unlocked/disposable; production accepts only verified release-ready hardware. Other host OSes, RP2040, older/unknown silicon and RISC-V release execution are unsupported.

**Project Type**: Embedded firmware, shared domain/codec libraries, local host service/operator CLI, native integrations in existing Cardano projects, and qualification tooling. Not a wallet, general HSM, remote fleet service or failover controller.

**Performance Goals**: SC-003: ≥ 99% of 10,000 warm single-pool requests ≤ 100 ms; every valid request in 10,000 synchronized 32-pool rounds ≤ 500 ms including queueing/evolution/activation/transport/independent verification. Overload ≤ 500 ms; authorized status ≤ 2 s. Qualify all 32 active + 32 staged and separate background-generation workload with one staged slot vacant, including midpoint evolution.

**Constraints**: No device-backed KES plaintext on primary; encrypted backup only at generation; password/private recipient key only on recovery host; no import/fallback; remove obsolete device secret before ACK/new-period signature. Max. 4096-byte message / 8192-byte frame, bounded queues/workspaces. Target 256 KiB KES-owned RAM and ≥ 32 KiB measured free SRAM after complete firmware/stacks. Same-host credentials do not provide protection after all are stolen. Backups intentionally weaken deployment-wide forward security.

**Scale/Scope**: FR-001–FR-032 and SC-001–SC-012, including one actual mixed bulk node, 32 simultaneous active + staged pools, 1,000 physical power cuts, 100 consecutive controlled production opportunities, preview/preprod trials and representative operators. No acceptance target is reduced based on prototype results.

## Constitution Check

Constitution 1.1.0 governs. **Initial gate: PASS for research. Post-design gate: PASS for this documentation-only plan; no constitutional exception requested.** This verdict does not activate implementation/release gates or imply hardware feasibility has passed.

| Principle / constraint | Initial assessment | Post-design evidence and enforcement |
|---|---|---|
| I. Explicit scope/correctness | Feature requirements provide scope; failures must be explicit | Traceability below covers every FR/SC. No additional failover controller/agent bulk support/general HSM. No response/key fallback or silently reduced capacity. |
| II. Verifiable behavior | Plan real executable and failure-path checks | Quickstart covers device/daemon/CLI/actual mixed node and independent validation. G1–G12/P0/P1 define oracles and nonempty evidence; planning receives documentation validation and G12 disposable host lint sensitivity evidence, not a claimed application/firmware gate pass. |
| III. Stable interfaces | Existing bulk/source/CLI semantics must survive | Five versioned contracts define new commands, files, protocol/errors, source union and telemetry. Legacy triple-envelope bulk remains valid; all affected native callsites/pattern matches must migrate together. No compatibility shim delivering fake secrets. |
| IV. Security at boundaries | Resolve authoritative crypto/hardware sources | Research cites both pinned crypto stacks, maintained primitive dependencies, recipient format and RP2350 primary sources. Security inventory includes required states, tests and explicit non-applicability. Review adapted KES/HPKE and provenance before adoption; secrets excluded from logs/fixtures/version control. |
| V. Maintainable Rust | Preserve Cargo name/edition; minimal bounded architecture | Shared core/codec, target-specific firmware, existing root host package and qualification member only. No generic repository/storage framework. Fixed buffer contracts avoid hot-path allocation/copying; document every necessary unsafe boundary. |
| VI. Observatory | MCP available; must inspect complete selected entries | Nine full entries consulted; coverage gaps recorded; commands/tool pins/oracles/thresholds/budgets/artifacts and sensitivity probes defined. G12 explicitly enables Clippy cognitive complexity at threshold 25 as a project guardrail; no matching catalog sensor or proven human-comprehension reading is claimed. Missing/inconclusive sensor readings block acceptance. Maintainer approval still required before implementation gates activate. |
| Dependency/tooling governance | Native releases and tool versions not assumed from names | CLI 11.4 pin explicitly honors user override; separate API 11.9 / crypto 2.6 and node API 11.6 / crypto 2.5 oracles. Cargo/license/advisory review, exact transitive locks and actual tool qualification required before implementation acceptance. |
| Performance governance | Prototype timing is not evidence | P0 defines approved measured baseline and noise-aware 5% regression rule; P1 preserves hard physical acceptance thresholds. No fabricated benchmark sensor ID. |

No unresolved product clarification remains. Hardware timing, secure provisioning, firmware size, independent review and cross-release executable interoperability are unmeasured **qualification obligations**, not design waivers. If a required experiment fails, report ERROR and obtain an explicit requirement/hardware decision; do not silently lower scope or call the candidate complete.

## Project Structure

### Documentation (this feature)

```text
specs/001-device-kes-management/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
    ├── device-protocol.md
    ├── cli-backup.md
    ├── node-integration.md
    ├── security.md
    └── quality-gates.md
```

`tasks.md` belongs to the subsequent task-generation workflow and is intentionally not generated now. Existing `checklists/` is left unchanged.

### Source code (planned repository layout)

```text
Cargo.toml                         # root cardano-kes-forge package; explicit kes-forge binary; workspace/default-members
Cargo.lock                         # pin reviewed dependencies and patched KES source
rust-toolchain.toml                # production toolchain and target
src/
├── main.rs                        # kes-forge operator CLI, including key-gen-KES (replace skeleton)
├── lib.rs                         # host clients, backup lifecycle and output publication
├── bin/kes-forged.rs               # kes-forged local Unix service/USB owner
├── cli/
├── host/
└── backup/
crates/
├── kes-core/                      # no_std state machine, crypto adapter and journal semantics
└── kes-protocol/                  # no_std bounded canonical codecs and errors
firmware/                          # kes-firmware: Secure signer + Non-secure USB boundary
third-party/kes-summed-ed25519/     # attributed narrowly reviewed Cargo path patch
xtask/                             # real qualification orchestration/evidence validation
fuzz/                              # parser and authenticated-state fuzz targets
benches/                           # representative Criterion workloads
tests/                             # host behavioral/contract/integration consumers
```

All listed paths are planned repository-root paths, not current artifacts. Existing code at planning time is only `Cargo.toml` (empty dependencies, edition 2024) and `src/main.rs`. Host default members exclude the target-only firmware but include both shared libraries and qualification tool. Do not add a std allocator to the firmware to hide dependency adaptation failures.

**Structure decision:** Root package owns host binaries and recovery tools; shared crates isolate code that can be measured/fault-tested on the host and reused without std on device. Firmware owns only hardware/security/runtime integration. A local daemon is necessary because 32 pools and multiple node processes share one USB device. Separate secure/nonsecure firmware components enforce the required key boundary, not a general plugin architecture. The third-party patch preserves a maintained KES construction rather than inventing crypto; it must carry source checksum, license and reviewed patch history.

### Native integration repositories

Use the supplied cardano-node/consensus checkouts as integration workspaces, preserving user changes. The cardano-cli checkout is source-research/oracle input only, not an edit target. Documentation references paths relative to their repository roots:

- Node: `cardano-node/src/Cardano/Node/Types.hs`, `Parsers.hs`, `Protocol/Shelley.hs`, configuration consumers, `Queries.hs`, `Tracing/Tracers/KESInfo.hs`, consensus trace adapters and native test/help files.
- CLI 11.4: require the unmodified release baseline for certificate issuance, conventional key/query operations and independent file/crypto compatibility checks. Previously inspected command/query modules are historical source evidence in research R1, not a native command-module change plan; `kes-forge key-gen-KES` owns device generation.
- Consensus: `Protocol/Praos/Common.hs`, `Protocol/Ledger/HotKey.hs`, Shelley/Praos/TPraos and hard-fork forging callers, generic block forging and diffusion `NodeKernel.hs`. Typed external failures must reach the actual block-production boundary; updating credential loading alone is insufficient.
- Separate Haskell interoperability executables use each baseline's exact API/crypto dependencies; do not share an incompatible Cabal graph or count the adapted Rust implementation as its own independent oracle.

## Phase 0 — Research outcome

[research.md](research.md) records decisions, rationale, alternatives and sources:

1. Unmodified CLI 11.4 / node 11.1.3 release pins, separate compatibility graphs and node/consensus native integration seams.
2. Existing Sum6KES dependency adaptation and authoritative interoperability.
3. Pico 2 hardware/security, Embassy, bounded USB/local service and entropy.
4. Crash-safe cleanup/retention and measured capacity risk.
5. Recipient public-key backup and local password/recovery lifecycle.
6. Per-pool mixed bulk, typed forging errors, rotation and existing telemetry.
7. Full Observatory selection, gaps and executable tooling/performance gates.

Research-agent dispatch failed due provider authentication; direct research completed the same questions. MCP remained available. Initial technical unknowns are resolved into explicit choices; no product clarification remains open.

## Phase 1 — Design outcome and implementation ordering

The data model defines device/pool/generation/credential/recipient/certificate/intent/observation identities, state transitions, counter/replay validation, flash commit/cleanup and host reconciliation. Contracts cover external device/local service, operator/CLI/backup files, native node/bulk/telemetry, release security and evidence gates. Quickstart is a validation/run guide, not implementation code.

Implementation should establish independent crypto/file oracles and tool sensitivity, then the no_std adaptation and fault-testable journal. **Measure the full-capacity physical evolution/erase/sign path early:** 32 sector cleanups may defeat 500 ms even when storage fits. Only after that feasibility gate, proceed to complete daemon/backup/native integration, hot rotation/telemetry, and full security/operator/public-network qualification. No dependency on copying prototype C/Python/HSM components is introduced. This is dependency ordering for the later tasks command, not an implementation performed by this planning run.

## Requirement-to-design traceability

| Requirement | Design responsibility | Acceptance gate |
|---|---|---|
| FR-001 | Data model: 32 live pools / 64 generations, bounded service, independent bulk entries | P1, G8, G10; SC-003/SC-011 |
| FR-002 | Crypto adapter, entropy, durable generation/publication and creation identity | G3, G7, G8; SC-007 |
| FR-003 | Release export boundary and separate compiled development inspection | G9; SC-004/SC-010 |
| FR-004 | Pool vs. offline management authority; unattended sessions and routine rotation | G2, G9, G11; SC-006 |
| FR-005 | Standard key formats and separate recipient-side recovery | G7, G8; SC-007/SC-009 |
| FR-006 | Certificate signature/key/cold-counter validation plus separate network binding | G3, G7, G10 |
| FR-007 | Native third source and per-entry file/forge union, single-agent preservation | G7, G10; SC-002/SC-007/SC-011 |
| FR-008 | Immutable attempt context, authenticated envelope and node independent verification | G6, G7, G10 |
| FR-009 | Forward-only periods, cleanup-before-ACK, same-period no-op | G3, G7, G8 |
| FR-010 | Double-bank recovery, immutable artifact references, quarantine | G8; SC-005 |
| FR-011 | Network-bound lifetime, committed expiry erasure, no trusted device clock | G3, G7, G10 |
| FR-012 | Bounded public status/latency/errors and host observation freshness | P1, G10, G11; SC-001/SC-012 |
| FR-013 | Active + staged state, durable activation intent and hot context switch | G3, G8, G10, G11; SC-006 |
| FR-014 | Typed signing failure at actual forge boundary and unattended reconnect | G10; SC-002/SC-011 |
| FR-015 | Fixed input/queue limits, per-pool fairness and immutable deadlines | G6, P1; SC-003 |
| FR-016 | Management sequence, credential epochs, tombstones and retirement | G3, G8, G9 |
| FR-017 | Complete operator/native source/mixed bulk/replacement procedures | Quickstart, G11; SC-001/SC-006/SC-007/SC-010/SC-011 |
| FR-018 | Release negative security matrix and independent review | G9; SC-004 |
| FR-019 | Dual pinned Haskell oracles, all periods and file/agent regressions | G7, G10; SC-002/SC-007 |
| FR-020 | Single immutable initial artifact and bounded retention/archival | G3, G7, G8 |
| FR-021 | Pool-scoped state/error handling and device-wide fault distinction | G3, G8, G10 |
| FR-022 | Rust `kes-forge key-gen-KES`, existing flags, device-only/no aliases or fallback; unmodified CLI 11.4 issuance/key/query/oracle baseline | G2, G7; SC-007 |
| FR-023 | Local recipient setup, protected private key, public enrollment only | G2, G9; SC-009 |
| FR-024 | Authenticated recovery, exact bindings, protected atomic no-replace output | G2, G6, G8; SC-009 |
| FR-025 | Atomic local password rewrap and future-only recipient replacement | G2, G8; SC-009 |
| FR-026 | Custody/archival/loss/compromise procedures; no password-reset bypass | Quickstart, G11; SC-009 |
| FR-027 | Three security states and pinned challenge-bound readiness verification | G9; SC-010 |
| FR-028 | Protected disposable-state inspection absent from release artifacts | G7, G9; SC-010 |
| FR-029 | Applicable silicon protection inventory, trusted readback and negatives | G9; SC-010 |
| FR-030 | Explicit irreversible fresh-trust transition and no release downgrade | G9; SC-010 |
| FR-031 | Exact legacy bulk preservation, independent source validation/errors | G2, G10; SC-011 |
| FR-032 | Existing metric/log/query inventory and confirmed-state derivation | G10; SC-012 |

SC-008 is the separate G11 preview/preprod + independent-review/mainnet-approval gate; neither controlled-network nor prototype success substitutes for it. Remaining SC criteria appear explicitly in the gate definition with original counts/deadlines.

## Complexity Tracking

No constitutional violations or exceptions. Four unavoidable boundaries—device, local host service, backup workstation and native node/consensus integration—come directly from the accepted custody/multi-pool/integration requirements. The Rust operator CLI owns device generation; unmodified cardano-cli is external issuance/conventional tooling and an independent oracle, not a patched integration surface. Shared core/protocol code reduces duplicated validation; public contracts are versioned without preserving obsolete private implementation paths. Unqualified hardware/tooling blocks acceptance, not a reason to retain a bypass or declare reduced-scope success.
