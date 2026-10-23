# cardano-kes-forge Constitution

## Core Principles

### I. Explicit Scope and Correctness

Every change MUST state its intended behavior, acceptance criteria, and relevant failure cases.
Implementation MUST remain within that scope; the project name alone does not establish product
requirements. Incorrect results and unsupported operations MUST produce explicit failures rather
than fabricated success. Correctness takes precedence over performance and convenience.

### II. Verifiable Behavior

Behavioral changes MUST be exercised through the affected executable or public interface before
acceptance. Bug fixes MUST demonstrate the reported failure before the fix when reproducible and
verify the corrected behavior afterward. Permanent tests MUST cover consumer-visible behavior,
boundaries, or failure modes rather than implementation details. Verification reports MUST name
the checks run, their results, and any unverified behavior; tests alone do not replace a smoke run.

### III. Stable and Explicit Interfaces

Changes to public commands, arguments, output formats, file formats, or Rust APIs MUST document
their input, output, and error contracts. Breaking changes MUST identify affected consumers and
provide a migration decision before acceptance. All repository-owned callers and associated
contract documentation MUST be updated together. Diagnostic output MUST remain distinguishable
from machine-consumed results wherever a machine-readable interface is provided.

### IV. Security at Trust Boundaries

External input MUST be validated before it controls sensitive operations. Secrets, if introduced,
MUST NOT appear in logs, diagnostics, fixtures, or version control. Changes handling keys,
cryptography, or protocol encodings MUST identify the governing specification and demonstrate
compatibility using authoritative vectors or an independent implementation. Custom cryptographic
primitives MUST NOT be introduced when a maintained, compatible implementation is available.
These requirements prevent unverifiable security claims without prescribing unapproved features.

### V. Simple, Maintainable Rust

Implementations MUST use the smallest design that satisfies the accepted requirements. New
abstractions and dependencies MUST have a concrete use case and a reviewable benefit. Changes MUST
remove code made obsolete by their replacement, not retain unused compatibility layers. Avoidable
allocation, copying, and repeated computation MUST be eliminated from changed execution paths.
Unsafe Rust MUST document its safety invariants and why safe alternatives do not meet the need.

### VI. Software Observatory Quality Gate

The Software Observatory MCP and its sensor catalog MUST guide the project's mandatory quality
gate. Before implementation, plans MUST consult the MCP to select applicable sensors, inspect
their full entries, and record their IDs, relevance, limitations, and coverage gaps. Keyword
suggestions are discovery aids, not proof of suitability. Catalog guidance MUST be translated
into executable project checks; consulting the MCP alone is not a passing sensor reading.

Before a code change or release is accepted, every applicable required sensor MUST have a valid,
passing reading for the candidate revision under a maintainer-approved gate definition. Missing,
stale, failed, or inconclusive readings MUST block acceptance. An unavailable MCP MUST block
sensor selection or revalidation; a previously approved, recorded selection MAY be executed
without a live MCP connection. Sensor definitions MUST be revalidated when their applicability
or tooling changes.

Each gate definition MUST record its sensor mapping, command, tool version, measured scope,
oracle or invariant, pass/fail rule, execution budget, and evidence artifact. Evidence MUST identify
the candidate revision, configuration, environment, exclusions, and result. An empty workload,
unexercised behavior, or a successful tool exit without the required measurement MUST NOT count
as a valid reading. Coverage measures execution, not correctness or test sensitivity.

The project MUST select, configure, and exercise Rust-compatible testing and benchmark tools
that produce the evidence required by the selected sensors and performance gates. Tools MUST
demonstrate relevant defect detection or controlled regression detection before their readings
are trusted. Thresholds, scope, and exclusions MUST be approved before evaluating the candidate;
they MUST NOT be weakened merely to make a failing candidate pass. This makes the gate evidence
of quality rather than a checklist of installed tools.

## Technical Constraints

- The established baseline is the Cargo package `cardano-kes-forge`, using Rust edition 2024.
  Changes to this baseline MUST include an explicit compatibility rationale.
- Dependencies MUST be declared through Cargo and reviewed for maintenance, license compatibility,
  and security implications before adoption.
- New requirements for a network, deployment platform, storage format, cryptographic algorithm,
  or runtime service MUST come from an accepted specification, not inference from the package name.
- Build failures, failed checks, and unsupported environments MUST be reported explicitly;
  acceptance MUST NOT imply verification that was not performed.
- The quality-tooling selection MUST address behavioral tests, property-based tests, mutation
  testing, coverage, and reproducible performance benchmarks. It MUST assess fuzzing and other
  catalog sensors against actual project risks and document non-applicability rather than
  silently omit them. Tool choices MUST satisfy the selected sensor entries; catalog examples
  are not exclusive tool mandates.
- Rust tooling MUST integrate with Cargo and the supported Rust toolchain. Selection MUST record
  supported platforms, pinned versions, reproducible commands, runtime cost, and retained report
  formats. Required tools MUST be configured and verified before their gates are declared active.
- Benchmark gates MUST define representative workloads, a baseline revision, environment controls,
  measured metrics, and noise-aware regression thresholds before candidate comparison. Results
  MUST distinguish a measured regression from an inconclusive comparison; neither may silently
  pass. A benchmark MUST NOT be assigned an invented Software Observatory sensor ID when the
  catalog has no matching entry; it remains an explicit project performance gate.

## Development Workflow

1. Define the change's scope, observable acceptance criteria, and affected contracts before coding.
2. Review existing implementation and conventions; record any constitutional conflict before
   proceeding with an incompatible design. Consult the Software Observatory MCP, record the
   selected sensors and coverage gaps, and approve applicable gate definitions before coding.
3. Implement the scoped change and update affected callers, behavior tests, and documentation.
4. Before acceptance, run `cargo fmt --check`, `cargo check`, `cargo test`, and
   `cargo clippy --all-targets -- -D warnings` for Rust changes. Exercise the changed behavior
   directly, including relevant failure paths. Documentation-only changes instead MUST validate
   their structure, internal consistency, and referenced project facts. Execute the selected
   testing and benchmark tools for applicable gates and retain revision-linked evidence.
5. Review evidence against acceptance criteria and each applicable principle. The Software
   Observatory quality gate MUST pass before code or release acceptance; unavailable or invalid
   required readings MUST NOT be waived as passing by a maintainer decision. Non-applicability
   MUST be justified in the approved gate definition, not asserted after a failure. Other
   unavailable checks MUST be recorded with their reason and require an explicit maintainer
   decision rather than a claim of success. Unresolved failures MUST block acceptance.

## Governance

This constitution governs project specifications, implementation plans, reviews, and acceptance.
Conflicting subordinate guidance MUST be amended or the proposed change MUST be rejected until a
constitutional amendment is approved.

Amendments MUST describe the proposed text, rationale, affected principles, compatibility impact,
and required migrations. A project maintainer MUST approve the amendment before it is treated as
ratified. Approval MUST be recorded in the change review or repository history. The original
ratification date MUST be preserved once established; the last-amended date MUST change whenever
governance content changes.

Constitution versions follow semantic versioning: MAJOR for incompatible principle removals or
redefinitions, MINOR for new principles or materially expanded guidance, and PATCH for
non-semantic clarifications or corrections. Version 1.0.0 establishes the initial baseline, not a
claim about the application's release maturity.

Every change review MUST check compliance with applicable principles and record unresolved
conflicts. Amendments MUST assess dependent guidance for inconsistency; changes to that guidance
require a separate scoped change. The Sync Impact Report is temporary review material and MUST be
removed before committing the amended constitution; it is not part of the governance rules.

**Version**: 1.1.0 | **Ratified**: 2026-10-22 | **Last Amended**: 2026-10-22
