# Quickstart: End-to-End Validation

This is a **post-implementation validation guide**, not evidence that the commands/features already exist. Today this repository contains a Rust skeleton and design artifacts. Do not substitute mocks for the device/node in acceptance, and do not run destructive scenarios against production credentials. Exact interfaces: [CLI/backup](contracts/cli-backup.md), [device/local service](contracts/device-protocol.md), [node/bulk/telemetry](contracts/node-integration.md). State invariants: [data-model.md](data-model.md). Full thresholds, workloads and evidence rules: [quality-gates.md](contracts/quality-gates.md).

## 1. Prerequisites and isolated fixture

- Linux x86_64 primary and a **separate trusted backup/recovery workstation**; external cold-key and offline management workflows. Do not copy their private credentials onto the primary.
- Rust/Cargo1.99.1, target `thumbv8m.main-none-eabihf`, pinned tools in the quality-gate contract. Pico2 A4-or-later at stock clock; one disposable development board and a separately provisioned release qualification board. USB power interrupter for physical fault testing, independently validating testnet peers, and32 disposable pool identities for full capacity.
- Build the **unmodified cardano-cli-11.4.0.0** (`25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`), not an executable inferred from the checkout name. It remains the certificate-issuance, conventional file-key/query tool and independent interoperability oracle; no Cardano CLI source modification is required or permitted by this integration. Build node11.1.3 with its required node/consensus patches separately. Preserve the two dependency graphs and oracle pins in research R1.
- The inspected installed CLI reports11.2.3.1 despite the checkout's11.4.0.0 manifest. Replace neither user's checkout nor binary implicitly; select explicit built paths. `--version` and executable/source hashes must establish the selected baseline before qualification.
- Use a private directory outside version control, `umask 077`, no core dumps, protected-memory support and a local filesystem supporting anonymous/no-replace publication. Generate all disposable secret material at runtime. Never save secret traces/fixtures in this repository.

The planned `xtask fixture` command creates an isolated controlled-network fixture and public manifest; it refuses an existing output directory and never accepts mainnet genesis for destructive testing:

```sh
umask 077
ulimit -c 0
cargo run --locked -p xtask -- fixture create --network controlled --pools 32 --out-dir /run/user/1000/kes-forge-validation
```

Use an appropriate private runtime directory for the executing user's UID rather than blindly reusing1000. The resulting manifest identifies disposable device/pool registrations, expected public keys, independently validating peers, explicit binary paths, network genesis/parameters, socket paths, test opportunity schedule, power-controller identity and separate secret-file references. It must not inline secrets or authorize irreversible provisioning implicitly. Define `FIXTURE` as that manifest path and `EVIDENCE` as a private report directory. Environment variables below contain **paths/public metadata only**, never passwords/private-key bytes.

## 2. Build and check the selected executables

```sh
rustc --version
cargo --version
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings -F clippy::cognitive_complexity
cargo build --locked --release --bins
cargo build --locked --release -p cardano-kes-forge --bin kes-forge
./target/release/kes-forge --help
cargo run --locked -p cardano-kes-forge --bin kes-forge -- --help
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --release
"$CARDANO_CLI" --version
"$CARDANO_NODE" --version
cargo run --locked -p xtask -- gate tool-sensitivity --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- gate cognitive-complexity --evidence "$EVIDENCE"
```

`CARDANO_CLI` and `CARDANO_NODE` point to the explicitly built binaries. In their separate native source directories run `cabal build cardano-cli` against the unmodified CLI pin and `cabal build cardano-node cardano-testnet` against the patched node/consensus candidate respectively, using pinned toolchains/index states. Required outcome: exact baseline/candidate identities and passing tool defect/regression probes. The host Cargo package remains `cardano-kes-forge`, but its operator binary is `kes-forge`; the help smoke checks above must identify that executable, and the actual installed invocation below assumes its directory is on `PATH`. The daemon executable is `kes-forged`. A version mismatch, modified CLI baseline, unconfigured tool, missing executable or empty case set stops validation. Building a release firmware profile does not provision a release-secure board.

G12 requires the implementation's repository-root `clippy.toml` to pin `cognitive-complexity-threshold = 25`. Its runner binds `CLIPPY_CONF_DIR` to that root and checks the complete host, firmware, maintained KES adaptation and separately built Rust-tooling target/feature matrix; the default-member Clippy command above alone is insufficient. Confirm an above-threshold disposable function fails with the expected lint, a boundary case passes, and local suppression is rejected. This allow-by-default restriction lint needs explicit enforcement and is only a code-complexity guardrail, not proof of human comprehension or a replacement for review/operator trials.

## 3. Clean-install public inputs and attended provisioning

This bootstrap is independent of `xtask fixture`: start from empty owner-only directories and installed planned production binaries. Install the primary profile on the service host, management profile on the offline management workstation, provisioning profile on the isolated attended provisioning workstation and recovery profile on the separate recovery workstation. The primary profile must not expose authority-signing, provisioning or recipient-private workflows. One physical operator can hold several roles, but host location is procedure/OS custody, not cryptographically provable.

On each workstation set `umask 077` and disable core dumps. Create primary machine credentials as the daemon service UID in its private `0700` credential directory. Node/operator callers may use separate UIDs explicitly mapped to their connections; they read only public configuration/evidence, never private credentials. Paths below are explicit local files in the responsible workstation's directory; transfers are authenticated **public files only**. Choose `DEVICE_ID` and `INCARNATION_ID` with separate `openssl rand -hex 16` invocations and retain their public values for the ceremony/enrollment. Choose the pool ID by decoding the conventional cold VK and taking BLAKE2b-224 (the enrollment builder checks it); do not use a pool label or slot number.

On the offline management workstation:

```sh
kes-forge authority key-create --role management --public-key-file management.pub.json --private-key-file management.key.json
```

Transfer only `management.pub.json` to provisioning. On recovery:

```sh
kes-forge recipient create --public-key-file recipient.pub.json --private-key-file recipient.key
```

Enter/confirm the hidden non-empty passphrase; archive the protected key and separately secure its unlocking credentials. Transfer only recipient public JSON to enrollment. Recovery private key/password never go to the Pico, management or primary.

On primary create the machine management-transport key, using the ceremony's agreed device ID:

```sh
mkdir -m 700 private
kes-forge credential create --device-id "$DEVICE_ID" --scope management --credential-epoch 0 \
  --public-key-file transport.pub.json --private-key-file private/transport.key.json
```

Transfer only `transport.pub.json` to provisioning. On the isolated provisioning workstation:

```sh
kes-forge authority key-create --role provisioning-reviewer --public-key-file reviewer.pub.json --private-key-file reviewer.key.json
kes-forge provision inspect --usb-device "$USB_DEVICE" --out-file inspection.json
```

Obtain the approved hardware-specific policy/recipe, authorized signed release firmware, partition manifest and boot-key fingerprint from the reviewed release workflow. They are prerequisites, not generated from inspection or accepted from an unknown device. Pin vendor manuals, supported silicon and picotool 2.3.1 executable hash as required by [security.md](contracts/security.md). In an editor create `provisioning.draft.json` with **every** ProvisioningManifest field and exact reviewed steps from that contract, signature null, references to these local public files, management/transport/reviewer public handoffs and exact SHA-256 digests. Select a fresh ceremony ID. No production root/private key literal belongs in it. Missing approved recipe/image/key or unsupported silicon blocks here rather than triggering automatic boot trust.

Explicitly set `managementPublicKeyDigest`, `managementTransportPublicKeyDigest` and `reviewerPublicKeyDigest` to SHA-256 of the exact transferred public-key file bytes. Review these content hashes along with their paths; prepare/apply must reject substituted key files. Manifest/record signatures use the contract's exact typed deterministic-CBOR conversion, never a floating-point JSON canonicalization.

```sh
kes-forge provision prepare --manifest provisioning.draft.json --review-key reviewer.key.json --out-file provisioning.approved.json
kes-forge provision apply --manifest provisioning.approved.json \
  --reviewer-public-key-file reviewer.pub.json --review-key reviewer.key.json \
  --out-file provisioning.record.json --authorize-irreversible
```

Review the entire signed before/after irreversible plan before apply. Expected: trusted readback and required negative checks, fresh device-generated root/identity/HPKE keys and a completed signed record. Incomplete evidence is not release-ready. Preserve the signed manifest, policy/recipe/image provenance and record; authenticate the reviewer public fingerprint out of band. Construct `device.identity.json` from the record's public fields and exact DeviceIdentity schema, with record/reviewer file references. Transfer this pin, reviewer public file, record and public evidence dependencies to primary and recovery; compare all bindings and fingerprint through the attended handoff, never learn a key from unauthenticated INFO. Keep reviewer private key on provisioning and management private key offline. Development fixtures instead use disposable firmware/trust, `isolated-development` policy and explicit `--allow-development`, never irreversible release locks or promoted inspected KES keys.

## 4. Start daemon, enroll and connect a pool

Use an editor on primary to create the exact closed `DeviceConfig` from [CLI bootstrap schemas](contracts/cli-backup.md#versioned-bootstrap-files), for example:

```json
{"version":1,"socketPath":"kes-forged.sock","deviceId":"<ceremony 32 lowercase hex>","deviceIdentityFile":"device.identity.json","connectionName":"management","credentialFile":"private/transport.key.json","credentialEpoch":0,"securityPolicy":"release-required"}
```

Substitute the actual device ID; angle-bracket text is explanatory, not an accepted value. Save as `device.json`. Create `daemon.json` (substitute actual stable USB selector and numeric service UID):

```json
{"version":1,"socketPath":"kes-forged.sock","usbDevice":"<stable USB selector>","deviceConfigFile":"device.json","poolConnectionFiles":[],"allowedPeerUids":[{"uid":1000,"connections":["management"]}]}
```

All relative file/socket references resolve from the containing file. Keep public configurations/evidence in a trusted-owner directory readable/searchable by intended caller UIDs with no untrusted writes. Store private credentials separately under the daemon UID: regular `0600` files in `0700` directories; point credentialFile references to those daemon-only paths (for example `private/transport.key.json` and `private/pool-machine.key.json` after placing the created files there under daemon custody). Public file readability never grants credential access. Actual service UID replaces 1000; initially only it maps to management. Configure socket/directory ACLs for explicitly authorized client UIDs when adding pool mappings. Start the daemon **before** management prepare/apply, in its own service session:

```sh
kes-forged --config daemon.json
```

Verify pinned release evidence and protected Unix socket access; no pool registration is required to open the provisioned management transport. In a second service-UID session set `DEVICE_CONFIG` to this directory's `device.json`. Obtain the existing conventional cold public envelope and exact enrolled Shelley genesis bytes from the cold/network workflows; keep cold/VRF secrets under their existing custody. Set `POOL_ID` to the cold-key hash, `NETWORK_MAGIC` to the agreed network magic and `INCARNATION_ID` to the newly selected ID. Create the pool machine key as the daemon UID and public enrollment payload on primary:

```sh
"$CARDANO_CLI" conway stake-pool id --cold-verification-key-file "$COLD_VKEY" --output-format hex
```

Use that public hex output as `POOL_ID`; the ordinary Cardano CLI is the existing public pool-identity creation path, not an extra KES secret generator.

```sh
kes-forge credential create --device-id "$DEVICE_ID" --scope pool --pool-id "$POOL_ID" \
  --incarnation-id "$INCARNATION_ID" --credential-epoch 0 \
  --public-key-file pool-machine.pub.json --private-key-file private/pool-machine.key.json
kes-forge management enrollment-create --device-config "$DEVICE_CONFIG" \
  --cold-verification-key-file "$COLD_VKEY" --shelley-genesis "$SHELLEY_GENESIS" \
  --network-magic "$NETWORK_MAGIC" --recipient-public-key-file recipient.pub.json \
  --machine-public-key-file pool-machine.pub.json --incarnation-id "$INCARNATION_ID" --out-file enrollment.json
kes-forge management prepare --device-config "$DEVICE_CONFIG" --action enroll --payload enrollment.json --out-file enrollment.request.json
```

Transfer public request and approved public enrollment inputs to offline management; compare device, cold hash, incarnation, network, machine/recipient keys, expected revision and sequence before signing:

```sh
kes-forge management sign --request enrollment.request.json --management-key management.key.json --out-file enrollment.authorization.json
```

Transfer only signed authorization back to primary:

```sh
kes-forge management apply --device-config "$DEVICE_CONFIG" --authorization enrollment.authorization.json
```

Require a validated durable enrollment response. Construct `pool.connection.json` with **all** existing PoolConnection fields: version 1, same socket/device/pin, enrolled pool/incarnation/networkBinding, unique `connectionName="pool-1"`, credentialFile referencing the daemon-owned private pool-machine file and `securityPolicy="release-required"`. Copy networkBinding from the validated enrollment payload, not manual network-time guesses. Add this file to daemon.json's `poolConnectionFiles` and explicit intended node/operator UID mappings in `allowedPeerUids`, each with `connections:["pool-1"]` (combine permitted connection names in one record if a UID already exists). Keep management mapped only to intended management callers; no wildcard or socket-only authorization. Grant those callers read/search access to public files and socket ACL access, not private files/directories. Stop/restart the daemon service (in its service session, normal termination then the same `kes-forged --config daemon.json` command). This static mapping change does not re-enroll or authorize a key. Set `POOL_CONNECTION` to the file and run as an explicitly mapped pool caller:

```sh
kes-forge status --connection "$POOL_CONNECTION" --json
```

Expected: authenticated pool registration, no active generation, no fabricated remaining validity or latency samples after restart. Repeat the same enrollment/mapping procedure for additional test pools, maximum 32. Cold/VRF/on-chain registration remain conventional and no offline authority/recipient secret goes to daemon or Pico. This completes clean-install bootstrap through actual daemon startup and enrollment; generation follows below.

## 5. Generate on device, issue certificate, recover backup

On the primary, use a stable request ID and next generation number obtained from public status. Choose explicit output paths in the private fixture directory:

```sh
kes-forge key-gen-KES \
  --connection "$POOL_CONNECTION" --request-id "$REQUEST_ID" --generation-number "$GENERATION_NUMBER" \
  --verification-key-file kes.vkey --encrypted-signing-key-file kes.kes-backup --generation-file generation.json
kes-forge backup fetch --connection "$POOL_CONNECTION" --generation "$GENERATION_ID" --out-file kes.second.kes-backup
cmp kes.kes-backup kes.second.kes-backup
```

Expected: a durable staged generation, conventional public key and immutable encrypted artifact; no plaintext device KES key on primary. Device generation is owned by this Rust operator command, with no era/node prefix, old command alias or software fallback. Retry a deliberately lost response with the same request/generation identity and verify the same committed generation, not another key. Existing unrelated output paths must fail. The unmodified Cardano CLI's software `node key-gen-KES` is exercised separately by the fixture on disposable file-based keys, with no device selected.

Transfer public VK to the existing cold-key workstation. Issue the matching certificate through the unmodified `"$CARDANO_CLI" conway node issue-op-cert` workflow; transfer only the public certificate back. Certify/activate using ordinary configured pool authority:

```sh
kes-forge certify --connection "$POOL_CONNECTION" --generation "$GENERATION_ID" --operational-certificate-file node.cert
kes-forge activate --connection "$POOL_CONNECTION" --generation "$GENERATION_ID" --current-period "$CURRENT_KES_PERIOD"
kes-forge status --connection "$POOL_CONNECTION" --json
```

The fixture computes period from network slot/genesis parameters, never a hardcoded days/epoch value. No management signature/PIN/second operator is needed for these routine operations.

Transfer artifact, public VK and trusted public device identity to the backup workstation. There:

```sh
kes-forge backup recover \
  --artifact kes.kes-backup --recipient-key recipient.key --device-identity-file device.identity.json \
  --expect-device "$DEVICE_ID" --expect-pool "$POOL_ID" --expect-generation "$GENERATION_ID" \
  --verification-key-file kes.vkey --out-file kes.skey
"$CARDANO_CLI" key verification-key --signing-key-file kes.skey --verification-key-file recovered.vkey
kes-forge recipient change-password --private-key-file recipient.key
```

Compare **decoded public key bytes**, not JSON whitespace/descriptions, through `xtask qualify interop`. Recover the same artifact to a new output after password change; recipient identity, artifact bytes and device configuration must be unchanged. Run wrong-password, wrong-recipient, altered-artifact and existing-output scenarios via `qualify recovery-files`: explicit failure, no partial published plaintext or overwritten key, no secrets in captured output. Interrupt password replacement and require a usable old or new protected file.

Management-authorized recipient replacement then generates a new staged key for the new recipient; old artifact still needs the old private key. Retain protected old keys while needed. A password change cannot revoke an old copied file, and loss of all keys/passwords is irrecoverable.

## 6. Mixed bulk node, rotation and telemetry

Use the fixture's one mixed bulk file with at least one legacy file-backed tuple and one explicit forge object; verify syntax against [node contract](contracts/node-integration.md). Start **one** actual node:

```sh
"$CARDANO_NODE" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$NODE_DB" --socket-path "$NODE_SOCKET" --bulk-credentials-file "$MIXED_BULK"
```

The fixture retains PID and schedules eligible opportunities for each pool. In another session:

```sh
cargo run --locked -p xtask -- qualify node --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify telemetry --fixture "$FIXTURE" --evidence "$EVIDENCE"
```

Require independent accepted-block evidence for both sources in this same process; disconnect device during actual signing and verify file-backed opportunities/synchronization continue, no fallback/invalid block is submitted, and reconnect resumes device-backed blocks with unchanged PID. Also exercise unchanged legacy bulk and all three singleton sources; reject a bulk kes-agent entry and entry-specific configuration conflicts.

Generate/certify the replacement while the active key signs. Schedule it:

```sh
kes-forge schedule --connection "$POOL_CONNECTION" --generation "$REPLACEMENT_GENERATION" --activation-period "$ACTIVATION_PERIOD"
```

Restart device and daemon between scheduling and eligible period. Expected: same durable intent/certificate, automatic activation on authenticated period observation, no extra approval, no reset to stale host state, zero signer-caused missed opportunities for unaffected pools. Second staged generation conflicts. Old/stale-generation responses cannot replace active context.

Telemetry scenarios must include two period transitions, staged vs active context, hot rotation, final valid period/expiry, device power cycle, disconnect/reconnect, failed evolution and lost ACK. Independent expectations use certificate/network/time for public validity and confirmed evolution for key-state fields. Preserve names, historical log mappings, zero error sentinels, cadence and legacy aggregation; no telemetry-triggered device mutation. The unmodified `"$CARDANO_CLI" conway query kes-period-info` still works from public certificate/network context while Pico is unavailable.

For host-only diagnostics, capture `kes-forge status --connection "$POOL_CONNECTION" --json` before any completed operation after daemon restart: every `latency` entry must be `{state:"unavailable",sample:null}`. After a validated SIGN or GET_BACKUP, check only its operation entry changes and that admission-to-validation duration includes host queue/USB/verification, rounded up in ms. GENERATE's sample covers the initial IN_PROGRESS acknowledgement, not asynchronous completion. Repeated status/OP_STATUS reads must preserve sample requestId, observedAt and duration while age increases.

With USB/session kept live, pause operational node period observations on the controlled fixture while continuing status reads. At ages <30000ms joined status may be fresh; at **>=30000ms** either confirmed/node-period age makes it stale, `ready=null` and remaining validity null even if STATUS keeps refreshing confirmed device facts. Unavailable joins likewise report readiness null, not false; only a fresh/current join computes boolean readiness from security/lifetime/health. Advance only wall clock and require no freshness extension. A queried latency entry likewise becomes stale at completion age >=30000ms, retaining the original sample. Exercise the exact boundary in the host fake-monotonic-clock tests; physical exercises must not claim millisecond scheduling precision. Resume a matching operational node observation to re-establish the join.

Induce a real admitted request's terminal deadline/USB failure on disposable fixtures. Require its last-completed latency sample outcome `error`, stable `DEADLINE_EXCEEDED`/`DEVICE_UNAVAILABLE` code and bounded duration; no in-progress/requested mutation is confirmed state. Disconnect immediately makes readiness unavailable; an error sample may still display without implying readiness. Session replacement/reboot/daemon restart resets latency samples to unavailable/null and invalidates old readiness; active rotation requires newly matching confirmed and node-period observations, not old-generation replies. Do not alter native KES telemetry/error sentinels to satisfy these separate status exercises. Qualification reports must distinguish unavailable diagnostics from successful hardware measurements.

Query management scope with `kes-forge status --device-config "$DEVICE_CONFIG" --json` as its explicitly mapped caller. Require null `observation`, `ready`, `remainingValidityPeriods` and `latency` rather than borrowing any pool's diagnostics; device security/directory facts remain separate.

## 7. Capacity, persistence, security and custody failures

```sh
cargo run --locked -p xtask -- qualify interop --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify load --fixture "$FIXTURE" --rounds 10000 --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify power-loss --fixture "$FIXTURE" --cuts 1000 --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify recovery-files --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify security --fixture "$FIXTURE" --evidence "$EVIDENCE"
```

Full scenarios/thresholds are centralized in the quality-gate contract. Include32 active+32 staged, aligned midpoint evolution, background generation with one staged vacancy, status under saturation,33rd registration rejection, replay/cross-pool faults and physical torn writes. A software run or dev board does not pass physical release qualification. Irrecoverable-corruption tests must fail closed and are not counted among successful ordinary power-loss recovery trials.

Exercise management credential revocation/replacement, deletion and device retirement while other pools sign, then reboot and replay old authorizations. Replace failed hardware using fresh trust, fresh device-generated KES keys and new matching certificates; no old private-key import. Archive artifacts before their device retention window ends.

Stop the primary producer before starting the conventional backup with the recovered `kes.skey` and same certificate, original Pico disconnected. Independently validate accepted backup blocks in a separate interval. Stop backup before returning to primary. The platform does not provide fencing/failover orchestration; simultaneous forging remains an operator risk.

## 8. Operator trials and public-network release gates

```sh
cargo run --locked -p xtask -- qualify operators --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify public-network --network preview --fixture "$PREVIEW_FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify public-network --network preprod --fixture "$PREPROD_FIXTURE" --evidence "$EVIDENCE"
```

Provide test delegation/leader opportunities and independent observers. Full-capacity physical qualification and independent security review precede operator-approved mainnet use. Record actual elapsed periods/accepted blocks, separate primary/backup intervals and rotation/recovery. Missing opportunities, hardware or valid gate reports is an explicit blocked qualification, not success.

At completion, remove disposable secret inspection/recovery files from the private fixture workstation under its secure-storage policy; retain only public revision-linked evidence and separately archived legitimate backup artifacts/recipient keys where intended. Do not claim file deletion erases external copied secrets or guarantees physical SSD erasure.
