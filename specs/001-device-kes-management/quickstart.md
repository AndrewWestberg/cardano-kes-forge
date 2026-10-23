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

## 3. Provision and establish security mode

Inspect without mutation:

```sh
kes-forge provision inspect --usb-device "$USB_DEVICE" --out-file "$INSPECTION"
kes-forge provision prepare --manifest "$PROVISIONING_MANIFEST"
```

The manifest is produced/reviewed from the hardware-specific policy in [security.md](contracts/security.md). Confirm silicon, flash, firmware/boot keys, required locks and fresh trust material. Only the explicitly attended provisioning ceremony may run:

```sh
kes-forge provision apply --manifest "$PROVISIONING_MANIFEST" --authorize-irreversible
```

Expected: verified trusted readback and signed provisioning evidence; all required negative checks pass before release-ready. Incomplete/unlocked/development evidence blocks production generation/signing. Development fixtures instead use disposable development firmware, explicit `--allow-development`, and no irreversible locks. Test current-state inspection before/after evolution and reboot with restricted output; repeat the attempted interface/debug access on release hardware and require rejection. Never promote an inspected key to release.

## 4. Recipient lifecycle on backup workstation

Run only on the separate backup/recovery system:

```sh
kes-forge recipient create --public-key-file recipient.pub --private-key-file recipient.key
```

Enter and confirm a non-empty long unique passphrase at the hidden terminal prompt. Archive the protected private key and separately secure its unlocking credentials. Transfer only `recipient.pub` to the management-enrollment workflow. Do not use the existing scripts' password argv/environment/display patterns.

On the primary, prepare a pool enrollment action containing the cold public key, network binding, recipient public key, machine public key and expected directory sequence/revision. Offline management signs it; the authorized host submits it:

```sh
kes-forge management prepare --device-config "$DEVICE_CONFIG" --action enroll --payload "$ENROLLMENT" --out-file "$UNSIGNED_REQUEST"
```

On the offline management workstation:

```sh
kes-forge management sign --request "$UNSIGNED_REQUEST" --management-key "$MANAGEMENT_KEY_FILE" --out-file "$AUTHORIZATION"
```

On the primary:

```sh
kes-forge management apply --device-config "$DEVICE_CONFIG" --authorization "$AUTHORIZATION"
kes-forged --config "$DAEMON_CONFIG"
```

Run the daemon in its service session; validate its Unix socket ownership/ACLs and configured connection mapping. Repeat enrollment for the required test pools. Pool cold/VRF handling and external on-chain registration remain conventional; no recipient private key/passphrase goes to the daemon or Pico.

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
