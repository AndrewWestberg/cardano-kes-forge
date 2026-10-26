# Quickstart: End-to-End Validation

This is a **post-implementation validation guide**, not evidence that all commands/features already exist. T002 establishes the Rust 1.99.1 workspace and build profiles. The `kes-forged` binary now loads the closed daemon configuration, exclusively claims the selected KES vendor-bulk interface and serves the protected Unix socket; the operator command surface remains incomplete. T005/T006 implement `xtask` candidate freeze, real gate dispatch and strict acceptance validation; their exercised setup controls are recorded in [quality-gates.md](contracts/quality-gates.md#executed-setup-orchestration), not application acceptance. T020 implements low-level bounded dispatch plus durable initial certify/activate/evolve/sign behavior, but no application firmware USB endpoint or board execution has been exercised. Do not substitute mocks for the device/node in acceptance, and do not run destructive scenarios against production credentials. Exact interoperability, power-loss, security, custody, timing and public-network campaigns remain mandatory.

The implemented build surfaces can be checked without a device:

```sh
cargo run -p cardano-kes-forge --bin kes-forge -- --version
cargo run -p cardano-kes-forge --bin kes-forged -- --version
cargo run -p xtask -- toolchain
cargo run -p cardano-kes-forge --bin kes-forge --no-default-features --features recovery -- --version
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features development --profile firmware-development
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features release --profile firmware-release
```

Select exactly one host installation feature (`primary`, `recovery`, `management`, `provisioning`, `development`); the default is `primary`, and only that profile includes the daemon target. Select exactly one firmware feature (`development`, `release`, or the isolated `usb-preflight`) with the bare-metal target. The product firmware links an ARM slot-A payload with a runtime entry and RP2350 image definition. It is not independently flashable until T044 supplies the boot-partition/partition-table integration. Development identity/root state is fresh and disposable each boot; release deliberately fail-stops pending T041 OTP/security readiness. `usb-preflight` instead links an unpartitioned disposable image at flash base and implements only the framed vendor-bulk transport probe below. These checks do not activate a quality gate or establish a custody/hardware-security guarantee.

### Disposable A2 USB transport preflight

`kes-usb-preflight` is an isolated, destructive development probe. It has no KES keys, INFO/OPEN/session handler, storage, provisioning, updater or production capability. It uses the clearly non-production prototype identity `cafe:4b45`, product `KES USB preflight`, and the same interface tuple required by `UsbWire`: vendor class `0xff`, subclass `0x4b`, protocol `0x01`, one bulk OUT endpoint and one bulk IN endpoint. The prototype VID/PID is not an authorized distribution identity; never ship it or substitute it for the required legitimate product allocation.

Build and inspect the RP2350 image without touching hardware:

```sh
cargo build --locked -p kes-firmware --bin kes-usb-preflight \
  --target thumbv8m.main-none-eabihf --no-default-features \
  --features usb-preflight --profile firmware-development
picotool info -a target/thumbv8m.main-none-eabihf/firmware-development/kes-usb-preflight -t elf
```

The observed image is an ARM Secure RP2350 executable with its image definition at `0x10000114` and entry point `0x10000129`. Flash only after explicit authorization to destroy all disposable board flash. The exercised A2 command erased the detected 4-MiB fitted range because picotool could not infer whole-flash size from this board:

```sh
picotool erase -r 0x10000000 0x10400000 --bus BUS --address ADDRESS
picotool load --ignore-partitions -v -x \
  target/thumbv8m.main-none-eabihf/firmware-development/kes-usb-preflight \
  -t elf --bus BUS --address ADDRESS
```

Grant the logged-in `plugdev` user access to this prototype identity separately from the BOOTSEL rule:

```udev
ACTION=="add|change", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ATTR{idVendor}=="cafe", ATTR{idProduct}=="4b45", GROUP="plugdev", MODE="0660"
```

The exercised A2 run erased 4194304 bytes, loaded and verified the image, and enumerated `cafe:4b45` at full speed with USB 2.00, one exact `ff/4b/01` interface, and 64-byte bulk endpoints `0x01`/`0x81`. Three complete unprivileged physical regression passes—including one after a Linux USB bus reset and one after an MCU power cycle—each completed 265 framed exchanges. They covered the exact success response, invalid requests, 256 alternating requests, one 8192-byte body, serial/bus-address/bus-port selectors, exclusive-claim rejection, and recovery after oversize, zero-length, trailing-byte and expired-partial frames. Host-side empty/8193-byte/zero-timeout requests were rejected before transfer. Run the reusable hardware case explicitly:

```sh
cargo test --locked -p cardano-kes-forge \
  --test usb_preflight_hardware -- --ignored --nocapture
```

This proves the selected Linux usbfs claim, interface matching, bounded bulk framing, malformed-frame recovery and RP2350 USB endpoint path on this disposable board. It does not prove INFO/OPEN authentication, KES operations, persistence, timing, security isolation, A4 feasibility or any acceptance gate.


### Authenticated A2 development firmware

`kes-a2-development` is a separate flash-base image for reversible RP2350 A2 protocol testing. It wires the real `UsbDispatcher` to the Embassy bulk endpoints and implements challenge-signed INFO, Ed25519-authorized HPKE OPEN, sequenced HMAC STATUS and replay invalidation. It reports `security_mode=development`, an all-zero unmeasured-firmware sentinel, and capability evidence stating `otp=untouched`, `persistence=none`, `entropy=health-checked-a2-exploratory` and `session-entropy=fresh-per-open`. Each boot obtains fresh TRNG-backed device identity, HPKE and boot-nonce material; none is persisted, so development self-pinning is valid only for that boot. Each valid OPEN is authenticated and HPKE-decrypted before drawing its session ID directly from the retained fallible TRNG source. Invalid OPEN traffic consumes no entropy; a source failure returns `ENTROPY_FAILURE` and remains latched until reboot. The physical A2 diagnostic exercises the same bounded source and health settings. This provides exploratory protocol authentication and entropy-path coverage, not production identity custody, independent entropy qualification or release access control.

Build it without enabling the slot-A product image:

```sh
cargo build --locked -p kes-firmware --bin kes-a2-development \
  --target thumbv8m.main-none-eabihf --no-default-features \
  --features a2-development --profile firmware-development
```

The transport-only preflight image does not expose a picotool reboot interface. Hold BOOTSEL while reconnecting the board, then use the newly enumerated BOOTSEL bus/address. `picotool load` uses the PICOBOOT protocol and does not need the RP2350 A2 E10 UF2 mass-storage workaround. Loading the ELF directly was physically verified on the 4-MiB A2 board. This command replaces only disposable flash and does not write OTP:

```sh
picotool load --ignore-partitions -v -x \
  target/thumbv8m.main-none-eabihf/firmware-development/kes-a2-development \
  -t elf --bus BUS --address ADDRESS
```

Run the direct physical behavior case or the public T048 development-evidence runner:

```sh
cargo test --locked -p cardano-kes-forge \
  --test a2_development_hardware -- --ignored --exact \
  authenticated_a2_info_open_status_fail_closed_and_reopen

cargo run --locked -p xtask -- qualify security-modes \
  --hardware yes --evidence /absolute/public/evidence/directory
```

The physical case requires serial `A2-AUTH-DEVELOPMENT`. It proves INFO signature verification under explicit boot-local development self-pinning, OPEN transcript authorization, response-MAC verification, authenticated STATUS, invalid-MAC fail-closed behavior and a fresh replacement session. Each run establishes two valid OPEN sessions, each drawing its session ID directly from the retained health-checked TRNG after authentication. It rejects the former deterministic device ID and boot nonce. The executed cold-boot check observed different SHA-256 fingerprints over the public device ID, identity key, HPKE key and boot nonce before and after power removal. The runner records software policy negatives and hashes each command output. It always records `release_qualified=false` and defers secure boot, debug locks, DMA isolation, OTP, signed update/rollback and post-lockdown service to T109 on A4-or-later hardware.

### Disposable A2 entropy-health diagnostic

`kes-a2-entropy-diagnostic` isolates the existing `HealthCheckedEntropy` register configuration and acquisition path from key creation, persistence and authenticated protocol startup. It initializes USB first, then performs one bounded diagnostic after the host request. The device reports only a fixed public status: it never returns raw TRNG blocks, derived seeds, sample hashes or keys. A healthy result requires configuration readback for sample count 200, inverter chain 1, autocorrelation/continuous/Von-Neumann checks enabled, four successful 192-bit blocks, no health failures, two nonzero 256-bit outputs and distinct outputs.

```sh
cargo build --locked -p kes-firmware --bin kes-a2-entropy-diagnostic \
  --target thumbv8m.main-none-eabihf --no-default-features \
  --features a2-entropy-diagnostic --profile firmware-development

# Reconnect while holding BOOTSEL, then flash the disposable ELF.
picotool load --ignore-partitions -v -x \
  target/thumbv8m.main-none-eabihf/firmware-development/kes-a2-entropy-diagnostic \
  -t elf --bus BUS --address ADDRESS

cargo test --locked -p cardano-kes-forge \
  --test a2_entropy_hardware -- --ignored --exact \
  health_checked_trng_reports_bounded_public_status_without_sample_bytes
```

The diagnostic uses serial `A2-TRNG-DIAGNOSTIC`. Configuration, autocorrelation, continuous-test, Von-Neumann and bounded-timeout failures have distinct public error statuses; acquisition stops and does not retry after failure. The physical A2 run passed four blocks after EHR readiness was corrected to use `TRNG_VALID.EHR_VALID`; `RNG_ISR` remains the health-error source. `HEALTHY` is an exploratory A2 register-path and hardware-health observation, not an entropy-rate estimate, independent statistical campaign, adversarial fault test, A4 result or release qualification. It does not write flash after boot or touch OTP. Reflash the authenticated development image through BOOTSEL to resume protocol work.

### Implemented native oracle lab

T009 provides the canonical codec and a semantic ASAN fuzz target; T010 provides separate native byte/file drivers and `xtask oracle self-check`. This is a disposable host lab, not device generation, a production signing service or Rust/native differential qualification. Build/record each driver against its original frozen graph, then run the Rust public-report command in a fresh no-swap user unit:

```sh
python3 -B xtask/oracles/driver.py cli-11.4 build
python3 -B xtask/oracles/driver.py node-11.1.3 build
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 /usr/bin/python3 -B "$PWD/xtask/oracles/driver.py" cli-11.4 identity
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 /usr/bin/python3 -B "$PWD/xtask/oracles/driver.py" node-11.1.3 identity
cargo build --locked --release -p xtask
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 "$PWD/target/release/xtask" oracle self-check
```

The runner and each child verify no-swap isolation before secret input and disable dumping. Missing cgroup-v2/user-manager support fails closed; do not run production material or bypass the guard. Whole-address-space mlockall exceeded the observed8-MiB limit, so this lab uses kernel no-swap isolation rather than claiming production locked-buffer protection. Actual run:768 signatures/valid verifications/corrupt-signature rejections across all64 periods,252 evolutions,4 terminal rejections, shared runtime seed agreement and native key/certificate file checks. See [research](research.md#t010-executed-independent-native-bytefile-oracles-2026-10-24) for exact identities and limits.

### Typed Sum6/native differential regression

After recording both driver identities above, run the private interoperability target explicitly in the same protected lab:

```sh
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" "$HOME/.cargo/bin/cargo" test --locked --release -p kes-core --features native-oracles --test crypto_interop -- --test-threads=1 --nocapture
```

This required qualification target is feature-gated to prevent accidental unprotected secret execution, not to make absent oracles a pass. The exercised3 cases compare all64 states/signatures with both native baselines and original Rust, conventional608-byte serialization, shortened lifetimes and invalid metadata/content. Public `KES_INTEROP_SUMMARY` counters exclude seeds/keys/states. The normal no_std adapter also built for ARM; neither these tests nor a retained link probe constitute board or story acceptance.

### Shared RAM state model regression

Run the current state model explicitly in the protected disposable lab; native oracle identities are not required for this target:

```sh
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" "$HOME/.cargo/bin/cargo" test --locked --release -p kes-core --features protected-runtime --test lifecycle_properties -- --test-threads=1 --nocapture
```

The exercised8 cases include10000 accepted sequences of1–256 public operations,32-pool scope/slot isolation, capacity/revision/policy refusals, no staged overwrite, certification/retry/conflict/network checks, immutable object integrity and signing-key preservation. Private KES/cold-key generation entropy is fresh OS input inside the no-swap/non-dumpable process, never a recorded property seed or fixture. `KES_GATE_SUMMARY` contains public actual counters only. The public backup corpus is unauthenticated syntax, not a valid recovered artifact. T020's separate durable lifecycle target now covers initial activation and every eligible period; seeded sensitivity, complete expiry/replacement, board feasibility and Foundation acceptance remain required.

### Certificate/native and complete core regression

With both pinned native identities recorded, the exercised full core command also runs certificate/native interchange and existing-current-key protection:

```sh
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" "$HOME/.cargo/bin/cargo" test --locked --release -p kes-core --features native-oracles -- --test-threads=1 --nocapture
```

The6 certificate cases cover both native baselines, exact canonical fields/cold signatures, all integer-width/lifetime boundaries and separate network/counter binding. A protected inline current-state fixture checks conflicting recertification preserves its real signing key. The T020 protected operations target separately exercises durable certification, initial activation, evolution, self-verified signing and cleanup failure. The expanded model emitted1306 actual certificate applications,156 retries,126 conflicts and824 network refusals in its10000 accepted sequences. Both actual ASAN fuzzers completed1000-run smoke checks with zero violations, seeded by11 public frame cases and14 independently native-verified public certificates. These are smoke checks, not the required hour-long fuzz or complete G3 sensitivity/acceptance.

### Authenticated journal regression

Run transaction faults only in the protected disposable lab. The target creates fresh KES, cold and storage keys after enforcing no-swap and non-dumpable process state:

```sh
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" "$HOME/.cargo/bin/cargo" test --locked --release -p kes-core --features native-oracles --test journal_faults -- --test-threads=1 --nocapture
cargo fuzz build snapshot --no-trace-compares --target-dir target/fuzz-private
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 "$PWD/target/fuzz-private/x86_64-unknown-linux-gnu/release/snapshot" "$PWD/fuzz/corpus/snapshot" -use_cmp=0 -use_memmem=0 -use_value_profile=0 -runs=1000
```

The first command now passes12 behavioral cases over81920 pool bit-cut attempts and17409 directory byte-boundary cuts, including authenticated successor selection, corrupt/ambiguous quarantine, missing objects, entropy refusal, cleanup-before-ACK, in-place successor transactions and both qualified retry and conservative once-only CLEAN recovery. The fuzzer's recorded T016 smoke passed1000 runs/10589 semantic checks from14 public scripts with zero violations. Keep all comparison-guidance flags disabled: fresh private snapshots exist only inside the protected process; retained fuzz inputs are public mutation selectors. These software results do not qualify fitted flash, physical power cuts, the reported A2 board, Foundation gates or release hardware.

### Fitted storage and secure-runtime compile/link check

The storage, TRNG and entrypoint are target-only. Build and lint both security modes independently:

```sh
cargo clippy --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features development --profile firmware-development -- -D warnings -F clippy::cognitive_complexity
cargo clippy --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features release --profile firmware-release -- -D warnings -F clippy::cognitive_complexity
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features development --profile firmware-development
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features release --profile firmware-release
```

The attached board observation was RP2350 A2/QFN60 with `flash devinfo=0x0c00`. The official Pico2 profile is4-MiB Winbond W25Q32RV; the manufacturer specifies a minimum100000 program/erase cycles. Firmware construction rejects any different profile. The linked development path uses fresh ephemeral identity/root material, configures and reads back the TRNG health policy, and owns one bounded copy gateway. Release fail-stops until T041 provides OTP roots and verified physical isolation/readiness. Only the isolated USB transport preflight above was flashed; the product slot payload still requires T044's boot partition, and no physical entropy, transaction, timing, endurance or power-cut result exists. A2 cannot satisfy the required A4-or-later campaign.

### Authenticated session regression

Run the exact session/protocol behavior targets, then build the maintained public-corpus fuzzer with the pinned nightly. Copy the corpus because libFuzzer may minimize or extend its input directory:

```sh
cargo test --locked -p kes-core --test session
cargo test --locked -p kes-protocol --test codec
RUSTUP_TOOLCHAIN=nightly-2026-10-22 target/gate-tools/fuzz/bin/cargo-fuzz build session --no-trace-compares --target-dir target/fuzz-private
rm -rf target/session-fuzz-smoke
mkdir -p target/session-fuzz-smoke
cp fuzz/corpus/session/* target/session-fuzz-smoke/
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 "$PWD/target/fuzz-private/x86_64-unknown-linux-gnu/release/session" "$PWD/target/session-fuzz-smoke" -use_cmp=0 -use_memmem=0 -use_value_profile=0 -runs=1000
```

The observed core and protocol runs passed5 and13 cases. They cover pinned challenge-bound INFO, the exact HPKE/Ed25519 OPEN transcript and response-envelope HMAC, failed replacement, independent request/response sequence spaces, invalidation and32-pool-plus-management capacity. The ASAN smoke completed1000 runs/6832 semantic checks from7 initial public action scripts with zero violations. This does not replace the required one-hour G6 campaign, independent transcript/security review or physical USB/disconnect/reboot execution. The attached A2 device cannot satisfy required A4-or-later qualification.

### Bounded dispatch and initial durable lifecycle regression

Run host-executable tests for the exact framing/scheduler/dispatcher source and the protected durable lifecycle target:

```sh
cargo test --locked -p kes-protocol --test codec
cargo test --locked -p kes-protocol --test firmware_scheduler
cargo test --locked -p kes-protocol --test firmware_usb
systemd-run --user --pipe --wait --collect --quiet -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" "$HOME/.cargo/bin/cargo" test --locked --release -p kes-core --features protected-runtime --test operations -- --test-threads=1 --nocapture
```

The observed protocol suite passed20 cases across five test binaries; the focused scheduler and USB harnesses passed3 cases each. They exercise fragmented framing, one complete body at a time, separate response prefix/body, deadline caps without reset, one-leaf generation turns, scoped command/storage/expiry errors and release of single-flight state after failure. The protected operations target passed3 cases: actual certify→first-activate→evolve→sign and reboot recovery, failed-cleanup invalidation with old certified-staged recovery, and every eligible relative period0–63 with self-verification, same-period no-write, stale refusal and expiry refusal. The journal fault regression remained12/12 after adding in-place successor persistence.

Firmware statically owns the three8192-byte frame buffers on core0; compile-time ledger assertions keep frame/session/hot/dispatch/workspace/stack budgets within262144 KES bytes. Host queues and queued bodies do not move onto the device. These checks execute the exact low-level source on host and compile/link it for ARM, but no USB peripheral traffic, flash timing, stack high-water, disconnect, power cut or board execution was observed. The attached A2 board remains disposable-development-only; T022 still requires stock-clock A4-or-later physical feasibility.






## 1. Prerequisites and isolated fixture

- Linux x86_64 primary and a **separate trusted backup/recovery workstation**; external cold-key and offline management workflows. Do not copy their private credentials onto the primary.
- Rust/Cargo1.99.1, target `thumbv8m.main-none-eabihf`, pinned tools in the quality-gate contract. Pico2 A4-or-later at stock clock; one disposable development board and a separately provisioned release qualification board. USB power interrupter for physical fault testing, independently validating testnet peers, and32 disposable pool identities for full capacity.
- Maintainer-approved A2 boards may be used for separately built, unlocked disposable development and exploratory testnet integration with explicit isolated-development opt-in. Never place production keys/trust on A2, use it for mainnet, or irreversibly provision it. Label every A2 result exploratory with actual silicon/mode; it cannot satisfy required A4-or-later physical fault/load/security acceptance. A4 checks execute on the final frozen candidate. The attached board was reported as A2; suitable A4-or-later qualification hardware is still required. This policy does not authorize flashing or OTP mutation by itself.
- Build the **unmodified cardano-cli-11.4.0.0** (`25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`), not an executable inferred from the checkout name. It remains the certificate-issuance, conventional file-key/query tool and independent interoperability oracle; no Cardano CLI source modification is required or permitted by this integration. Build node11.1.3 with its required node/consensus patches separately. Preserve the two dependency graphs and oracle pins in research R1.
- The inspected installed CLI reports11.2.3.1 despite the checkout's11.4.0.0 manifest. Replace neither user's checkout nor binary implicitly; select explicit built paths. `--version` and executable/source hashes must establish the selected baseline before qualification.
- Use a private directory outside version control, `umask 077`, no core dumps, protected-memory support and a local filesystem supporting anonymous/no-replace publication. Generate all disposable secret material at runtime. Never save secret traces/fixtures in this repository.

The implemented `xtask fixture create` command creates a **public scenario declaration only**. It refuses existing output paths (including dangling symlinks), requires exactly 32 controlled-network pool cases and rejects mainnet. It does not start a network, create operational keys, inspect/flash a device or authorize provisioning:

```sh
umask 077
ulimit -c 0
cargo run --locked -p xtask -- fixture create --network controlled --pools 32 --out-dir /run/user/1000/kes-forge-validation
```

Choose an appropriate existing parent directory for the executing UID rather than blindly reusing1000. Only owner-only `manifest.json` is published inside the new `0700` fixture directory; the file is `0600`. The manifest declares 32 case labels, not invented PoolIds or hardware slots. Actual device/pool identities and public keys come from referenced provisioning/enrollment/public workflow outputs. Native baseline references retain T004's explicit unmodified CLI11.4.0.0 and node11.1.3 provenance; execution/freeze must still check the actual executable files and hashes.

Operational paths are separate under a fresh runtime-root name in the host temporary directory, local to each named workstation. They are **not materialized by fixture creation**. Supported workflows and qualification execution create the required files in `0700` directories with private files `0600`, disabled core dumps and protected transient secret memory. Recipient/recovery, cold-authority and management private files never move onto primary; recovery and provisioning must use separate workstations, also separate from primary. The declaration requires explicit authorization for each attended irreversible ceremony and cannot grant it.

The declaration retains operator and qualification executables, independently validating peer, socket, physical power-controller and leader-schedule references. `qualification_executable` is the absolute primary-workstation `kes-foundation-qualification` board adapter consumed by xtask; fixture creation does not install or trust it. Controlled parameters are magic42, 1000-ms slots, 64 slots/KES period and lifetime64; exact Shelley genesis bytes and actual VRF-derived public leadership schedules are execution inputs, not fabricated by the generator. Missing inputs, unsupported custody, unavailable executables or absent physical hardware block the corresponding execution. A4-or-later qualification requirements are unchanged; A2 remains explicitly opted-in disposable exploration only.

An actual CLI smoke created this public-only declaration, observed 32 cases and `0700`/`0600` permissions, found no runtime directory, and rejected existing-output/mainnet retries without changing the prior manifest. The release behavioral suite passed 43 cases after fixture safety coverage. This is not a device/network acceptance result. Define `FIXTURE` as the returned absolute manifest path and `EVIDENCE` as a separate report directory outside operational runtime roots. Environment variables below contain **paths/public metadata only**, never passwords/private-key bytes.

## 2. Build and check the selected executables

For the implemented gate commands below, `XTASK` is one explicitly built absolute qualification-executable path and `CANDIDATE` is the exact directory returned by `xtask freeze` with reviewer-owned definition/approval files. Use the [closed evidence schema](contracts/quality-gates.md#implemented-evidence-cli-and-closed-schema); missing approval or a changed source/tool identity blocks measurement. Product scenarios remain post-implementation instructions, not setup readings.

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
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features release --profile firmware-release
"$CARDANO_CLI" --version
"$CARDANO_NODE" --version
"$XTASK" gate run --candidate "$CANDIDATE" --gate G1
"$XTASK" gate run --candidate "$CANDIDATE" --gate G12
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

`usbDevice` accepts `vid=HHHH,pid=HHHH,serial=ASCII` or `vid=HHHH,pid=HHHH,bus=N,port=N[.N...]`; these pin both the application identity and a stable serial or physical port. `bus=N,address=N` is accepted for attended diagnosis only because addresses change on reconnect. Use the legitimately assigned application-firmware VID/PID, not the RP2350 BOOTSEL ID or an invented production allocation. The runtime must expose one vendor-specific interface with class `ff`, subclass `4b` and protocol `01`, containing exactly one bulk OUT and one bulk IN endpoint. `kes-forged` deliberately rejects BOOTSEL and unrelated vendor interfaces before writing.

Grant only the daemon account or its dedicated device group read/write access to that exact application VID/PID, for example:

```udev
ACTION=="add|change", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ATTR{idVendor}=="HHHH", ATTR{idProduct}=="HHHH", GROUP="kes-forge", MODE="0660"
```

Reload the rules and reconnect the device before starting the service. Replace every placeholder; the literal `HHHH` values are not valid IDs.


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

Expected: a durable staged generation, conventional public key and immutable encrypted artifact; no plaintext device KES key on primary. Device generation is owned by this Rust operator command, with no era/node prefix, old command alias or software fallback. After a lost response or reconnect, query `OP_STATUS` with the exact request ID, generation number and payload identity before deciding whether to retry; never blindly replay a mutation. Resume publication from the committed generation when status is committed, and retry only the exact identity when status says not committed. Changed payload under the same request ID must conflict. A reclaimed terminal result remains `RESULT_RECLAIMED` across reconnect/restart and must never generate a replacement key. Existing unrelated output paths must fail. The unmodified Cardano CLI's software `node key-gen-KES` is exercised separately by the fixture on disposable file-based keys, with no device selected.

Transfer public VK to the existing cold-key workstation. Issue the matching certificate through the unmodified `"$CARDANO_CLI" conway node issue-op-cert` workflow; transfer only the public certificate back. Certify/activate using ordinary configured pool authority:

```sh
kes-forge certify --connection "$POOL_CONNECTION" --generation "$GENERATION_ID" --operational-certificate-file node.cert
kes-forge activate --connection "$POOL_CONNECTION" --generation "$GENERATION_ID" --current-period "$CURRENT_KES_PERIOD"
kes-forge status --connection "$POOL_CONNECTION" --json
```

The fixture computes period from network slot/genesis parameters, never a hardcoded days/epoch value. No management signature/PIN/second operator is needed for these routine operations.

On successful certification, `kes-forge` atomically publishes the canonical public certificate beside the configured daemon socket as `.kes-forge-<connectionName>-<generationId>.operational-certificate.cbor`. Exact retries reuse identical bytes; conflicting bytes for the same generation fail. The running node reads this digest-bound handoff only when authenticated device state activates that generation, then independently checks its KES key, start period and counter before replacing the pool's hot context. It is public certificate material, not a key or a source reload.

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
After reconnect or reboot, reconcile the authenticated device revision before signing or retrying lifecycle work. Catch up directly to a later eligible period and persist only that final state; requesting the current relative period succeeds without a flash write, while any lower relative period is stale and must still fail after reboot. At `P >= S+L`, authenticated observation commits erasure of the active secret and retains current-expired public metadata, its encrypted artifact and any staged replacement. Expiry is not inferred while the device is unpowered.

Treat corruption by scope: an irrecoverable authenticated pool-bank/object inconsistency quarantines that pool while unrelated pool state remains usable; directory, trust-root or entropy-health corruption is device-wide and prevents service. Never restore an older pool snapshot, select another pool implicitly or regenerate an acknowledged backup.

Telemetry scenarios must include two period transitions, staged vs active context, hot rotation, final valid period/expiry, device power cycle, disconnect/reconnect, failed evolution and lost ACK. Independent expectations use certificate/network/time for public validity and confirmed evolution for key-state fields. Preserve names, historical log mappings, zero error sentinels, cadence and legacy aggregation; no telemetry-triggered device mutation. The unmodified `"$CARDANO_CLI" conway query kes-period-info` still works from public certificate/network context while Pico is unavailable.

For host-only diagnostics, capture `kes-forge status --connection "$POOL_CONNECTION" --json` before any completed operation after daemon restart: every `latency` entry must be `{state:"unavailable",sample:null}`. After a validated SIGN or GET_BACKUP, check only its operation entry changes and that admission-to-validation duration includes host queue/USB/verification, rounded up in ms. GENERATE's sample covers the initial IN_PROGRESS acknowledgement, not asynchronous completion. Repeated status/OP_STATUS reads must preserve sample requestId, observedAt and duration while age increases.

With USB/session kept live, pause operational node period observations on the controlled fixture while continuing status reads. At ages <30000ms joined status may be fresh; at **>=30000ms** either confirmed/node-period age makes it stale, `ready=null` and remaining validity null even if STATUS keeps refreshing confirmed device facts. Unavailable joins likewise report readiness null, not false; only a fresh/current join computes boolean readiness from security/lifetime/health. Advance only wall clock and require no freshness extension. A queried latency entry likewise becomes stale at completion age >=30000ms, retaining the original sample. Exercise the exact boundary in the host fake-monotonic-clock tests; physical exercises must not claim millisecond scheduling precision. Resume a matching operational node observation to re-establish the join.

Induce a real admitted request's terminal deadline/USB failure on disposable fixtures. Require its last-completed latency sample outcome `error`, stable `DEADLINE_EXCEEDED`/`DEVICE_UNAVAILABLE` code and bounded duration; no in-progress/requested mutation is confirmed state. Disconnect immediately makes readiness unavailable; an error sample may still display without implying readiness. Session replacement/reboot/daemon restart resets latency samples to unavailable/null and invalidates old readiness; active rotation requires newly matching confirmed and node-period observations, not old-generation replies. Do not alter native KES telemetry/error sentinels to satisfy these separate status exercises. Qualification reports must distinguish unavailable diagnostics from successful hardware measurements.

Query management scope with `kes-forge status --device-config "$DEVICE_CONFIG" --json` as its explicitly mapped caller. Require null `observation`, `ready`, `remainingValidityPeriods` and `latency` rather than borrowing any pool's diagnostics; device security/directory facts remain separate.

## 7. Capacity, persistence, security and custody failures

```sh
cargo run --locked -p xtask -- qualify feasibility --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify interop --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify load --fixture "$FIXTURE" --rounds 10000 --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify power-loss --fixture "$FIXTURE" --cuts 1000 --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify power-loss-software --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify management-software --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify recovery-files --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify security --fixture "$FIXTURE" --evidence "$EVIDENCE"
```

Full scenarios/thresholds are centralized in the quality-gate contract. Include32 active+32 staged, aligned midpoint evolution, background generation with one staged vacancy, status under saturation,33rd registration rejection, replay/cross-pool faults and physical torn writes. A software run or dev board does not pass physical release qualification. Irrecoverable-corruption tests must fail closed and are not counted among successful ordinary power-loss recovery trials.

Foundation feasibility uses three synchronized32-pool rounds to cover aligned evolution, midpoint evolution and activation, plus every named foundational transaction boundary; later commands retain the unchanged larger final counts. The runner performs a read-only hardware inspection before any campaign, accepts stock-clock A4-or-later development hardware for Foundation, requires32 active+32 staged states, physical erase/wear/link/RAM/stack readings and a ready separate power controller, and runs controlled timing plus lost-commit/skipped-erase sensitivity. Its strict NDJSON contains public keys/signatures/timestamps/revisions only; disposable private seeds/states never enter the fixture or evidence. Every returned signature is checked by both pinned native baselines. The currently attached A2 can exercise only explicitly opted-in disposable development and is rejected before physical qualification.

`management-software` is development evidence only. It runs the credential replace/revoke and staged-discard, management-transport credential, interruption-safe deletion/re-enrollment, and interruption-safe device-retirement regressions through authenticated core state and directory/pool codec restart. Its manifest must report `device_transport_status` and `physical_power_cut_status` as `unavailable-not-attempted`; it does not establish daemon/device, concurrent producer, physical cut or release acceptance.

The 2026-10-26 development run passed the management software campaign's five scenarios in 261 ms. The protected no-swap power-loss software campaign passed 99330 ordinary recovery cases, one intentional-corruption case, all 18 modeled transaction boundaries, 32 pool identities and all six operational scenarios; maximum scenario duration was 6382 ms. The first power-loss invocation correctly failed closed outside a fresh `MemorySwapMax=0` unit. These are host-model results only, not physical cuts or device acceptance.


Device-backed management prepare/sign/apply commands are not usable until the management CLI, firmware `MANAGE` dispatch and real daemon USB transport exist. Do not substitute a manually edited envelope or a mock success. When available, prepare only public sequence/revision-bound material on the operational host, sign it only on the offline management workstation, then apply the exact signed scope/action through the management connection. Ordinary pool credentials never authorize credential/recipient changes, staged discard, deletion, retirement or firmware authorization. After an uncertain response, reconcile durable status and replay the exact envelope; never advance the sequence or alter the payload speculatively.
Exercise management credential revocation/replacement, deletion and device retirement while other pools sign, then reboot and replay old authorizations. Replace failed hardware using fresh trust, fresh device-generated KES keys and new matching certificates; no old private-key import. Archive artifacts before their device retention window ends.

Stop the primary producer before starting the conventional backup with the recovered `kes.skey` and same certificate, original Pico disconnected. Independently validate accepted backup blocks in a separate interval. Stop backup before returning to primary. The platform does not provide fencing/failover orchestration; simultaneous forging remains an operator risk.
Credential or recipient changes cannot revoke copied KES secrets or old recipient private-key files. Pool deletion and device retirement erase only reachable device-held state and authorization; they do not erase exported artifacts, offline backups, an unreachable device or an already running conventional producer. A lost or compromised device has no remote-wipe guarantee. Restore service only from an existing protected generation-time backup for its remaining lifetime, or provision fresh hardware trust and generate a fresh KES key with a new matching cold-issued certificate. There is no private-key import, rollback recovery, password-reset bypass or automatic fencing.

## 8. Operator trials and public-network release gates

```sh
cargo run --locked -p xtask -- qualify operators --fixture "$FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify public-network --network preview --fixture "$PREVIEW_FIXTURE" --evidence "$EVIDENCE"
cargo run --locked -p xtask -- qualify public-network --network preprod --fixture "$PREPROD_FIXTURE" --evidence "$EVIDENCE"
```

Provide test delegation/leader opportunities and independent observers. Full-capacity physical qualification and independent security review precede operator-approved mainnet use. Record actual elapsed periods/accepted blocks, separate primary/backup intervals and rotation/recovery. Missing opportunities, hardware or valid gate reports is an explicit blocked qualification, not success.

At completion, remove disposable secret inspection/recovery files from the private fixture workstation under its secure-storage policy; retain only public revision-linked evidence and separately archived legitimate backup artifacts/recipient keys where intended. Do not claim file deletion erases external copied secrets or guarantees physical SSD erasure.
