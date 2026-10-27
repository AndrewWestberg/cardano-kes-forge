# Quickstart: End-to-End Validation

This is a **post-implementation validation guide**, not evidence that all commands/features already exist. The `kes-forged` binary loads the closed daemon configuration, owns the selected KES vendor-bulk interface and serves the protected Unix socket; the operator and product release surfaces remain incomplete. T005/T006 implement candidate freeze, gate dispatch and strict acceptance validation; their setup controls are not application acceptance. The disposable A2-specific development runtime has exercised authenticated USB enrollment, generation, certification, activation, signing, management and retirement. Do not substitute mocks for the device/node in acceptance or run destructive scenarios against production credentials. Exact interoperability, power-loss, security, custody, timing and public-network campaigns remain mandatory.

The implemented build surfaces can be checked without a device:

```sh
cargo run -p cardano-kes-forge --bin kes-forge -- --version
cargo run -p cardano-kes-forge --bin kes-forged -- --version
cargo run -p xtask -- toolchain
cargo run -p cardano-kes-forge --bin kes-forge --no-default-features --features recovery -- --version
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features development --profile firmware-development
cargo build --locked -p kes-firmware --target thumbv8m.main-none-eabihf --no-default-features --features release --profile firmware-release
```

Select exactly one host installation feature (`primary`, `recovery`, `management`, `provisioning`, `development`); the default is `primary`, and only that profile includes the daemon target. Select exactly one firmware feature with the bare-metal target. The generic `development` firmware creates a fresh disposable identity/root on every boot; the separate `a2-development` images use the explicitly initialized persistent disposable identity described below. The product firmware links an ARM slot-A payload with a runtime entry and RP2350 image definition; it is not independently flashable until T044 supplies boot-partition integration. Release deliberately fail-stops pending T041 OTP/security readiness. `usb-preflight` links an unpartitioned disposable image at flash base and implements only the framed vendor-bulk probe. These checks do not establish release hardware security.

### Implemented public management handoff

Use an already authenticated daemon/device configuration. Prepare/apply run on the primary (or isolated development) installation; offline signing requires the separate management installation. The disposable A2 development runtime implements durable management, but the product release dispatcher is not complete. The earlier CLI/socket enrollment smoke used a RAM-only core model; the later physical observations below are separate evidence.

```sh
kes-forge management enrollment-create --device-config device.json \
  --cold-verification-key-file cold.vkey --shelley-genesis shelley-genesis.json \
  --network-magic NETWORK_MAGIC --recipient-public-key-file recipient.json \
  --machine-public-key-file machine.json --incarnation-id FRESH_HEX32 \
  --out-file enrollment.json
kes-forge management prepare --device-config device.json \
  --action ENROLL --payload enrollment.json --out-file enrollment.request.cbor
# On the isolated management installation:
kes-forge management sign --request enrollment.request.cbor \
  --management-key management.private.json --out-file enrollment.authorization.cbor
# Transfer only the signed public authorization back to primary:
kes-forge management apply --device-config device.json \
  --authorization enrollment.authorization.cbor
```

Keep the authorization and adjacent `.kes-forge-management-<request-id>.operation.json` record together. Retry the same apply after uncertain delivery; it reconciles authenticated `OP_STATUS` before redispatch. Do not create a new request to resolve a lost response. Primary cannot run offline signing, and operator commands do not open the daemon's private management-transport credential.

#### Destructive management: exact public payload and scope

These are operator-authorized destructive workflows, not commands to run automatically. **Retirement was exercised on the disposable A2 at device management sequence 2 / revision 12.** The exact retirement replay reconciled after reboot, and its former pool connection was unavailable. That identity's pools cannot be resumed. Because the board is disposable and unlocked, its flash was subsequently erased and a new development identity was initialized; reinitialization does not restore the retired authority or its keys. These observations do not establish the full management scenario (including concurrent producers), physical power-cut behavior, A4/security qualification, network acceptance or release readiness.

On a separately authorized, nonretired disposable device, use the current public device configuration and authenticated status:

```sh
kes-forge status --device-config device.json --json
```

Select one action/scope below; do not run all blocks as a batch. Obtain `POOL_ID` (56 lowercase hex characters), `INCARNATION_ID` (32 lowercase hex characters), the current credential epoch and staged generation from the authenticated status for that exact target. The device target uses JSON `null` for **both** identifiers; a pool target supplies **both** identifiers, even though apply uses the device management connection. There is no `--scope`, `--pool` or `--generation` management CLI flag. Do not put a pool connection or pool transport private key in `--device-config`.

```sh
# Revoke one pool machine credential; NEXT_EPOCH is that pool's current epoch + 1.
export ACTION=CREDENTIAL_REVOKE SCOPE=pool NEXT_EPOCH
export POOL_ID INCARNATION_ID
```

Alternatively, device-scope revocation uses the device's current epoch + 1:

```sh
export ACTION=CREDENTIAL_REVOKE SCOPE=device NEXT_EPOCH
```

**Device-scope revocation cuts off the management transport itself.** Possessing the offline authority does not bypass a revoked transport or provide a public recovery/replacement connection. Do not use it as a rotation procedure; arrange any separately authorized reachable transport before considering this action. A lost response may be impossible to reconcile over the revoked credential.

```sh
# Discard only the currently staged generation (32 lowercase hex characters).
export ACTION=STAGED_DISCARD SCOPE=pool GENERATION_ID
export POOL_ID INCARNATION_ID
```

```sh
# Delete one pool and its device-held generations.
export ACTION=POOL_DELETE SCOPE=pool
export POOL_ID INCARNATION_ID
```

```sh
# Retire the entire reachable device, not just one pool; perform last.
export ACTION=DEVICE_RETIRE SCOPE=device
```

After setting the selected block's variables to reviewed public values, generate its payload in a fresh owner-controlled handoff directory (no group/world-writable ancestry). This standard-library-only helper writes public JSON, not a key or a signature; choose a fresh `PAYLOAD` filename for each new operation:

```sh
export PAYLOAD="$PWD/management.payload.json"
umask 077
python3 - <<'PY'
import json
import os

def fixed_hex(name, size):
    value = os.environ[name]
    if len(value) != 2 * size or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(name + " must be exact lowercase hex")
    return value

def uint(value):
    if not 0 <= value <= 0xffffffffffffffff:
        raise ValueError("credential epoch must fit an unsigned 64-bit integer")
    if value < 24:
        return bytes([value])
    for marker, width in ((0x18, 1), (0x19, 2), (0x1a, 4), (0x1b, 8)):
        if value < 1 << (8 * width):
            return bytes([marker]) + value.to_bytes(width, "big")

action, scope = os.environ["ACTION"], os.environ["SCOPE"]
if scope == "pool":
    pool, incarnation = fixed_hex("POOL_ID", 28), fixed_hex("INCARNATION_ID", 16)
elif scope == "device":
    pool = incarnation = None
else:
    raise ValueError("scope must be device or pool")
if action == "CREDENTIAL_REVOKE":
    text = os.environ["NEXT_EPOCH"]
    if not text or any(c not in "0123456789" for c in text) or int(text) == 0:
        raise ValueError("NEXT_EPOCH must be the target's current epoch + 1")
    payload = b"\xa1\x70credential_epoch" + uint(int(text))
elif action == "STAGED_DISCARD" and scope == "pool":
    payload = b"\xa1\x6ageneration\x50" + bytes.fromhex(fixed_hex("GENERATION_ID", 16))
elif (action, scope) in (("POOL_DELETE", "pool"), ("DEVICE_RETIRE", "device")):
    payload = b"\xa0"
else:
    raise ValueError("unsupported action/scope")
with open(os.environ["PAYLOAD"], "x", encoding="utf-8") as output:
    json.dump({"version": 1, "poolId": pool, "incarnationId": incarnation,
               "canonicalPayload": payload.hex()}, output, separators=(",", ":"))
    output.write("\n")
PY
```

The closed payload-file schema is exactly `{version,poolId,incarnationId,canonicalPayload}`. `canonicalPayload` is lowercase hex of the independently canonical CBOR action map, not hex of JSON or a nested CBOR bytestring. Per the [management contract](contracts/device-protocol.md#exact-management-and-signed-transcript-schemas), revoke encodes `{credential_epoch: U}`: `a1` (one-entry map), `70` (16-byte text key), UTF-8 `credential_epoch`, then the shortest unsigned integer encoding. For epoch 1 it is `a17063726564656e7469616c5f65706f636801`; use the actual next epoch, not that example unconditionally. Discard encodes `{generation: B16}`: `a1`, `6a`, UTF-8 `generation`, `50`, then the exact 16 generation bytes. Delete and retire encode the empty map `a0`. No private material is needed to generate any of these bytes.

Use fresh request/authorization filenames for the selected operation:

```sh
# Operational installation: binds the exact target/action/payload to authenticated
# current revision, next management sequence, device ID and a fresh request ID.
kes-forge management prepare --device-config device.json \
  --action "$ACTION" --payload "$PAYLOAD" --out-file management.request.cbor --json

# Transfer the public request to the isolated management workstation.
# Review device, action, target/incarnation, generation or epoch, sequence and revision.
# Management installation only; the private authority never leaves this workstation:
kes-forge management sign --request management.request.cbor \
  --management-key management.private.json --out-file management.authorization.cbor --json

# Transfer only the signed public authorization back to the operational installation:
kes-forge management apply --device-config device.json \
  --authorization management.authorization.cbor --json
```

The JSON payload, request, authorization and operation record contain public management material; keep their integrity and archive their exact bytes as public evidence. The signed authorization is an executable authorization, not a secret key: transfer only to its intended operational host. Neither the offline management private key, daemon-owned management transport private credential, pool machine private credential, recipient private key/password nor recovered KES key belongs in this handoff. The operator CLI uses the protected daemon connection; it does not read transport private keys.

**Uncertainty and retry:** preserve the authorization with its adjacent `.kes-forge-management-<request-id>.operation.json` record. After a timeout, disconnect, daemon restart or reboot, rerun the **same apply command**, with the same bytes and record in place. A resumed apply first performs authenticated `OP_STATUS`; committed results return the recorded sequence/revision without repeating the mutation. Only authenticated `NOT_COMMITTED` permits redispatch of the identical authorization. `UNKNOWN`, `IN_PROGRESS`, unavailable transport and deadline expiry are not evidence of noncommit. `RESULT_RECLAIMED` or a conflict is not success and does not authorize inventing a replacement request. Do not delete the record, increment a sequence/epoch, alter a generation or re-prepare merely to resolve a lost response. A genuinely new action requires reconciled current authority and fresh prepare/sign; concurrent state changes can invalidate a previously prepared revision.

**Durable consequences:**

- Credential revocation increments the selected scope's epoch, persists revoked policy and invalidates that scope's sessions; old machine credentials cannot reopen it after reboot. Pool revocation does not retire its KES generations or delete other pools. Device revocation blocks ordinary management OPEN and is not device retirement.
- Staged discard removes only the named current staged generation and its device-held secret/object retention; it must not remove the active generation. It is not a way to cancel or roll back the active key. Archive any needed immutable backup before discarding; copied artifacts are unaffected.
- Pool deletion cleans that pool's device-held active/staged state and objects, denies its former credential/incarnation and retains a deletion tombstone/replay and certificate high-water history. It does not delete other pools or reset history. Re-enrollment is a new signed `ENROLL` with a fresh incarnation, fresh machine credential and fresh device-generated KES key/certificate, not reuse of the deleted connection or private-key import.
- Device retirement cleans all reachable device-held pool state and durably denies pool service after reboot. It is terminal service retirement, not a factory reset, authority reset or reusable blank device. Retained management reconciliation evidence supports exact retirement retry; it does not restore pool service.

None of these actions erases a copied backup artifact, recipient private key/password, exported KES state, an unreachable/lost device or an already running conventional producer. Recipient replacement cannot re-encrypt old immutable artifacts or revoke their old recipient key. Without an existing generation-time artifact **and** its matching recipient private key/password, there is no recovery or password-reset bypass. An existing backup restores only that generation's remaining valid lifetime on a conventional producer; fresh hardware requires fresh trust and device-generated keys with a matching cold-issued certificate. Stop/fence the old producer separately before backup forging: this platform offers neither remote-wipe guarantees nor automatic fencing.

### Public device and pool status

```sh
kes-forge status --device-config device.json --json
kes-forge status --connection pool.connection.json --json
```

Choose exactly one source. All primary operator workflows now load public connections without opening daemon transport private credentials. Device-directory status has null pool observation/readiness/remaining-validity/latency fields. Pool status joins actual daemon observations: both ages must be below30000ms, while missing node data, disconnect, unresolved mutations or a changed session make readiness unavailable immediately. Stale/unavailable readiness and remaining validity are null, not false/zero. A freshly authenticated committed expiry can instead report `ready:false, remainingValidityPeriods:0`.

An authenticated status reporting unavailable health restricts readiness; a later healthy status can remove that restriction only while the original matching confirmed and node-period observations remain fresh. Status reads do not refresh their timestamps. A confirmed observation cannot roll the same generation's relative period backward, even if it carries a higher pool revision.

The exercised physical smoke made two real CLI requests through the daemon and authenticated USB to the attached disposable A2 development image. It confirmed development mode, unverified release evidence, null management-scope pool diagnostics and absence of an operator transport-private-key file. It neither flashed nor wrote OTP. This is an A2 status-path observation, not durable pool service, timing or release qualification.

### Role-separated host package staging

The packaging command builds one exact feature with locked dependencies and default features disabled. Use a fresh destination beneath a trusted owner-controlled parent, not a group-writable checkout:

```sh
cargo run --locked -p xtask -- package --workspace "$PWD" \
  --profile management --out-dir "$HOME/kes-forge-management-package"
cargo run --locked -p xtask -- package --workspace "$PWD" \
  --profile recovery --out-dir "$HOME/kes-forge-recovery-package"
```

The staged executable must report the exact complete role surface through `--installation-profile`; packaging rejects missing handlers or forbidden role capabilities before publishing a distributable manifest. Only primary includes `kes-forged`. No configurations, private keys, prototype USB rules or operator credentials are copied. Install legitimate allocated USB IDs and least-privilege rules through a separately approved administrator workflow. No build/package command flashes, resets or provisions hardware.

The public manifest hashes staged executables and Cargo inputs and explicitly makes no release-readiness claim. A failed build/validation can retain its owned incomplete staging directory; use a fresh path for retry rather than overwriting it. Management, recovery and development profiles have been staged successfully; the development package includes `dev inspect`. Full primary and provisioning packaging still depend on their missing firmware-update and attended-apply command surfaces, respectively.

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

`kes-a2-development` is an unlocked disposable RP2350 A2 image implementing challenge-signed INFO, Ed25519-authorized HPKE OPEN, authenticated management enrollment, pool STATUS and operation reconciliation, cooperative KES generation, immutable backup retrieval, certification, activation, evolution and signing. It requires a separately initialized persistent development identity; ordinary startup fails closed if identity is missing or damaged. The root is plaintext flash and exposed to debug/BOOTSEL: **never use production keys, trust or mainnet on this board**. The boot nonce is fresh per boot. A blank device reports `persistence=identity-only`; an explicitly provisioned directory reports `persistence=identity-and-enrollment`. Release security is not available in this image.

The physical A2 passed the JEDEC/SFDP guard, one-time identity and directory provisioning, three signed enrollments, per-pool authenticated sessions and interleaved operation-status requests. A third pool with a public disposable recipient fixture generated and certified a KES key, activated it, evolved it to period 1 and produced a signature verified independently by the host; altered-message verification failed. The evolved state signed again after reboot. Repeated backup fetches matched byte-for-byte, and host recovery verified the device signature and decrypted the 608-byte period-zero key against its verification key before and after reboot. USB-reset session invalidation also passed. These are exploratory results, not A4 release qualification or the complete daemon/CLI workflow.

After separate authorization to modify disposable board flash, build both images:

```sh
cargo build --locked -p kes-firmware --bin kes-a2-identity-initialize --bin kes-a2-development \
  --target thumbv8m.main-none-eabihf --no-default-features \
  --features a2-development --profile firmware-development
```

Hold BOOTSEL while reconnecting the board and identify its current bus/address. Load the initializer without erasing the entire flash; the linker prevents its image from overlapping the journal and identity regions:

```sh
target/picotool/picotool load --ignore-partitions -v -x \
  target/thumbv8m.main-none-eabihf/firmware-development/kes-a2-identity-initialize \
  -t elf --bus BUS --address ADDRESS
```

The initializer does not write identity on boot. Only after explicit disposable-initialization authorization, run:

```sh
KES_A2_AUTHORIZE_DISPOSABLE_IDENTITY_INITIALIZATION=yes \
  cargo test --locked -p cardano-kes-forge --test a2_identity_hardware \
  -- --ignored --exact authorized_disposable_identity_is_initialized_once_and_read_back
```

It initializes exactly once from the onboard health-checked TRNG and reports public identity keys only. It refuses nonblank journal/identity regions, torn identity records and repeat initialization; it never erases, imports a root or writes OTP. If initialization was interrupted, stop instead of retrying or erasing existing state. A physical power cycle has not been qualified. An initializer already running on the A2 can return to BOOTSEL without pressing the button:

```sh
cargo test --locked -p cardano-kes-forge --test a2_identity_hardware \
  -- --ignored --exact disposable_initializer_can_return_to_bootsel
```

To provision a blank disposable directory, first create a separate management authority using the management installation profile. The hardware test below accepts its public file and installs that root together with the publicly known A2 test transport credential. This transport credential is deliberately insecure and must never be used for production:

```sh
cargo run --locked -p cardano-kes-forge --no-default-features --features management \
  --bin kes-forge -- authority key-create --role management \
  --public-key-file /absolute/protected-lab/management-public.json \
  --private-key-file /absolute/protected-lab/management-private.json

KES_A2_AUTHORIZE_DISPOSABLE_DIRECTORY_PROVISIONING=yes \
KES_A2_MANAGEMENT_PUBLIC_KEY=/absolute/protected-lab/management-public.json \
  cargo test --locked -p cardano-kes-forge --test a2_directory_hardware \
  -- --ignored --exact authorized_disposable_directory_is_provisioned_once
```

The directory operation requires valid public keys and entirely erased directory and pool regions; it refuses repeat initialization, damage and nonblank state. Preserve the private authority separately from public handoffs. An interrupted or already-provisioned directory must not be reset implicitly.

Build it without enabling the slot-A product image:

```sh
cargo build --locked -p kes-firmware --bin kes-a2-development \
  --target thumbv8m.main-none-eabihf --no-default-features \
  --features a2-development --profile firmware-development
```

The initializer's explicit reboot command above returns to BOOTSEL; use the newly enumerated bus/address after it appears. The authenticated development image likewise exposes a disposable-only vendor reset exercised by `disposable_development_can_return_to_bootsel` in `tests/a2_development_hardware.rs`. `picotool load` uses PICOBOOT and does not need the RP2350 A2 E10 UF2 mass-storage workaround. After separate flash authorization, this command replaces the disposable image and does not write OTP or intentionally erase the journal/identity regions:

```sh
target/picotool/picotool load --ignore-partitions -v -x \
  target/thumbv8m.main-none-eabihf/firmware-development/kes-a2-development \
  -t elf --bus BUS --address ADDRESS
```

Run the direct physical behavior case or the public T048 development-evidence runner:

```sh
cargo test --locked -p cardano-kes-forge \
  --test a2_development_hardware -- --ignored --exact \
  authenticated_a2_info_open_status_fail_closed_and_reopen

cargo test --locked -p cardano-kes-forge \
  --test a2_development_hardware -- --ignored --exact \
  usb_bus_reset_invalidates_authenticated_session

cargo run --locked -p xtask -- qualify security-modes \
  --hardware yes --evidence /absolute/public/evidence/directory
```

The persistent-identity image passed INFO/OPEN/STATUS and invalid-MAC checks on hardware before directory provisioning. Its USB bus-reset regression passed after invalidation was moved into the USB reset callback; an exact enrollment retry also survived a bootrom reboot. These are disposable development observations, not a physical power-cut test. The runner always records `release_qualified=false` and defers secure boot, debug locks, DMA isolation, OTP, signed update/rollback and post-lockdown service to T109 on A4-or-later hardware.

#### Protected current-state inspection

Stop the daemon so the disposable device can be claimed directly. Build the separate development profile and run it on the trusted development workstation in a fresh cgroup-v2 unit with swap disabled and core dumps prohibited:

```sh
cargo build --locked --no-default-features --features development --bin kes-forge \
  --target-dir target/a2-development-host
systemd-run --user --pipe --wait --collect --quiet \
  -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" \
  "$PWD/target/a2-development-host/debug/kes-forge" dev inspect \
  --connection "$POOL_CONNECTION" --usb-device "$A2_USB_SELECTOR" \
  --generation "$GENERATION_ID" --allow-development --out-file "$PROTECTED_DIRECTORY/current.kes-dev"
```

The pool connection must use `isolated-development`, the enrolled pool credential and a pinned device identity. The output directory must be owned by the caller and private; publication is no-overwrite and produces a `0600` file. The A2 exercise extracted the active disposable state at relative period 1, then independently verified its public key and signature; missing opt-in and output overwrite were refused. `KESDEV01` contains the **current secret state**, not the initial encrypted backup or an import format. It is absent from release firmware and normal node sockets. Removing a file does not guarantee erasure of retained copies; never inspect production keys.

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

On the attached RP2350 A2/QFN60, raw OTP `FLASH_DEVINFO` and its enable flag are zero; the ROM's `0x0c00` is the default 16-MiB encoding, not a measured flash size. `picotool` estimated 4 MiB by address aliasing. Firmware now reads JEDEC and SFDP directly and the A2 passed the approved 4-MiB check before identity, directory and pool-journal writes. The identifiers do not establish physical marking or endurance. No physical power-cut, timing or endurance qualification exists, and A2 cannot satisfy the required A4-or-later campaign.

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

### Host-only 32-pool load control

Build the qualification binary, then run the software load control in a fresh no-swap, non-dumpable unit. The two pinned native oracle driver identities must already exist as described above. Choose a fresh evidence directory; existing log/manifest paths are never overwritten.

```sh
cargo build --locked -p xtask --bin xtask
systemd-run --user --pipe --wait --collect --quiet \
  -p MemorySwapMax=0 -p LimitCORE=0 -p WorkingDirectory="$PWD" \
  "$PWD/target/debug/xtask" qualify load-software \
  --evidence "$PWD/target/foundation-load-software"
```

The command executes 160 maximum-4096-byte requests across 32 fresh real core pools: aligned evolution, period 31→32, replacement activation, and two signing waves interleaved with 64 actual generation leaves. Initial load has 32 active plus 32 staged generations; background generation starts with exactly one staged vacancy. Every signature is verified locally and by both pinned native releases; journal recovery checks all 32 pool identities and final active/staged states.

`software-load.log` retains bounded public per-request admission, dispatch, verified-completion and original admission-plus-500-ms deadline readings. `software-load.json` checks those records against the measured summary. `verified_completions` includes late verified results; only `timely_usable_completions` excludes deadline misses. Native verifier subprocess startup is included, unlike in-process node verification. A `software-pass` establishes software-control correctness only, never the P1 timing threshold, USB behavior, physical flash or A4 readiness. Rust type sizes are reported separately from unmeasured physical RAM/stack high-water.

The same protected-unit launcher is required for `qualify power-loss-software` and `qualify management-software`. A plain terminal invocation does not establish the secret-memory prerequisite.







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

On Linux, run recovery commands in a fresh cgroup-v2 unit with `MemorySwapMax=0` and `LimitCORE=0`. The CLI verifies both the zero swap limit and zero current usage before reading a passphrase; it fails closed if that protection is unavailable. For an interactive recovery workstation, start a protected shell and run the commands inside it:

```sh
systemd-run --user --pty --wait --collect -p MemorySwapMax=0 -p LimitCORE=0 /bin/bash
```


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

Build one mixed bulk file with at least one legacy file-backed tuple and one explicit forge object using the executable examples in the [node contract](contracts/node-integration.md). Start **one** actual node with approved network inputs:

```sh
"$CARDANO_NODE" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$NODE_DB" --socket-path "$NODE_SOCKET" --bulk-credentials-file "$MIXED_BULK"
```

The mixed-node and telemetry qualification runners are not yet implemented. Use the actual node commands and credential-file construction in [the node contract](contracts/node-integration.md) for manual development exercises; do not treat a node startup or local signature as accepted-block or telemetry qualification. T066 and T088 remain open.

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

The local recovery-file campaign is available as `xtask qualify recovery-files --fixture FILE --evidence DIR`. Its closed JSON fixture contains `recovery_cli`, `lab`, `artifact`, `recipient_key`, `password_file`, `device_identity`, `verification_key`, `expect_device`, `expect_pool`, `expect_generation` and `separate_workstation_declared`; all paths are absolute, the lab is an empty owner-only directory, and the password file is owner-only with no newline. Run it in a fresh no-swap unit, with a genuine matching disposable artifact and recipient. The runner records public case hashes and simulated terminal-barrier interruptions; it explicitly reports recipient replacement and separate-workstation proof as unavailable rather than claiming T049 completion. Recovered plaintext outputs exist only in the protected lab and must be removed under the workstation's disposal policy after inspection.

`xtask qualify interop --fixture FILE --evidence DIR` runs the protected offline native comparison with an A2-generated artifact, recovered signing key, actual cold-signed certificate and independently supplied public pins. Its closed JSON fixture uses the `Inputs` fields in `xtask/src/qualify/interop.rs`; fixed-size identifiers and keys are arrays of bytes, paths are absolute, and `disposable_lab_authorized` must be true. Run in a fresh no-swap unit. It publishes `interop.json` without private hashes or key material; live device/network checks and unmodified CLI executable issuance remain separate obligations.


The disposable A2 development runtime supports durable signed enrollment, pool credential and recipient changes, staged discard, pool deletion and device retirement. Recipient replacement, management transport replacement, deletion, reboot reconciliation, fresh-incarnation re-enrollment and final retirement have been exercised through the real daemon and CLI. **Retirement committed at device management sequence 2 / revision 12; exact replay survived reboot and the former pool connection was unavailable.** The same disposable board was then erased, given a new development identity and directory, enrolled at sequence 1, and generated, certified and activated a fresh key; a real device SIGN returned 448 bytes that independently verified, an altered message was rejected, and status reported a fresh observation with readiness true. It then evolved to relative period 1 (revision 5) and signed there with independent verification; after a device reboot and daemon restart the persisted period 1 state signed again, with status again fresh and ready. The board is therefore reusable, while the retired identity and its keys are not. This is not completion of the full concurrent-management scenario, a physical power-cut campaign, A4/security/network acceptance or a release claim. Product release firmware and signed firmware update are not complete. Follow the exact public payload, prepare/sign/apply, scope and uncertainty workflow in [Destructive management](#destructive-management-exact-public-payload-and-scope). Ordinary pool credentials never authorize credential/recipient changes, staged discard, deletion, retirement or firmware authorization.

After a disposable A2 management credential rotation, hardware regression tests can use the actual daemon-owned replacement fixture without changing the initial-credential bootstrap:

```sh
KES_A2_MANAGEMENT_CONFIG=/private/lab/device-next.json \
  cargo test --locked --test a2_development_hardware -- --ignored \
  --exact authenticated_a2_info_open_status_fail_closed_and_reopen
```

Run secret-bearing tests in the protected no-swap laboratory described above; never use these public qualification fixtures for production.

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
