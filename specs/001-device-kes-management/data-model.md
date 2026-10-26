# Phase 1 Data Model

Normative design for [spec.md](spec.md). Protocol encodings are in [device-protocol.md](contracts/device-protocol.md); host/backup file rules in [cli-backup.md](contracts/cli-backup.md). Fields marked secret never enter ordinary response structures, logs or fixtures.

## Shared types and identity

- `DeviceId`: 16 random bytes, bound to pinned device Ed25519 identity key and provisioning evidence.
- `PoolId`: BLAKE2b-224 of the registered 32-byte cold verification key; full 28 bytes, not a user label or slot index.
- `IncarnationId`, `GenerationId`, `RequestId`: independent 16-byte random identifiers. A hardware slot 0–31 is only an internal location. Identity does not change when another slot is deleted.
- `Revision`, generation number, management sequence, credential epoch, certificate counter and absolute period: checked unsigned 64-bit integers. Overflow is an explicit failure, never wraparound. Relative period: 0–63.
- `NetworkBinding`: network magic, SHA-256 of exact enrolled Shelley genesis bytes, `slots_per_kes_period > 0`, `1 <= max_kes_evolutions <= 64`. The genesis digest is the platform's enrollment binding, not a claim to equal the node's differently encoded genesis-hash type. Nodes compare the exact enrolled parameters and identity before use.
- Fixed 32-byte verification keys; 448-byte Sum6KES signatures; 608-byte canonical signing state. Algorithm/version identifiers are explicit at persistence/file boundaries.

### Checked implementation boundary

`kes_core::types` implements these public identities as distinct fixed-width types with no implicit defaults or slot/label conversion. Creation consumes fresh caller-supplied fallible cryptographic entropy; decoding exact public bytes is separate from authenticating enrollment. `DeviceIdentityBinding` associates the ID, identity verification key and provisioning-evidence digest but is explicitly not provisioning/readiness proof. INFO alone cannot establish a trusted pin.

The six durable counter types expose checked addition/increment without wraparound. `RelativePeriod`, `HardwareSlot` and `KesLifetime` have separate bounds. `EnrolledGenesisHash` uses SHA-256 of exact bytes, never JSON normalization or the native node's hash encoding; enrollment must additionally validate the actual genesis structure and parameters. Pool identity reuses pinned no_std `blake2 0.10.6` with the BLAKE2b output size parameter set to 28, not a truncated 512-bit digest.

Six behavioral boundary cases passed, including the public cold-VK vector independently produced by unmodified CLI11.4.0.0 and exact-byte SHA-256 observations. The core checked on `thumbv8m.main-none-eabihf`; a separate compiled host consumer matched both hashes, rejected counter overflow/relative64 and refused real entropy EOF without fallback. These are shared-type/API checks, not cryptographic state, firmware execution or release qualification.

### Cryptographic implementation boundary

`kes_core::crypto::KesKey` owns fixed zeroizing state plus immutable enrolled `KesLifetime`; ordinary request fields cannot extend it. `CanonicalState` is a non-Debug borrowed secret view with explicit algorithm1 (Sum6KES/Ed25519/BLAKE2b-256), schema1 and separately checked relative period. Only its exact608-byte body goes into conventional Cardano key serialization; neither Rust period nor enrollment metadata is appended. Unsupported identities/schema, suffixed612-byte inputs and period/state disagreement fail closed. This internal restore/interop API is not a device private-key import operation.

Generation borrows caller-owned output/tree buffers with independent lifetimes and consumes fresh caller-supplied entropy; completion releases the key while retaining an immutable verified cache. Signing borrows the exact bounded message and writes a caller448-byte signature buffer. Forward/no-op/backward and shortened-lifetime rules are explicit. Out-of-lifetime refusal leaves the candidate unchanged; it is not committed expiry. The transaction owner must persist erasure and retain public expired-generation metadata before acknowledging expiry. Hardware entropy, session authorization, slot routing and durable cleanup are not established by a primitive operation.

### Shared state implementation boundary

`kes_core::state` separates a compact hot `Device` directory from the single cold `DirectorySnapshot` workspace. Live plus retained identities are bounded together at32 with explicit full failure, never eviction or reset. Full cold registrations/generations must not become a32-element resident firmware array: secret banks, certificates and staged trees use research R4's shared workspace. Trusted `Actor` values are internal authorization context, not an authenticated wire capability. `VerifiedReleaseReadiness` has no public constructor; a development/release label or public evidence tuple cannot authorize production.

`PoolRegistration` and `KESGeneration` own their secret/public record fields; generation records retain only immutable public-object references and artifact digests after the tree workspace is released. Fixed `GenerationSecret` storage delegates to the key's explicit live/erased marker and zeroizing owner, without Clone/Debug/serde or allocator/boxing. Staging is a RAM candidate only, not a durable publication acknowledgement. Its captured policy binds pool/incarnation, recipient identity/policy epoch and credential epoch, not an ordinary revision that may change while generation runs.

The public object is exact `header || tree || encrypted_backup`, maximum6144 bytes. All multibyte header integers are big-endian:

| Byte range | Meaning |
|---|---|
| 0–7 | `KESPUB01` |
| 8–9 | u16 format version1 |
| 10–25 | GenerationId16 |
| 26–27 | u16 tree length4064 |
| 28–29 | u16 encrypted-backup length, at most2048 |
| 30–31 | Reserved zero |
| 32–4095 | 127 BFS public hashes, each32 bytes |
| 4096–end | Immutable already-encrypted backup producer output |

`PublicObjectRef` binds version, generation, exact total length and SHA-256 of the entire object. Parsing checks that reference, the expected VK and all63 parent hashes, rejecting trailing/unknown/reserved/malformed bytes. Only an authenticated secret snapshot can authenticate the reference; an attacker-supplied matching digest is not authority. Backup magic/map identification here does not verify its signature, HPKE or closed schema.

### Certificate implementation boundary

`kes_core::certificate::OperationalCertificate::decode_and_verify` owns only an exact canonical certificate, at most154 bytes, after strict cold Ed25519 verification over `hot_vk32 || counter_u64_be || start_u64_be`. It preserves bytes/digest and typed counter/start; public key getters borrow validated offsets rather than copying extra key/signature arrays. The old unchecked field constructor and state-module certificate aliases are removed. Canonical borrowed CBOR now lives once in `kes_core::cbor`; protocol framing/schema retains its own transport errors and converts the lower codec errors.

`validate_bound` separately checks cold/PoolId/KES identity, the entire enrolled/request network tuple, enrolled lifetime and strictly greater last-activated counter. Network is not signed into the certificate. `LifetimeWindow` uses checked `S+L` and half-open `S <= P < S+L`; it does not establish an authenticated current period.

Pool `certify` checks trusted caller scope and network, validates a new staged binding before mutation and advances only the pool revision/lifecycle, never the activated counter high-water. Exact bytes for an already-certified generation are idempotent even with an older retry revision; an impossible future revision fails. Different recertification fails without replacing current/staged key or immutable object data. `DurablePool::certify` persists a newly applied result through journal CLEAN before returning; an exact duplicate performs no write.

### Secure runtime implementation boundary

The firmware runtime uniquely owns fitted flash, RP2350 TRNG, derived keys and one secure gateway. The gateway contains fixed 8192-byte request and response buffers: a nonsecure caller supplies only an exact bounded slice for one copy in, and receives one bounded copy out. Secure state never retains the caller's slice. Every transaction drop zeroizes both buffers and restores the single-flight idle state. This safe ownership contract does not itself configure or prove SAU/MPU/ACCESSCTRL isolation; T041 owns that physical boundary.

The OTP root remains a 32-byte secret input to HKDF-SHA256 with DeviceId salt. Versioned labels derive independent storage root, session root and device-identity seed owners. None implements Debug, Clone or serialization. Development replaces OTP persistence with a fresh identity/root on every boot and is explicitly disposable. Release currently fail-stops before operation rather than using ephemeral material; only verified T041 OTP provisioning and security policy may enable it.

Entropy acquisition owns the TRNG, read-verifies sample count 200/one-inverter configuration with all three hardware tests enabled, and returns only after collecting credited hardware blocks. Generation and session each receive a newly seeded ChaCha20Rng from fresh 256-bit input under different derivation labels. Health failure or bounded timeout is sticky until reboot; time, USB data and previous pseudorandom state are never substitutes.

### Authenticated session implementation boundary

`kes_core::session` signs challenge-bound INFO responses against the pre-enrolled device identity pin; a key returned by INFO is never its own trust root. OPEN uses RFC9180 base mode with X25519/HKDF-SHA256/ChaCha20-Poly1305 and binds device, unpredictable boot nonce, pool/incarnation or management scope, credential epoch, per-scope open counter and request ID before decapsulation. The machine Ed25519 signature covers that tuple plus encapsulation and ciphertext. Separate exporter keys authenticate the challenge acknowledgement and exact OPEN response envelope before the host installs a session.

Each established scope owns separate strict request and response u64 sequence spaces and zeroizing HMAC-SHA256 keys. Any replay, skip, exhaustion, bad MAC, wrong device/scope/session/request binding, credential epoch change or revocation invalidates that scope. Disconnect and reboot clear the fixed table. Replacement affects only the same scope; capacity is exactly32 pool sessions plus one management transport session, with compile-time record/table SRAM ceilings of256/8448 bytes. A management transport session establishes machine connectivity only: mutation still requires the separately verified management envelope and trusted internal `Actor`.

### Initial durable lifecycle and dispatch boundary

`kes_core::activation::DurablePool` owns the sole decoded live registration paired with its authenticated `ReadyToken`. First activation accepts only a matching certified-staged generation when no active generation exists, checks certificate/object/lifetime bindings, evolves to the eligible relative period, advances certificate high-water and persists through predecessor cleanup and CLEAN before returning context. Forward evolution persists only a strictly newer period; a same-period request is a no-write success and a lower period is rejected without invalidating the usable owner. Any journal failure wipes resident generation secrets and makes the owner unusable until authenticated recovery.

`DurablePool::sign` performs required forward evolution first, so no signature can use a successor before durable cleanup. It signs the exact borrowed message, independently verifies the 448-byte result against the retained VK/lifetime/period and only then returns the signature and SHA-256 message digest. The protected exhaustive lifecycle regression covers every eligible relative period 0–63, same-period no-write behavior, stale refusal, half-open expiry refusal and durable revision progression. Committed expiry/public-metadata retention remains T072; replacement activation and scheduling remain T081/T082.

`firmware::usb::UsbDispatcher` owns one 8192-byte nonsecure receive buffer; the secure gateway owns one 8192-byte request and one 8192-byte response buffer. Framing metadata is separate, so incoming bytes are parsed from caller-owned storage and the exact body is copied once into secure storage. The deterministic request envelope and signing message remain borrowed in place. The dispatcher is statically allocated on core0 rather than placed on either core's stack; host services own all queued bodies.

The fixed scheduler stores deadlines/leases only. SIGN uses the original remaining `min(budget,500 ms)`, status/INFO/OPEN are capped at 2 seconds and GENERATE at 10 minutes; none resets after admission. Exactly one global generation lease exists and each scheduler turn invokes exactly one caller-owned leaf step. Compile-time constants account the R4 262144-byte KES ledger, including 24576 frame bytes, 8448 session bytes, 8192 hot metadata, 4096 dispatch metadata, 32768 shared crypto workspace, 8192 journal workspace, 16384 combined stack and 7936 margin. These are enforced design ceilings, not measured peak high-water results.




## Entities

| Entity | Fields and relationships | Ownership/validation |
|---|---|---|
| Device | identity/public key, silicon revision, firmware digest/security version, hardware-policy digest, mode, health, directory revision, management root public key, pool directory | OTP roots and derived storage/identity/session keys are secret; production operations require verified release readiness, not merely `mode=release`. |
| PoolRegistration | pool ID, incarnation, cold VK, network binding, credential public key/epoch/revoked flag, recipient public key/ID, management sequence, last management request digest/result, generation counter, certificate high-water mark, active/staged references | At most 32 live registrations. Management signs enrollment and changes; normal pool authority cannot change recipient/credential/network or delete registration. |
| PoolTombstone | pool ID, last incarnation, management sequence, certificate/generation high-water marks, deletion revision | Persists after deletion. Re-enrollment requires management authorization of fresh incarnation and retained history. Directory full fails explicitly; no silent eviction/reset. |
| KESGeneration | generation ID/number, creation request ID/digest, pool/incarnation, VK, relative period, secret state or erased marker, state, public-object digest, backup digest/recipient ID, optional certificate | At most one active/current-expired plus one staged generation. Staged generation cannot overwrite another. Generation completion merges into latest pool revision, not the active-state snapshot at job start. |
| OperationalCertificate | canonical certificate bytes, cold VK, KES VK, counter, start period, digest | Verify cold signature over the release's OCertSignable bytes, cold identity, VK and counter. Network is NOT a signed opcert field; network binding is separately enforced by enrollment/session/request. Counter is strictly greater than the last activated counter for a new generation; exact duplicate certification is idempotent. |
| ActivationIntent | target generation, certificate digest, absolute activation period, creation request ID, expected active generation, committed revision | Pool-authorized, durable, no offline approval. Period must be at/after certificate start and before expiry. Executes only on an authenticated eligible node period. Preserve on daemon/device/node restart. |
| PublicObject | version, generation ID, 4064-byte public tree, encrypted backup bytes, lengths and digest | Contains no plaintext secret. Immutable while referenced. Authenticate through the secret snapshot. Write and read-verify before publishing the generation. |
| BackupArtifact | version/suite, device/pool/incarnation/generation/VK, recipient ID, HPKE encapsulation/ciphertext/tag, device signature | Created once from period-zero state; identical bytes retained across evolution/reboot/recipient changes. Retrieval only for staged, active or current expired generation. Archive before replacement reclaims it. |
| RecipientKeyFile | format/KDF parameters, public key/ID, salt, nonce, encrypted private key, tag | Backup workstation only. Keypair remains unchanged on password change. Password and unlocked key are transient secret memory. Pico/primary stores only public enrollment data and encrypted artifact. |
| PoolConnection | socket, expected device identity, pool/incarnation, credential reference, network binding, security policy | Host configuration, never a decryption credential. OS ACL plus per-pool device authentication. Multiple processes may use configured pool connections; daemon serializes each pool's signing/lifecycle work. |
| SigningAttempt | request ID, active generation, pool/incarnation, certificate digest, absolute/relative period, exact message bytes, message digest, monotonic service-admission time/deadline | Immutable once admitted; result must match every identity field, verify independently, and arrive before deadline. No durable mutation for an ordinary current-period signature. One admitted attempt per pool, 32 total; bodies remain on the host until single-flight device dispatch, whose budget is only the original remaining time. |
| ConfirmedObservation | boot/session identity, pool/incarnation, generation, certificate digest, revision, confirmed relative period, health, host UTC observation time and monotonic observation instant | Host-only cache derived from normal acknowledgements/status. Reject lower revision and retired-generation updates. A requested target is never an observation. Retain invalidated facts only as historical, not current readiness. |
| NodePeriodObservation | device/boot/session/pool/incarnation/network/active generation/certificate context, absolute node period, host UTC receipt time and monotonic receipt instant | Only authorized native operational SIGN/EVOLVE/OBSERVE_PERIOD contexts update this host-only record. Operator activation inputs and STATUS do not refresh it. Remaining-validity joins require matching confirmed state and both ages <30000 ms; age >=30000 ms is stale. Missing context, disconnect/reboot/session replacement/restart or unresolved mutation makes readiness unavailable immediately. No persisted telemetry or device wall clock. |
| OperationLatency | pool, operation, request ID, duration milliseconds, outcome/code, UTC completion timestamp, monotonic completion instant, boot/session/generation context | One RAM-only last-completed sample for each of eight fixed operations per live pool (32×8 maximum), per device-protocol.md; no request body or secret. Integer duration rounds up from original service admission through daemon validation or terminal failure. Fresh for age <30000 ms, stale at >=30000 ms; no sample or daemon restart/session replacement is unavailable/null. STATUS/OP_STATUS reads never overwrite or refresh samples. |
| ManagementEnvelope | device, scope, incarnation, operation, sequence, request ID, expected revision, payload digest, offline signature | Canonical domain-separated encoding; replay sequence survives reboot. Exact last duplicate returns recorded outcome; lower sequence or changed payload fails. Firmware-signing authority is distinct from this management authority and pool cold authority. |
| DevelopmentInspection | device/pool/incarnation/generation, relative period, raw current state | Development-only protected file on trusted development workstation; absent from release image and normal node signing interface. Not an initial backup or an import format. |

## Generation and pool transitions

1. **Enroll:** management commits registration with recipient, cold key, network, machine credential and fresh incarnation. No KES secret yet.
2. **Generate:** pool authority supplies expected next generation number and stable request ID. One bounded in-memory job captures incarnation, recipient and credential policy epochs. Power loss before durable publication leaves no usable generation. Completion rechecks those epochs and the vacant staged slot under the pool lock, merges with latest active state, persists key+immutable artifact reference, erases obsolete snapshots, then returns `staged`. Policy change cancels and wipes the job.
3. **Certify:** staged → certified-staged after full certificate checks. This does not affect active telemetry or signing. Exact duplicate is harmless; different certificate for an already-certified generation conflicts.
4. **Schedule:** certified-staged stays staged; durable activation intent added. No trusted device clock. Node period observation, not elapsed unpowered time, triggers execution.
5. **Activate:** with eligible node period, evolve the replacement to `absolute_period - start_period`, validate its lifetime, commit it as active, retire/remove old active secret and old intent, finish cleanup before acknowledgement. Old public artifact may then be reclaimed. First activation uses the same transition with no previous active key.
6. **Evolve:** active `(generation,r)` → same active `(generation,r')`, with `r' > r` and `r' < max_kes_evolutions`. Perform all cryptographic transitions, persist only final state, erase superseded state before acknowledgement. Same-period request succeeds without another write; earlier-period request fails. Evolution does not alter VK, certificate, generation ID or backup bytes.
7. **Expire:** authenticated period at/after `start + max_kes_evolutions` commits secret erasure, retaining current expired public metadata/artifact and any staged replacement. Signing fails. Device does not expire keys while unpowered or fabricate a replacement.
8. **Revoke/replace credential:** management commits epoch change, invalidates old sessions and cancels affected unpublished jobs. Other pools unchanged. Routine rotation remains pool-authorized.
9. **Delete/retire:** management commits tombstone/retired state and wipes secrets and authorization caches before success. Retired device rejects signing/generation after restart. External backups are neither revoked nor erased.
10. **Damaged:** irrecoverable authenticated-state inconsistency quarantines affected pool; directory/trust/entropy faults may be device-wide. No automatic blank reinitialization, import, old-snapshot restore or selection of another pool.

A pool can retain its active/current-expired generation while one staged generation is generated/certified. Retired generations are never resurrected. A second staged generation returns `STAGED_CONFLICT`; explicit staged discard is management-authorized and retains generation-number/replay high-water marks. There is no extra authority needed for ordinary generate/certify/activate/schedule.

## Signing and lifetime invariants

- For certificate start `S`, permitted lifetime `L`, and authenticated node period `P`, require `S <= P < S+L`, checked addition, and `relative=P-S` no lower than committed evolution. Primitive capacity 64 does not override a smaller network limit.
- Evolution and activation happen under pool serialization before new-period signing. A current-period sign itself causes no journal write. A signature is returned only after device self-verification; the node also verifies using its immutable attempt context before block submission.
- An old-generation attempt either completes before activation or returns a typed stale-context error. Do not pair an old signature with a new certificate.
- A compromised authorized primary can advance prematurely, sign permitted content and cause denial of service. There is no chain-validator, trusted-clock, non-equivocation or deployment-wide forward-security claim.

## Durable transaction and recovery protocol

Each secret bank has an authenticated versioned header/body, dedicated COMMIT page and dedicated CLEAN page. Authenticate revision, parent revision, slot, pool/incarnation and object references; never trust a bare flash generation number. Each page is programmed once after erase.

1. Serialize pool mutation; create candidate in bounded zeroizing RAM. Read-verify referenced public objects first.
2. Erase/read-verify inactive bank if necessary. Program candidate with fresh AEAD nonce; read back, authenticate and validate full decoded invariants.
3. Write/read-verify authenticated COMMIT marker. This is the durable successor point, not permission to acknowledge.
4. Erase/read-verify obsolete bank, invalidate relevant XIP/cache lines, wipe obsolete RAM/cache. Write/read-verify authenticated CLEAN marker.
5. Only now return success or a signature using successor state. Do not start another mutation before cleanup completes.

Recovery before serving: authenticated successor COMMIT without CLEAN requires predecessor cleanup and CLEAN completion even if the predecessor was torn during erase. A CLEAN predecessor plus an incomplete uncommitted candidate may discard that candidate. Two committed valid banks require consecutive revision/parent agreement; choose successor and clean predecessor. A corrupt apparently committed successor, ambiguous marker ordering, invalid object digest or missing authoritative bank quarantines rather than falling back. Interrupted CLEAN-page programming is retried only under the flash part's qualified program rules; otherwise recreate the same successor in an erased bank without acknowledging or exposing old state, with a recovery state machine covered by fault injection. Implementation must prove every reachable marker combination under the supported flash tear model.

Implementation boundary after T017: `Journal<PoolCodec>` uses two4096-byte banks with a3584-byte authenticated snapshot span (maximum3440 canonical plaintext bytes after the128-byte header and16-byte AEAD tag) and two separate8192-byte immutable-object slots; `Journal<DirectoryCodec>` uses two8192-byte banks with a7680-byte snapshot span (maximum7536 plaintext bytes). Each bank's remaining two256-byte pages are COMMIT then CLEAN. Snapshot AAD and marker MACs bind device and exact directory or `(slot,pool,incarnation)` scope, revision, parent and bank. The firmware map places the directory after two1-MiB firmware slots, then32 isolated32-KiB pool regions. A scoped pool flash owner can reach only its24-KiB banks/objects, not its8-KiB reserve or adjacent regions. Pool decode validates lifecycle, generation, object and certificate relationships; directory decode preserves32 identities/tombstones plus replay and retirement state. The conservative W25Q32RV adapter uses core0-only aligned page/sector operations and the HAL's SRAM/core-pause/XIP-cache sequence. Physical execution and qualification remain pending.


Deletion is journaled before directory tombstone publication; recovery reconciles directory and slot incarnations and completes both sides before reuse. Management sequence is durably advanced with the authorized operation, or directory records pending intent that is completed idempotently; no acknowledgement between independently inconsistent records. Device retirement commits a global deny state before clearing slots.

Public-only orphan objects may be reclaimed after authenticated authoritative references are known. Retained referenced backups are never regenerated to repair missing bytes. Signing, status and backup retrieval never mutate lifecycle merely for telemetry.

## Host consistency and retention

The daemon persists only public descriptors, encrypted artifacts, request IDs and configured credentials. Device state is authoritative; stale host files cannot roll it back. Generation number plus creation request ID permits recovery of a lost acknowledgement even after other mutations. Reused request ID with changed payload conflicts; an old generation number whose artifact has been reclaimed returns terminal `RESULT_RECLAIMED`, never a new key. Generic mutations use revision compare-and-swap and durable last-operation identity. After timeout, disconnect or process restart, query `OP_STATUS` with the exact operation identity before any retry: resume output publication for a committed result, preserve a terminal failure/reclaimed result, or replay only the exact payload after authoritative not-committed status. An uncertain older result never permits blind mutation replay.

Keep certificate/VK/artifact output manifests crash-recoverable. Files individually use atomic publication; the CLI reports success only after all outputs and a public completion manifest are durable. A partial host publication is repaired from the same committed generation, never by regenerating its secret. On reconnect, discard lower-revision, retired-generation and prior-session replies; reconcile authenticated pool state before refreshing readiness. Current-period reconciliation is no-write, a lower KES period remains stale across reboot, and a later eligible period catches up directly to the durable final state. Committed expiry retains current-expired public metadata/artifact and staged replacement while the active secret stays erased. A quarantined pool is reported separately from device-wide directory/trust/entropy failure. Device-held encrypted artifacts are a bounded retention window, not the operator's long-term archive.
