# Device and Local-Service Contract v1

Normative planned interface, not an existing executable. Related: [data model](../data-model.md), [security](security.md), [node integration](node-integration.md).

## Transport, framing and limits

Device: dedicated USB vendor bulk IN/OUT endpoints; no arbitrary memory/flash/OTP reads, bootloader passthrough, private-key import, transaction signing or HSM compatibility commands. Host daemon `kes-forged` owns one device handle and exposes Unix stream sockets only. A configured daemon can serve multiple node processes and mixed bulk entries without giving each process ownership of USB.

Each message is `u32be byte_length || deterministic-CBOR-map`. Maximum encoded message 8192 bytes excluding prefix. RFC 8949 deterministic encoding: definite lengths, shortest integer encoding, sorted encoded map keys, no duplicate keys, floats, tags, indefinite lengths or trailing bytes; nesting <=4. Map field names below are exact UTF-8 keys. Unknown required-version/opcode/field or noncanonical signed encoding is rejected; no permissive legacy fallback. Read prefix before reserving bounded space, reject oversize immediately, and expire incomplete frames within 2 seconds.

| Limit | v1 bound |
|---|---|
| Live pools / generations | 32 / one active-or-current-expired and one staged per pool |
| Message to sign | 0–4096 raw bytes; never sign a prehash instead of the exact Cardano content |
| Canonical opcert bytes | <=1024 bytes; recognized pinned Cardano encoding only |
| Encrypted backup | <=2048 bytes; one whole artifact fits a frame |
| Normal sessions | 32 pool sessions plus one management transport session |
| Service-admitted signing requests | one per pool; 32 total in the daemon, including queued and device-dispatched requests; duplicates/overload do not displace another pool |
| Generation jobs | one global cooperative job, one leaf-work step per scheduling turn |
| Additional host-queued work | one lifecycle and one status request per pool; one management operation globally; each lane reserves at most one 8192-byte frame |
| Local socket receive capacity | at most 64 connected peers, one <=8192-byte incomplete frame per peer; 2-second frame expiry; refuse excess peers without allocating another frame |
| Signing budget | min(node slot-attempt budget, 500 ms), starting at service admission before queueing; no dispatch/reconnect-time deadline reset |
| Status budget | 2 seconds under saturation |
| Generation job budget | 10 minutes; timeout cancels unpublished work or reconciles a committed result |

A full service queue yields `BUSY` within the calling deadline; authorized normal/status lanes have separate bounded quotas. Service admission occurs after local authorization and bounded frame validation, before waiting for USB. The native caller's earlier slot deadline remains an upper bound. The daemon retains queued message bodies and dispatches at most one complete device operation at a time, round-robin across ready pools/lanes; a generation start returns `IN_PROGRESS` and subsequent leaf work is cooperative, not a retained ten-minute transport request. Pending requests remain counted against their original pool quota and deadline. Expired queued requests are rejected without device dispatch; a dispatched timeout never implies rollback or permits an overlapping secure request to overwrite its workspace. The original request must finish or the transport/session must be invalidated and reconciled before reuse. This is bounded single-flight dispatch, not 32 resident device message bodies.

Device request storage is one 8192-byte nonsecure receive buffer, one 8192-byte secure validated request buffer, and one 8192-byte response buffer; parse the exact signing bytes in place within the secure buffer, not into another 4096-byte copy. Do not retain incoming USB frames in per-pool device queues. The secure gateway copies once after checking length/ownership and never retains a mutable nonsecure pointer. A host sending a second command before completion receives bounded `BUSY` without another secure allocation; it cannot displace existing work. Shared generation/evolution/journal workspaces and all stacks have separate ceilings in research R4. These are design bounds to prove on hardware, not measured results.

Round-robin host service and bounded generation steps prevent a flooding pool monopolizing work. The device has an uptime timer for request budgets, not a trusted wall clock for KES. Each dispatched `budget_ms` is the remaining original host budget, rounded down; zero remaining budget is not dispatched. The daemon independently enforces the original host monotonic deadline and discards late results even if transport cancellation cannot undo a committed mutation. Independent node verification must also finish before that original deadline. P1 measures admission-to-verified-result, including every queued 4096-byte body, not just device-resident execution.

## Authenticated device identity and sessions

1. `INFO` without a session returns protocol version, device ID, pinned identity/HPKE public keys, fresh 32-byte boot nonce, current open counter for each scope, firmware hash/security version, capability evidence and limits. Sign deterministic response bytes with Ed25519 under domain `cardano-kes-forge/info/v1`. Challenge includes a fresh caller nonce and must be echoed in signed evidence. Rate-limit unauthenticated requests. Verify against the pre-enrolled pin/provisioning record, not keys returned by this message alone.
   Release-ready `capability_evidence` uses the exact bounded canonical v1 record and independent signature transcript in [security](security.md); a signed mode label alone is not readiness evidence.
2. `OPEN` targets a pool+incarnation or management scope. Host uses HPKE v1 suite 0x0020/0x0001/0x0003 base mode to the enrolled device HPKE public key; authenticated `info` is the deterministic tuple `["cardano-kes-forge/session/v1", device, boot_nonce, scope, incarnation, credential_epoch, open_counter, request_id]`. Encrypt a fresh 32-byte challenge. The authorized machine Ed25519 key signs that tuple plus encapsulation and ciphertext. Device verifies scope, current epoch and counter before decapsulation. Management transport authentication is not authority to apply a management operation.
3. Both sides derive separate 32-byte request and response MAC keys through RFC 9180 `Export` with labels `cardano-kes-forge/request/v1` and `cardano-kes-forge/response/v1`. Device returns fresh 16-byte session ID and challenge acknowledgement authenticated with the response key. Increment open counter only after authenticated OPEN; atomically replace only that scope's session. No pool key/password travels in the handshake. Clear HPKE ephemeral/shared material after session establishment.
4. A session has separate monotonic u64 request/response sequence spaces; one host daemon serializes each pool. Reboot, disconnect, revocation, epoch change or overflow invalidates it. A fresh unpredictable boot nonce prevents replay across restart without per-signature flash writes. Host reconnects unattended, rechecks release evidence, opens sessions and reconciles authoritative state before signing. No fallback.

This is a versioned application protocol using standard HPKE/HMAC/Ed25519, not a new cryptographic primitive. Independent review must cover transcript binding, cross-protocol domains, replay and session replacement before release.

## Request/response envelope

Authenticated request fields: `version=1`, `op`, `device` (16 bytes), `pool` (28 bytes or null for device scope), `incarnation` (16 bytes or null), `session` (16 bytes), `seq` (u64), `request` (16 bytes), `budget_ms` (bounded u32), `payload` (operation map), `mac` (32 bytes). MAC is HMAC-SHA256 of `"cardano-kes-forge/request-frame/v1" || deterministic-CBOR(envelope without mac)`.

Response repeats identity, request and operation, adds `request_seq`, `seq`, `status`, `payload`, and response-domain MAC. A success carrying signing-state metadata includes `revision`, `generation`, `certificate_digest`, `relative_period`, `lifecycle`, `health`. These describe committed state only. Host must match request/context and reject old session, generation, incarnation, digest or revision. Error payloads are bounded public diagnostics, never encoded requests/credentials/secrets.

The daemon-facing socket uses the same versioned length/CBOR operation payloads but terminates device sessions internally. Local requests include configured `connection`, `request`, `budget_ms`, `op`, `payload`; local response includes those identifiers and `status`, `payload`. Socket ACLs map peer UID to permitted configured connections; a caller cannot name another connection or submit a replacement credential. Credentials are loaded from restricted files, not embedded in ordinary requests. Apply `SO_PEERCRED` and safe socket-path ownership; no world-writable listener. Haskell CLI/node implement this small byte contract natively rather than shelling out per signature.

### Concrete v1 codec conventions

The implemented `kes_protocol` codec is allocation-free: caller-owned receive/encode buffers and borrowed exact payload/message views. A first nonempty receive starts the fixed 2000-ms incomplete-frame deadline; more fragments never reset it. Syntax validation is not authentication, enrollment, readiness or permission to execute an operation. Raw byte views, envelopes and development-state views have no Debug formatter; parser errors do not echo input.

All maps are closed and every field is required unless prefixed `?`. `Bn` means an exact n-byte bytestring, `U` an unsigned64, `U32` unsigned32, `Tn` UTF-8 text of at most n bytes without NUL. Positive U excludes zero. Map keys are text and sorted by their exact encoded bytes. Only unsigned integers, bytes, text, arrays, maps, bool and null are admitted; canonical syntax does not normalize text. `pool`/`incarnation` are either B28/B16 together or both null. Wire network names are snake_case; bootstrap JSON retains its existing camelCase names.

Authenticated response fields are exactly the request fields minus `budget_ms`, plus `request_seq` and `status`; response `seq` is the device sequence. Local request fields are exactly `{version,connection,request,budget_ms,op,payload,?target}`, and local response fields `{version,connection,request,op,status,payload}`. Optional `target` is `[device:B16,pool:B28|null,incarnation:B16|null]`, with both scope identifiers null or both present. Rust operator clients supply this public expected identity; the daemon compares it to the configured route before opening a session or contacting USB. A mismatch returns `WRONG_DEVICE` or `WRONG_POOL`. It is not authorization; peer UID and device session authentication remain mandatory. Existing native six-field requests omit it. The target never enters device envelopes or local responses. Connection names are 1–64 ASCII alphanumeric/`-_.`. Dedicated unauthenticated-session envelopes are:

| Kind | Exact fields, in addition to version1/op |
|---|---|
| INFO request | `request:B16,payload:{challenge:B32}` |
| INFO response | `request:B16,device:B16,status,payload,signature:B64` |
| OPEN request | `device:B16,pool:B28|null,incarnation:B16|null,request:B16,payload` |
| OPEN response | same target/request fields, `status,payload,mac:B32` |

INFO/OPEN are rejected in ordinary device/local envelopes. Pool scope is required for generation, backup, certification, activation, scheduling, evolution, signing, observation and development inspection; update operations require device scope. STATUS/OP_STATUS/MANAGE/OPEN admit either scope. DEV_INSPECT is rejected in both local socket directions; its eventual development-only handler is not implemented by the codec.


### Local operator STATUS diagnostics

Only a `LocalRequest` STATUS may add `host_diagnostics:true` to its otherwise unchanged payload. The daemon strips that flag before authenticated device encoding. Ordinary native STATUS requests and responses retain their original schema and do not allocate or transmit this diagnostic snapshot.

An opted-in successful local STATUS response adds exactly `host_device:B16`, `host_pool:B28|null`, `host_incarnation:B16|null`, `host_observation` and `host_latency` to the required wire payload. Host pool/incarnation are paired; the operator validates them against public configuration. These additions are forbidden in authenticated device responses.

`host_observation` is null for management scope, otherwise the nine-element tuple `[state,confirmedAgeMs,nodePeriodAgeMs,confirmedObservedAt,nodePeriodObservedAt,context|null,historicalDescriptor|null,ready|null,remaining|null]`. `host_latency` is null for management, otherwise eight entries in `GENERATE,GET_BACKUP,CERTIFY,ACTIVATE,SCHEDULE,EVOLVE,SIGN,OBSERVE_PERIOD` order. Each entry is null or `[requestId,durationMs,outcome,code,observedAt,ageMs,...context]`.

Context is flattened to preserve the four-level CBOR bound: `[device:B16,bootNonce:B32,session:B16,pool:B28,incarnation:B16,networkMagic:U,genesisDigest:B32,slotsPerKesPeriod:U,maxKesEvolutions:U,generation:B16|null,certificateDigest:B32|null,revision:U|null]`. Observation context carries that twelve-element array; latency appends its twelve elements after the six sample fields. UTC strings are display metadata; ages use only the daemon monotonic clock. The operator converts this bounded local snapshot into the exact public JSON schema in cli-backup.md. A read never renews either observation or the last completed operation sample.

## Operation catalog

All mutations carry `expected_revision` except generation, which additionally reconciles by durable generation number/creation ID. Every generation-specific operation names `generation`. Device checks machine authority AND pool binding; a management signature does not grant plaintext extraction.

| Operation | Authority | Payload | Successful result / mutation |
|---|---|---|---|
| `STATUS` | pool; management for device directory | optional generation | Device health/security; pool identity, credential epoch/revocation, active/staged descriptors, backup availability, committed evolution, blocking reason. No device expiry countdown. |
| `GENERATE` | pool | `next_generation_number`, `expected_revision` | Job acknowledgement is explicitly `IN_PROGRESS`, not a usable generation. Durable completion yields staged descriptor, VK and artifact digest; creation request ID remains attached. |
| `OP_STATUS` | same pool/scope | original request ID and generation number where applicable | `IN_PROGRESS`, committed descriptor, `NOT_COMMITTED`, `RESULT_RECLAIMED`, or `UNKNOWN`; unknown is not permission to create a different generation. |
| `GET_BACKUP` | pool | generation | Exact retained immutable bytes and digest; no re-encryption. |
| `CERTIFY` | pool | generation, canonical certificate bytes, network binding, expected revision | Validated staged certificate digest/public descriptor. Cold key remains external. |
| `ACTIVATE` | pool | generation, certificate digest, current absolute period, expected active generation/revision | Atomically active descriptor after required evolution, old-secret cleanup and durable completion. |
| `SCHEDULE` | pool | generation, certificate digest, activation absolute period, expected active generation/revision | Durable activation intent; no separate rotation approval. |
| `EVOLVE` | pool | generation, certificate digest, target absolute period, network binding, expected revision | Confirmed evolved state or explicit stale/expired failure. If expiry is committed, return `EXPIRED` with public committed metadata. |
| `SIGN` | pool | generation, certificate digest, absolute period, network binding, exact message bytes | Signature (448 bytes), SHA-256 message digest and confirmed signing context. May first commit needed forward evolution; never create a generation. Device self-verifies; node independently verifies. |
| `OBSERVE_PERIOD` | pool | absolute period, network binding, expected revision | Reconciles eligible scheduled activation or expiry, then returns committed descriptor. This is an operational request, not a side effect of telemetry queries. |
| `MANAGE` | offline management signature plus authorized transport | signed envelope with action and canonical payload | Enrollment, credential replace/revoke, recipient replace, staged discard, pool delete, device retire, or firmware authorize; replay-safe durable result. |
| `UPDATE_BEGIN` / `UPDATE_CHUNK` / `UPDATE_FINALIZE` | management-authorized signed firmware manifest | manifest digest; bounded offset+bytes; final digest | Fixed inactive firmware-slot writes only, verified image and security-version transition. No caller-supplied raw address; see security contract. |
| `DEV_INSPECT` | explicit development opt-in and pool authority | generation, protected-output request | Current disposable state plus period/context; compiled out of release. Node sockets never expose it. |

Pool `STATUS` can show the public authorization state, not machine credentials. Host operator status joins its last node-period observation to report remaining validity and labels absent/stale observations. `STATUS`, `GET_BACKUP` and telemetry reads do not evolve. `OBSERVE_PERIOD` is explicit lifecycle processing by the node, needed to execute scheduled rotation even when no block is forged.

### Exact operation payload schemas

| Request | Closed payload |
|---|---|
| OPEN | `boot_nonce:B32,credential_epoch:U,open_counter:U,encapsulation:B32,ciphertext:B48,signature:B64` |
| STATUS | `?generation:B16` |
| GENERATE | `next_generation_number:U,expected_revision:U` |
| OP_STATUS | `request:B16,?generation_number:U` |
| GET_BACKUP | `generation:B16` |
| CERTIFY | `generation:B16,certificate:bytes<=1024,network:Network,expected_revision:U` |
| ACTIVATE | `generation:B16,certificate_digest:B32,current_absolute_period:U,expected_active_generation:B16|null,expected_revision:U` |
| SCHEDULE | ACTIVATE fields with `activation_absolute_period` instead of `current_absolute_period` |
| EVOLVE | `generation:B16,certificate_digest:B32,target_absolute_period:U,network:Network,expected_revision:U` |
| SIGN | `generation:B16,certificate_digest:B32,absolute_period:U,network:Network,message:bytes<=4096` |
| OBSERVE_PERIOD | `absolute_period:U,network:Network,expected_revision:U` |
| MANAGE | Management below |
| UPDATE_BEGIN | `manifest_digest:B32,expected_revision:U` |
| UPDATE_CHUNK | `manifest_digest:B32,offset:U,bytes:bytes<=4096,expected_revision:U`; checked offset+length |
| UPDATE_FINALIZE | `manifest_digest:B32,final_digest:B32,expected_revision:U` |
| DEV_INSPECT | `generation:B16,protected_output:true` |

`Network` is `{network_magic:U32,shelley_genesis_digest:B32,slots_per_kes_period:positive U,max_kes_evolutions:U in1..64}`. The certificate bytes are canonical CBOR `[[hot_vk:B32,counter:U,start_period:U,cold_signature:B64],cold_vk:B32]`; protocol structural parsing alone does not verify its signature, identity, lifetime or counter. The core certificate layer separately verifies exact48-byte OCertSignable/cold signature, enrolled identities/network/lifetime and activated-counter rules before RAM certification. Network is not a signed opcert field. This core enforcement does not imply an implemented authenticated device dispatcher or durable acknowledgement.

| OK response | Closed payload |
|---|---|
| INFO | `challenge:B32,identity_public_key:B32,hpke_public_key:B32,boot_nonce:B32,open_counters:Counter[<=33],firmware_digest:B32,security_version:U,hardware_policy_digest:B32,security_mode:Security,capability_evidence:bytes<=2048,limits:Limits` |
| OPEN | `session:B16,challenge_acknowledgement:B32` |
| STATUS | `health:Health,security_mode:Security,revision:U,credential_epoch:U,revoked:bool,active:Descriptor|null,staged:Descriptor|null,blocking_reason:T256,directory:DirectoryEntry[<=32],?management_sequence:U`; management-scope consumers require `management_sequence` |
| GENERATE/CERTIFY/ACTIVATE/SCHEDULE/OBSERVE_PERIOD | Descriptor |
| OP_STATUS | Descriptor for a generation operation, or exactly `{management_sequence:U,revision:U}` for a committed management operation; never a hybrid |
| GET_BACKUP | `generation:B16,backup:complete BackupArtifact<=2048,artifact_digest:B32` |
| EVOLVE | Context |
| SIGN | Context plus `signature:B448,message_digest:B32` |
| MANAGE | `management_sequence:U,revision:U` |
| UPDATE_BEGIN/CHUNK/FINALIZE | `manifest_digest:B32,offset:U,revision:U` |
| DEV_INSPECT | Context plus `state:B608`, never an initial-state backup |

`Context` is `{revision:U,generation:B16,certificate_digest:B32,relative_period:0..63,lifecycle:Lifecycle,health:Health}`. `Descriptor` is `{generation:B16,generation_number:U,creation_request:B16,verification_key:B32,artifact_digest:B32,revision:U,certificate_digest:B32|null,relative_period:0..63,lifecycle:Lifecycle,health:Health,backup_available:bool,certificate_start:U|null,certificate_counter:U|null}`. `DirectoryEntry` is `{pool:B28,incarnation:B16,revision:U,management_sequence:U,credential_epoch:U,revoked:bool,deleted:bool,health:Health,active:B16|null,staged:B16|null}`; generation references avoid excessive nesting. The management directory includes retained deletion tombstones within the same 32-entry bound. A deleted entry retains its last incarnation and management sequence, has `revoked=true`, and has null active/staged references. Scope-specific directory/descriptor contents remain runtime invariants.

`Counter` is `{pool:B28|null,incarnation:B16|null,open_counter:U}` with paired scope. `Limits` fixes U32 values `{frame_bytes:8192,message_bytes:4096,certificate_bytes:1024,backup_bytes:2048,pools:32,sessions:33}`. Health is `healthy|damaged|unavailable`; Lifecycle is `staged|certified-staged|active|expired|retired`; Security is `development|release-unprovisioned|release-ready`. A label is never evidence of readiness.

`IN_PROGRESS` is restricted to GENERATE/OP_STATUS with `{request:B16,generation_number:U}`. OP_STATUS `UNKNOWN|NOT_COMMITTED|RESULT_RECLAIMED` uses `{request:B16,?generation_number:U}`. Committed `EXPIRED` on SIGN/EVOLVE/OBSERVE_PERIOD uses Context, never a signature. Other non-OK errors use `{scope:"device"|"pool",diagnostic:T256}`; public diagnostics and authenticity must be enforced by the runtime.

For management `OP_STATUS`, omit `generation_number`. Only authenticated `NOT_COMMITTED` authorizes redispatch of the identical durable authorization. `UNKNOWN`, `IN_PROGRESS`, device unavailability, and deadline expiry retain an uncertain operation record; they do not prove that the mutation failed to commit.

### Exact management and signed transcript schemas

Management is `{device:B16,pool:B28|null,incarnation:B16|null,management_sequence:U,request:B16,expected_revision:U,action,canonical_payload:bytes<=4096,signature:B64}`. The payload bytes contain an independently canonical closed CBOR map. Outer device must equal the signed device; a pool-scoped outer target must equal signed pool/incarnation. A device management transport may address a signed pool target.

| Action and target | Closed canonical payload |
|---|---|
| ENROLL, pool | `version:1,device:B16,pool:B28,incarnation:B16,cold_verification_key:B32,network:Network,machine_public_key:B32,credential_epoch:0,recipient_public_key:B32,recipient_id:B32`; inner target matches signed target |
| RECIPIENT_REPLACE, pool | `recipient_public_key:B32,recipient_id:B32` |
| STAGED_DISCARD, pool | `generation:B16` |
| POOL_DELETE, pool | empty map |
| CREDENTIAL_REPLACE, either | `machine_public_key:B32,credential_epoch:U` |
| CREDENTIAL_REVOKE, either | `credential_epoch:U` |
| DEVICE_RETIRE, device | empty map |
| FIRMWARE_AUTHORIZE, device | Manifest |

`Manifest` is `{version:1,firmware_digest:B32,partition_manifest_digest:B32,storage_schema:1,image_length:positive U,security_version:U,hardware_policy_digest:B32,signature:B64}`. Structural management validation does not replace distinct firmware/ROM authority, image validation or provisioning evidence.

Session info is the eight-element array specified above; the OPEN-signature input extends it with encapsulation and ciphertext to ten elements. The management-signature input is `["cardano-kes-forge/manage/v1",device,pool-or-null,incarnation-or-null,management_sequence,request,expected_revision,action,canonical_payload-map]`; the final element is the unchanged underlying map, not another bytestring wrapper. Borrowed visitors emit canonical field omission and transcript pieces without copying a message body; callers supply the prescribed domain prefix.

The backup syntax parser recognizes only the exact KESBKP01 schema from CLI/backup: version1/KEM32/KDF1/AEAD3, fixed identifiers/public keys, period0, ciphertext624 and device signature64. It does not authenticate the recipient digest, device signature, HPKE or AEAD. Authentication and lifecycle handlers remain later foundation/story work.


### Host observation freshness and operational latency

Version 1 uses a fixed `observationMaxAgeMs=30000`; no caller may extend it to make old evidence fresh. Use host monotonic time for age and UTC timestamps for display only. `ConfirmedObservation` preserves authenticated committed facts separately from `NodePeriodObservation`, which comes only from an authorized native client's operational SIGN/EVOLVE/OBSERVE_PERIOD context and is bound to device/boot/session/pool/incarnation/network/active generation/certificate. Operator-supplied activation periods and device STATUS responses alone are not a current node-period observation. Updating public status does not refresh the node-period timestamp.

`fresh` requires both observations in the current reconciled context, no unresolved mutation, and each monotonic age strictly less than 30000 ms. At age >=30000 ms with the connection still usable, report `stale`. Absent observations, disconnect, device reboot/session replacement, daemon restart, invalid authenticated context or unresolved mutation make readiness `unavailable` immediately; retain previous public facts only as explicitly historical. After an active-generation change invalidate the old join and obtain matching confirmed state and a current operational node observation before reporting fresh again. Staging alone does not replace active observations. Repeated queries, requested target periods, wall-clock jumps and late old-generation replies cannot extend freshness. Stale/unavailable joins have null remaining-validity/readiness values, never a fabricated zero or an assertion of current signing readiness. Public certificate bounds remain independently reportable.

Runtime diagnostics retain one last-completed record per registered pool and each of the fixed operations GENERATE, GET_BACKUP, CERTIFY, ACTIVATE, SCHEDULE, EVOLVE, SIGN, OBSERVE_PERIOD; at most 32×8 records, held only in daemon RAM. The record contains `operation`, `requestId`, `durationMs` (nonnegative integer milliseconds rounded up), `outcome` (`success` or `error`), stable `code`, `observedAt` (UTC RFC3339), monotonic completion time and current boot/session/generation context. Measure from service admission through host queueing, transport, validation and daemon-side signature verification or terminal failure/deadline; additionally the native node independently verifies under the original slot deadline. GENERATE success here means the initial validated IN_PROGRESS acknowledgement, not completion of the ten-minute asynchronous job; label that outcome `code=IN_PROGRESS`. A timeout remains an error even if a late device result arrives. Never retain message bodies or secrets in diagnostics.

Expose `latency` as an object keyed by those eight operations, each `{state: "fresh"|"stale"|"unavailable", sample: <record>|null}`. A sample is fresh for age <30000 ms, stale at >=30000 ms, unavailable/null before any completion and after daemon restart or session replacement. Disconnect invalidates readiness immediately; a newly completed terminal transport failure may still be shown as an error latency sample, never successful readiness. STATUS, OP_STATUS and diagnostic reads do not create/overwrite samples or refresh their ages. The timing is operational host latency, not firmware-only timing or a replacement for P1 qualification. Fixed record count and constant-time overwrite prevent an unbounded history.

Management signed tuple: `["cardano-kes-forge/manage/v1", device, scope, incarnation, management_sequence, request_id, expected_revision, action, canonical_payload]`. Increment strictly from stored sequence; exact last replay returns stored public result, changed bytes conflict. New incarnation is authorized explicitly and does not reset old certificate/replay history. Initial management transport key is enrolled during attended provisioning and cannot sign the offline authorization on its own.

## Error taxonomy and recovery

Stable statuses: `INVALID_FRAME`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_OPERATION`, `AUTH_FAILED`, `REPLAY`, `WRONG_DEVICE`, `WRONG_POOL`, `WRONG_NETWORK`, `SECURITY_NOT_READY`, `ENTROPY_FAILURE`, `CAPACITY`, `BUSY`, `DEADLINE_EXCEEDED`, `REVISION_CONFLICT`, `STAGED_CONFLICT`, `STALE_GENERATION`, `STALE_PERIOD`, `NOT_YET_VALID`, `EXPIRED`, `CERTIFICATE_INVALID`, `RECIPIENT_INVALID`, `RESULT_RECLAIMED`, `STATE_DAMAGED`, `DEVICE_UNAVAILABLE`, `IN_PROGRESS`, `UNKNOWN`, `NOT_COMMITTED`, `OK`.

Static malformed configuration is a startup error. Runtime USB/daemon loss is `DEVICE_UNAVAILABLE` for dependent pools only. Device-wide vs pool-local error scope is explicit. Missing/invalid MAC is a transport-authentication failure and cannot carry trusted state updates. Lost mutation responses require status reconciliation; only byte-identical IDs/payloads can be retried, and confirmed successor state takes precedence. Cancellation never implies rollback. All fatal security failures clear session secrets; neither daemon nor node converts an error into a fabricated signature or software key.

## Compatibility and change policy

Version 1 is a new protocol, not compatible with Pico HSM. Breaking wire/storage changes require a new major version, explicit native/Rust caller migration and qualified signed-state migration; never try an older parser after authentication fails. Existing file-based and kes-agent interfaces are intentionally untouched. No secrets in protocol fixtures: generate disposable keys at runtime and retain only public evidence/counterexample metadata.
