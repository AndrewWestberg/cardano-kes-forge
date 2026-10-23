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
| Admitted signing requests | one per pool; 32 total; duplicates/overload do not displace another pool |
| Generation jobs | one global cooperative job, one leaf-work step per scheduling turn |
| Additional queued work | one lifecycle and one status request per pool; one management operation globally |
| Signing budget | min(node slot-attempt budget, 500 ms); no admission-time deadline reset |
| Status budget | 2 seconds under saturation |
| Generation job budget | 10 minutes; timeout cancels unpublished work or reconciles a committed result |

A full queue yields `BUSY` within the calling deadline; authorized normal/status lanes have separate bounded quotas. Round-robin service across admitted pools and bounded generation steps prevent a flooding pool monopolizing work. The device has an uptime timer for request budgets, not a trusted wall clock for KES. The daemon independently enforces the original host monotonic deadline and discards late results even if transport cancellation cannot undo a committed mutation.

## Authenticated device identity and sessions

1. `INFO` without a session returns protocol version, device ID, pinned identity/HPKE public keys, fresh 32-byte boot nonce, current open counter for each scope, firmware hash/security version, capability evidence and limits. Sign deterministic response bytes with Ed25519 under domain `cardano-kes-forge/info/v1`. Challenge includes a fresh caller nonce and must be echoed in signed evidence. Rate-limit unauthenticated requests. Verify against the pre-enrolled pin/provisioning record, not keys returned by this message alone.
2. `OPEN` targets a pool+incarnation or management scope. Host uses HPKE v1 suite 0x0020/0x0001/0x0003 base mode to the enrolled device HPKE public key; authenticated `info` is the deterministic tuple `["cardano-kes-forge/session/v1", device, boot_nonce, scope, incarnation, credential_epoch, open_counter, request_id]`. Encrypt a fresh 32-byte challenge. The authorized machine Ed25519 key signs that tuple plus encapsulation and ciphertext. Device verifies scope, current epoch and counter before decapsulation. Management transport authentication is not authority to apply a management operation.
3. Both sides derive separate 32-byte request and response MAC keys through RFC 9180 `Export` with labels `cardano-kes-forge/request/v1` and `cardano-kes-forge/response/v1`. Device returns fresh 16-byte session ID and challenge acknowledgement authenticated with the response key. Increment open counter only after authenticated OPEN; atomically replace only that scope's session. No pool key/password travels in the handshake. Clear HPKE ephemeral/shared material after session establishment.
4. A session has separate monotonic u64 request/response sequence spaces; one host daemon serializes each pool. Reboot, disconnect, revocation, epoch change or overflow invalidates it. A fresh unpredictable boot nonce prevents replay across restart without per-signature flash writes. Host reconnects unattended, rechecks release evidence, opens sessions and reconciles authoritative state before signing. No fallback.

This is a versioned application protocol using standard HPKE/HMAC/Ed25519, not a new cryptographic primitive. Independent review must cover transcript binding, cross-protocol domains, replay and session replacement before release.

## Request/response envelope

Authenticated request fields: `version=1`, `op`, `device` (16 bytes), `pool` (28 bytes or null for device scope), `incarnation` (16 bytes or null), `session` (16 bytes), `seq` (u64), `request` (16 bytes), `budget_ms` (bounded u32), `payload` (operation map), `mac` (32 bytes). MAC is HMAC-SHA256 of `"cardano-kes-forge/request-frame/v1" || deterministic-CBOR(envelope without mac)`.

Response repeats identity, request and operation, adds `request_seq`, `seq`, `status`, `payload`, and response-domain MAC. A success carrying signing-state metadata includes `revision`, `generation`, `certificate_digest`, `relative_period`, `lifecycle`, `health`. These describe committed state only. Host must match request/context and reject old session, generation, incarnation, digest or revision. Error payloads are bounded public diagnostics, never encoded requests/credentials/secrets.

The daemon-facing socket uses the same versioned length/CBOR operation payloads but terminates device sessions internally. Local requests include configured `connection`, `request`, `budget_ms`, `op`, `payload`; local response includes those identifiers and `status`, `payload`. Socket ACLs map peer UID to permitted configured connections; a caller cannot name another connection or submit a replacement credential. Credentials are loaded from restricted files, not embedded in ordinary requests. Apply `SO_PEERCRED` and safe socket-path ownership; no world-writable listener. Haskell CLI/node implement this small byte contract natively rather than shelling out per signature.

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

Management signed tuple: `["cardano-kes-forge/manage/v1", device, scope, incarnation, management_sequence, request_id, expected_revision, action, canonical_payload]`. Increment strictly from stored sequence; exact last replay returns stored public result, changed bytes conflict. New incarnation is authorized explicitly and does not reset old certificate/replay history. Initial management transport key is enrolled during attended provisioning and cannot sign the offline authorization on its own.

## Error taxonomy and recovery

Stable statuses: `INVALID_FRAME`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_OPERATION`, `AUTH_FAILED`, `REPLAY`, `WRONG_DEVICE`, `WRONG_POOL`, `WRONG_NETWORK`, `SECURITY_NOT_READY`, `ENTROPY_FAILURE`, `CAPACITY`, `BUSY`, `DEADLINE_EXCEEDED`, `REVISION_CONFLICT`, `STAGED_CONFLICT`, `STALE_GENERATION`, `STALE_PERIOD`, `NOT_YET_VALID`, `EXPIRED`, `CERTIFICATE_INVALID`, `RECIPIENT_INVALID`, `RESULT_RECLAIMED`, `STATE_DAMAGED`, `DEVICE_UNAVAILABLE`, `IN_PROGRESS`, `UNKNOWN`, `NOT_COMMITTED`, `OK`.

Static malformed configuration is a startup error. Runtime USB/daemon loss is `DEVICE_UNAVAILABLE` for dependent pools only. Device-wide vs pool-local error scope is explicit. Missing/invalid MAC is a transport-authentication failure and cannot carry trusted state updates. Lost mutation responses require status reconciliation; only byte-identical IDs/payloads can be retried, and confirmed successor state takes precedence. Cancellation never implies rollback. All fatal security failures clear session secrets; neither daemon nor node converts an error into a fabricated signature or software key.

## Compatibility and change policy

Version 1 is a new protocol, not compatible with Pico HSM. Breaking wire/storage changes require a new major version, explicit native/Rust caller migration and qualified signed-state migration; never try an older parser after authentication fails. Existing file-based and kes-agent interfaces are intentionally untouched. No secrets in protocol fixtures: generate disposable keys at runtime and retain only public evidence/counterexample metadata.
