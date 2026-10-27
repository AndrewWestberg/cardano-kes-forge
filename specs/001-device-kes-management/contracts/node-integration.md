# Cardano Node Integration and Monitoring Contract v1

Baselines and source revisions: [research R1](../research.md). Node compatibility is 11.1.3 with required node/consensus modifications; the separate **unmodified cardano-cli-11.4.0.0** baseline is pinned to `25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`, not the older CLI bundled with node 11.1.3. It remains the certificate-issuance, conventional file-key/query tool and independent interoperability oracle; no CLI fork, source patch or device-generation extension is required. Build their Haskell graphs separately. Device-only generation belongs to the Rust operator executable as `kes-forge key-gen-KES`, with the [CLI/backup contract](cli-backup.md) flags unchanged, no era/node prefix, old command alias or software fallback. The Cargo package remains `cardano-kes-forge`; the daemon executable is `kes-forged` and the `kesSource.type` discriminator remains `cardano-kes-forge`. New native modules/constructors below are design names, not claims that the existing code implements them.

## Source selection and bulk-file grammar

Single-pool startup retains `--shelley-kes-key FILE` and `--shelley-kes-agent-socket SOCKET`; add `--shelley-kes-forge-config FILE`. Exactly one is selected for that credential, with existing certificate and VRF inputs. Each bulk entry independently selects file or forge. kes-agent remains single-pool only. There is no global external-signer switch and no runtime source fallback or source-changing hot reload.

`--bulk-credentials-file` remains a JSON array. Each element is either:

1. An existing array of exactly three **embedded text-envelope objects**, in the existing order `[operationalCertificate, vrfSigningKey, kesSigningKey]`; or
2. A new discriminated object with exactly `version`, `operationalCertificate`, `vrfSigningKey`, `kesSource`:

```text
NewEntry = {
  version: 1,
  operationalCertificate: TextEnvelope<NodeOperationalCertificate>,
  vrfSigningKey: TextEnvelope<VrfSigningKey>,
  kesSource: FileSource | ForgeSource
}
FileSource = { type: "file", signingKey: TextEnvelope<KesSigningKey> }
ForgeSource = { type: "cardano-kes-forge", connectionFile: FilePath }
```

A legacy tuple is interpreted exactly as file-backed; existing files need no rewrite. New file objects allow explicit source selection but do not replace the tuple format. A mixed array can interleave both forms in any order. JSON objects are decoded with duplicate-key detection before ordinary Aeson value construction; unknown/new conflicting source fields, unsupported versions, empty paths, `type="kes-agent"`, missing fields and malformed legacy triples fail. There is no default source for malformed new entries.

A forge connection file is public configuration version 1 with mandatory `version=1`, `socketPath`, `deviceId`, `deviceIdentityFile`, `poolId`, `incarnationId`, `networkBinding`, `connectionName`, `credentialFile`, `securityPolicy`. The native decoder requires an explicit `securityPolicy`: `"release-required"` or `"isolated-development"`; omission is not defaulted. Exact encodings, validation, credential creation and daemon/device bootstrap schemas are defined in [cli-backup.md](cli-backup.md); use that one schema, not a native-only variant. The credential file is owner-only and used by the daemon; it is never embedded in bulk JSON.

The node resolves a bulk entry's `connectionFile` relative to the **bulk file's directory**, then resolves `socketPath` relative to the **connection file's directory**; absolute paths are normalized, not rebased. The native decoder validates `deviceIdentityFile` and `credentialFile` as nonempty paths but does not open those files or load their secrets. The Rust daemon/operator loaders apply the shared configuration's path and identity/credential checks. Do not inherit another entry's connection, certificate or mutable state.

All credentials are loaded before returning the forging credential list. The native loader checks envelope decoding, forge pool/cold identity and genesis network binding, combined singleton/bulk duplicate pool IDs, and a maximum of 32 device-backed credentials; file/agent credentials do not consume those 32 entries. Singleton and bulk file credentials use the same KES verification-key/certificate binding check. Bulk mismatches identify `FILE[index].kesSource.signingKey` and `FILE[index].operationalCertificate`; the check applies to both legacy triples and explicit file objects, without changing the external-source branch. A regression exercises actual conventional envelope loading for matching and mismatching keys in both formats; it has not been run for this change. Explicit file entries contain plaintext file-based KES state as they always did; the no-primary-secret claim applies to device-backed state, not other pools' VRF/file keys.

Static well-formedness does not require a live Pico/daemon. A valid forge entry can start in unavailable state while synchronization and file-backed pools run. A stale host certificate is a bootstrap hint bound to that pool; it cannot restore an older active generation. On authenticated reconciliation adopt the device's committed public descriptor only after validating cold identity/network/counter, never an arbitrary returned certificate.

## Operator commands and T067 evidence status

The following are source-grounded command recipes, **not a record that they were executed**. T067 remains incomplete until the required live source/startup/error and backup exercises are recorded alongside the quickstart. No accepted blocks, unchanged-PID reconnect, outage isolation, A4 security or public-network qualification is established by these recipes. The previously connected disposable A2 has been permanently retired; it must not be reused for this exercise. A fresh, explicitly development-only device and enrollment are required for any new A2 run.

### Singleton and bulk startup

Set `NODE_BIN` to the executable built from the modified node/consensus graph, not an upstream unmodified node or the CLI interoperability oracle. Each singleton invocation below requires the same real network configuration/topology, separate usable database/socket paths, a matching operational certificate and VRF signing key. Set the quoted variables to actual paths before running; the three commands are **alternatives**, not concurrent producers:

```sh
"$NODE_BIN" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --shelley-operational-certificate "$OPCERT" --shelley-vrf-key "$VRF_SKEY" \
  --shelley-kes-key "$KES_SKEY"

"$NODE_BIN" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --shelley-operational-certificate "$OPCERT" --shelley-vrf-key "$VRF_SKEY" \
  --shelley-kes-agent-socket "$KES_AGENT_SOCKET"

"$NODE_BIN" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --shelley-operational-certificate "$OPCERT" --shelley-vrf-key "$VRF_SKEY" \
  --shelley-kes-forge-config "$POOL_CONNECTION"
```

The singleton flags are optional only as a complete absent set (relay/no singleton producer). A configured singleton needs certificate, VRF key and exactly one KES source; supplying two source flags fails option parsing. Missing singleton inputs fail credential loading. A bulk-only producer omits **all** singleton credential flags. Singleton and bulk credentials can also be combined, but a repeated cold pool identity is rejected even when its source differs. Singleton kes-agent support is retained; no bulk kes-agent source exists.

Use `jq` to embed **real complete envelopes**, not filenames, abbreviated `cborHex` values or fabricated example keys. The following creates exact legacy, explicit-file and mixed inputs. The three pools in `mixed.json` must have distinct cold identities; file pool A, device pool B and file pool C must each have matching certificate/VRF/KES material. The output contains file KES and VRF secrets: use an owner-controlled directory, `umask 077`, and no publication in evidence.

```sh
umask 077
jq -n --slurpfile cert "$FILE_A_CERT" --slurpfile vrf "$FILE_A_VRF" \
  --slurpfile kes "$FILE_A_KES" \
  '[[$cert[0], $vrf[0], $kes[0]]]' > "$CREDENTIAL_DIR/legacy.json"

jq -n --slurpfile cert "$FILE_C_CERT" --slurpfile vrf "$FILE_C_VRF" \
  --slurpfile kes "$FILE_C_KES" \
  '[{version:1, operationalCertificate:$cert[0], vrfSigningKey:$vrf[0],
     kesSource:{type:"file", signingKey:$kes[0]}}]' \
  > "$CREDENTIAL_DIR/explicit-file.json"

jq -n --slurpfile legacy "$CREDENTIAL_DIR/legacy.json" \
  --slurpfile files "$CREDENTIAL_DIR/explicit-file.json" \
  --slurpfile cert "$DEVICE_B_CERT" --slurpfile vrf "$DEVICE_B_VRF" \
  --arg connection "$DEVICE_B_CONNECTION_FROM_BULK_DIR" \
  '$legacy[0] + [{version:1, operationalCertificate:$cert[0],
    vrfSigningKey:$vrf[0], kesSource:{type:"cardano-kes-forge",
    connectionFile:$connection}}] + $files[0]' \
  > "$CREDENTIAL_DIR/mixed.json"

"$NODE_BIN" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --bulk-credentials-file "$CREDENTIAL_DIR/mixed.json"
```

`DEVICE_B_CONNECTION_FROM_BULK_DIR=connections/pool-b.json`, for example, selects `$CREDENTIAL_DIR/connections/pool-b.json`; its `socketPath="../daemon.sock"` selects `$CREDENTIAL_DIR/daemon.sock`. Using `legacy.json` or `explicit-file.json` instead of `mixed.json` in the final command exercises those formats independently. No KES source flag belongs on the bulk-only command.

Static errors abort startup, not just one worker. Bulk syntax/source/envelope errors generally identify `FILE[index]` and the applicable field; connection read/parse/pool/network errors identify the resolved connection filename. Combined duplicate identities emit `The configured forging credentials contain a duplicate stake pool identity`, with no index; more than 32 device credentials emits `At most 32 cardano-kes-forge pool credentials may be configured`. Do not promise indexed diagnostics for these global checks. Neither errors nor evidence should dump the embedded secret envelopes.

A syntactically valid forge entry does not require a connected daemon/device to finish credential loading. Consensus attempts initial active-state recovery with a 500-ms client budget and constructs an external HotKey even on recovery failure, without a confirmed descriptor. Later operational updates reconcile again; failed reconciliation/evolution uses `KESExternalEvolutionError`, and recoverable signing failures abandon that pool's attempt before block submission. This implements unavailable startup/retry paths; proving synchronization, healthy file-pool opportunities and reconnect without restart requires the live mixed-node campaign, not merely parser success. There is no file fallback, source-changing reload or automatic fencing.

Source anchors: node `Parsers.hs` (`parseKesSourceFilePath`, singleton alternatives), `Protocol/Shelley/Credentials.hs` (`decodeBulkCredentials`, `parseEntry`, `parseSource`), `Protocol/Shelley/KesForge.hs` (`decodeKesForgePoolConfig`), `Protocol/Shelley.hs` (`readLeaderCredentialsSingleton`, `readLeaderCredentialsBulk`, `validateKesKeyBinding`, `validateCredentialIdentities`, `validateForgePool`); consensus `Protocol/Praos/Common.hs` (`instantiatePraosCredentials`) and `Protocol/Ledger/HotKey.hs` (`mkExternalHotKey`). Paths are relative to the node/consensus source roots in research R1.

### Explicit backup stop/recover/start procedure

Recovery is an operator-controlled source cutover, not daemon fallback. An immutable encrypted generation backup contains initial KES state, not the device's latest evolved secret. The recovered key is for that generation's **same public verification key and operational certificate**, only within its valid KES interval; it does not renew expiry or authorize a different generation. Have the exact generation backup, public KES verification envelope, pinned device identity document, expected device/pool/generation IDs and passphrase-protected recipient private file available on the isolated recovery workstation.

1. Stop the device-backed producer and disable any service supervisor/restart job that could restart it. Confirm it has exited and cannot sign concurrently; disconnect Pico and keep the original producer stopped throughout the backup interval. This is a manual custody/operational check: the software supplies no fencing or automatic revocation of the original signer. Stopping one mixed-node process also stops its file pools; arrange the separate recovery interval accordingly.
2. If the retained artifact has not already been copied safely, fetch it **before** disconnect/stop of its daemon using the primary/development executable: `"$PRIMARY_KES_FORGE" backup fetch --connection "$POOL_CONNECTION" --generation "$GENERATION_HEX32" --out-file "$BACKUP_ARTIFACT"`. This retrieves the retained encrypted artifact, not current secret state. Generation output already includes that artifact; fetching is not required when the validated copy is available.
3. On the isolated recovery workstation, run the recovery-profile executable below. It prompts interactively for the recipient passphrase; do not put a passphrase in flags, environment or logs. Recovery requires a fresh no-swap/non-dumpable process and a supported owner-controlled destination; output must not already exist. Treat nonzero exit, including uncertain durability, as failure requiring inspection, not permission to overwrite.

```sh
"$RECOVERY_KES_FORGE" backup recover \
  --artifact "$BACKUP_ARTIFACT" --recipient-key "$RECIPIENT_PRIVATE" \
  --device-identity-file "$DEVICE_IDENTITY" --expect-device "$DEVICE_HEX32" \
  --expect-pool "$POOL_HEX56" --expect-generation "$GENERATION_HEX32" \
  --verification-key-file "$GENERATION_VKEY" --out-file "$RECOVERED_KES_SKEY"
```

4. Securely transfer the resulting owner-only conventional `kes.skey` to the designated file producer. Start it using the **first singleton command above**, with `KES_SKEY` set to that recovered file and `OPCERT` set to the same generation's certificate. Retain the original VRF key and network settings; do not issue a replacement certificate simply to make the recovery test pass. For bulk, explicitly rebuild the affected entry as a file source, keeping the other pools' identities/material unchanged, then restart the node. No automatic source switch occurs.
5. Record a separate Pico-disconnected interval and independently accepted recovered-key blocks before claiming backup producer interoperability. Local signature verification or process startup alone is insufficient. Before any later device-backed restart, stop the file producer and again ensure single-producer custody; there is no automatic mutual exclusion.

Executable prerequisites and remaining validation: modified native node/consensus executable; real network/genesis/topology and pool stake/leader opportunities; matching conventional certificate/VRF/file keys; working kes-agent for its singleton regression; `jq`; primary/development daemon and authorized connection/socket with a fresh eligible device; recovery-profile executable, recipient key/passphrase and secure filesystem/memory environment; independent chain/block observer. The commands above were not run for this documentation change. The planned `xtask/src/qualify/node.rs` and `backup_producer.rs` runners are absent in the inspected tree; do not cite a nonexistent `xtask qualify node` command as executable evidence. Required evidence still includes all singleton sources, legacy/explicit/mixed bulk and bad-source startup results, unavailable startup, ten independently accepted blocks per mixed pool, zero outage-induced missed eligible file opportunities, same-PID reconnect with a later accepted device block, and same-certificate recovered-key accepted blocks with Pico disconnected. No production credentials, OTP operation or retired-A2 reuse is authorized by this procedure.


## Native changes and caller migration

- Node `Cardano.Node.Types`: add a forge source configuration alternative; `Parsers`: enforce individual-source exclusivity; `Protocol.Shelley`: extend bulk decoder to the union above and construct independent credential sources. `Configuration` consumers of `ProtocolFilepaths`, tests and help must follow the same native types. No fake `KesSigningKey` is constructed.
- Consensus `Protocol.Praos.Common`: add `PraosCredentialsExternal` with bounded client/configuration, not plaintext key material. It instantiates an external HotKey-compatible implementation; existing unsound/file and agent implementations remain semantically unchanged.
- Consensus `Protocol.Ledger.HotKey`: represent unavailable/evolved external state and immutable signing context without a secret. Introduce a typed signing failure result; migrate all callers rather than catching arbitrary exceptions or using a pure-I/O shim. Expected unavailable errors are values; programming exceptions retain native failure handling.
- Consensus Shelley/Praos/TPraos/header forging implementations and hard-fork wrappers: thread the typed failure to the generic block-forging boundary. Native ledger header encoding and `Signable` serialization define the exact bytes; do not hash twice or reconstruct a lookalike message in Rust.
- Diffusion `NodeKernel`: handle recoverable external failure surrounding the actual `Block.forgeBlock` call, not only `checkShouldForge`. Trace the failure and abandon that pool's attempt before `ChainDB.addBlockAsync`; preserve synchronization and future attempts. Keep forging contexts/workers independent so waiting for USB cannot serialize healthy file-based pool opportunities behind it.
- Node `Queries`, `Tracing/Tracers/KESInfo`, consensus error tracers and associated native tests: expose confirmed metadata/errors under the existing monitoring conventions below. Do not create a device-only replacement monitoring system.

Before implementation changes to exported native symbols, obtain language-server references and migrate every constructor/pattern match, test helper and hard-fork wrapper. Existing local forks are user changes: do not overwrite them to match upstream tags. Upstream release oracles remain a separate compatibility check.

## Atomic signing context and hot rotation

A forging attempt captures `(device, pool, incarnation, generation, certificate, certificate_digest, network_binding, absolute_period, confirmed_revision)` as one context. Its exact header body uses that certificate. Sign request names the same generation/digest/content/period and a deadline bounded by the current slot. Device signs only committed active state after any necessary evolution. Node validates envelope identities, length, deadline and `verifySignedKES` against the captured public key/relative period before constructing/submitting the block.

The daemon admits at most one signing attempt per pool, 32 total, before waiting for USB; queued bodies stay on the host and device dispatch is single-flight. The native caller's original monotonic slot deadline must include host admission/queueing, transport, evolution/activation and its own independent verification. Remaining device budget cannot restart the deadline. Runtime daemon latency samples include daemon verification and are diagnostic only; they do not replace this caller-side deadline or P1 measurement.

Rotation is serialized with each pool's generation selection, not a global lock. If rotation commits after context capture, the old request completes before the activation linearization point or fails `STALE_GENERATION`; never splice the new certificate into an already signed old header. Refresh/rebuild is allowed only as a fresh attempt within the original slot deadline, not an unbounded retry. Schedule processing is driven by authenticated operational period updates even in slots where the pool does not lead. Staging/certification does not change active context.

After lost acknowledgement or restart, reconcile device active generation/certificate/revision before resuming signing. Persist scheduled intent on the device and public descriptors/artifacts on host; device state wins over stale host files. Normal rotation requires no node restart, SIGHUP, separate PIN, management credential or second operator. The existing node SIGHUP path remains for existing source behavior, not the sole forge activation mechanism.

Successful certification durably publishes the exact canonical public operational certificate in the socket directory as `.kes-forge-<connectionName>-<generationId>.operational-certificate.cbor` before reporting CLI completion. Publication is owner-controlled, no-follow, atomic and idempotent only for identical bytes. Native reconciliation reads the generation-scoped file only after an authenticated active descriptor selects it; SHA-256 digest, KES verification key, start period and counter must all match that descriptor before the dynamic `OCert` replaces the old context. A staged file cannot change active signing, and a missing/mismatched file makes only that pool unavailable rather than reloading configuration or falling back.

## Failure scope

| Condition | Required behavior |
|---|---|
| Invalid static bulk entry or conflicting duplicate pool | Reject startup with a public error; bulk syntax/key-binding errors are indexed, combined duplicate-pool errors are global. |
| Device absent at startup / disconnected mid-signature | Dependent attempts fail; node stays alive/syncing; file-backed opportunities continue. |
| Wrong response key/period/generation/certificate/message, malformed signature or late result | Reject before block submission; invalidate affected observation/session as appropriate. |
| Pool-local storage/auth failure | Only that device-backed pool blocked; no selection of another key. |
| Device-wide security/entropy/hardware fault | All dependent pools unavailable; file-backed pools unchanged. |
| Reconnection | Reauthenticate identity/security, reconcile committed state and resume later eligible attempts without human unlock/restart. |
| Expiry with no certified replacement | Explicit expiry, no automatic generation/certificate/fallback. |

## Existing KES telemetry inventory

Source evidence in inspected node `Tracing/Tracers/KESInfo.hs:60–162`, `Tracing/Tracers/Consensus.hs:104–111,1487–1504`, `Queries.hs:153–186`, and CLI 11.4-compatible `EraBased/Query/Run.hs:347–559`, `Type/Output.hs:36–97`.

Let `S` be opcert start, `L` network max KES evolutions, `E=S+L`, `r` confirmed active-generation relative evolution, `C=S+r`, `R=max(0,E-C)`. All four forging metrics below are integer **KES periods**, not epochs, slots or days.

| Existing output | Meaning / value |
|---|---|
| `operationalCertificateStartKESPeriod` | `S` |
| `operationalCertificateExpiryKESPeriod` | `E` (exclusive signing upper bound) |
| `currentKESPeriod` | `C`, never current network period or unconfirmed requested target |
| `remainingKESPeriods` | `R`, from confirmed active key state |
| Machine `kind="KESInfo"` | When `R>7`; fields `startPeriod=S`, historical `endPeriod=C`, historical `evolution=E` |
| Machine `kind="ExpiryLogMessage"` | When `R<=7`; adds `keyExpiresIn=R`, same historical field mapping |
| Severity | Info when `R>7`; Warning for `2<=R<=7`; Alert for `R<=1` |
| `Forge.StateUpdateError` | Existing update-error trace/metric; value is failing slot number. When certificate KES info is available, start/expiry retained and `currentKESPeriod=0`, `remainingKESPeriods=0` are error sentinels, not successful period-zero readiness. |
| `KESCouldNotEvolve` / `KESKeyAlreadyPoisoned` | Preserve native meanings and context; add typed external-unavailable errors without relabeling unknown state as successful evolution. |

Emission is driven by existing `forgeStateInfoTracer` updates from `checkShouldForge`, with configured tracer filtering/detail/metrics behavior. Do not add a device polling emission timer or change warning cadence. Reconciled metadata becomes visible at the next applicable normal emission. Do not emit successful key-state observations from stale cached data. For an unavailable external signer with a known certificate, route through the update-error convention with public `S/E` and zero key-state sentinels. No certificate means no invented certificate metrics.

Credential labeling/aggregation: `TraceLabelCreds` includes `credentials` in machine logs and label text in human logs; `asMetrics` deliberately drops that label and forwards the existing metric names. `Protocol.Shelley` presently assigns the label `Shelley`; preserve the existing label/aggregation behavior rather than claiming newly pool-labeled Prometheus gauges. Internally keep pool/generation identity isolated. During qualification correlate emissions with controlled pool schedules/public attempt evidence to validate attribution even where the legacy metric backend is last-update/aggregated. Do not change file/agent labels or metric schemas as a side effect.

The unmodified CLI's `conway query kes-period-info` certificate lifetime query remains key-free; certificate issuance continues through its conventional `conway node issue-op-cert` command:

| Existing JSON field | Source / semantics |
|---|---|
| `qKesCurrentKesPeriod` | Chain-tip slot divided by network slots-per-KES-period; unlike forging `currentKESPeriod`, this is network period. |
| `qKesStartKesInterval`, `qKesEndKesInterval` | Certificate start and network-derived end; preserve native interval classification. |
| `qKesRemainingSlotsInKesPeriod` | Existing interval calculation in slots, not the device's evolution. Preserve native out-of-interval/null behavior. |
| `qKesOnDiskOperationalCertificateNumber` | Certificate counter from the specified public certificate. |
| `qKesNodeStateOperationalCertificateNumber` | Chain protocol-state counter or null when absent. |
| `qKesMaxKESEvolutions`, `qKesSlotsPerKesPeriod` | Queried genesis/network parameters. |
| `qKesKesKeyExpiry` | Existing era/time conversion when within interval; null for future/expired/error classifications or unavailable conversion. |

Certificate/time estimates remain computable while Pico is offline. Monitoring reads do not cause evolution. Host observation freshness follows the device-protocol contract's fixed 30000-ms monotonic-age rule: a remaining-validity/readiness join requires matching current confirmed state and an authorized operational node-period observation, both ages <30000 ms; equality is stale. Disconnect, changed boot/session, restart, missing observation or unresolved mutation makes readiness unavailable immediately, regardless of age. Lost ACK stays unknown until reconciled; a requested target is never confirmed state. Operator activation input and STATUS alone cannot refresh the network-period observation. Reject delayed old-generation observations after rotation and require a new context-matched join. Historical confirmed facts may remain labelled as such, but stale/unavailable joins expose no current readiness/remaining validity. Existing key-free CLI certificate estimates and conventional file/agent behavior remain unchanged.

A STATUS revision advance caused only by staging preserves the original active confirmed and node-period observation contexts and timestamps; it does not refresh either clock or replace the active join. The local status renderer accepts that older observation revision only for the same active generation and certificate, never a future revision. Credential epoch/revocation changes and activation invalidate the old join. Retired-generation rejection uses the authenticated immutable per-incarnation generation-number high-water mark and its generation ID: lower numbers and a different ID at the current number are rejected even at a higher pool revision. Human-readable status includes active/staged descriptors and all eight operation latency states and samples independently of readiness.

Each native external HotKey applies the same freshness/invalidation policy to its own in-memory observation context using its local monotonic clock, never a daemon's raw monotonic timestamp. Normal operational updates refresh observations even when the pool is not leader; there is no new device polling/emission timer. At the next existing tracer emission, stale/unavailable external state uses the established update-error/zero-sentinel convention rather than a successful KESInfo event. Wall-clock adjustments, repeated monitoring queries and late responses cannot freshen it. No device countdown, expiry timestamp, telemetry-only flash record or trusted wall clock is added. Operator-only latency diagnostics follow cli-backup.md without modifying existing KES metric names, labels or cadence.

## Acceptance matrix

Executable scenarios are in [quickstart.md](../quickstart.md) and [quality-gates.md](quality-gates.md). Required: actual Rust-owned `kes-forge key-gen-KES` generation with unchanged CLI 11.4.0.0 certificate/file/query interoperability; all three single-pool sources; unchanged legacy bulk; one mixed file/device node process with ten independently accepted blocks per pool; rejection of bulk kes-agent/conflicts; device outage with zero outage-induced missed eligible file-backed opportunities; reconnect without restart; evolution and hot rotation with correct per-pool contexts. Requiring a Cardano CLI source change fails acceptance; node/consensus patches remain required. SC-012 additionally requires two transitions, final valid period/expiry, rotation, power cycle, disconnect, failed evolution and lost ACK with independent expected telemetry. Separate homogeneous processes do not satisfy mixed bulk acceptance.

Freshness qualification additionally covers ages 29999/30000/30001 ms, a connected but silent native client, repeated status reads, wall-clock jumps with unchanged monotonic age, daemon/device/node restart, session replacement, unresolved mutation and delayed old-generation replies. Verify successful normal-context refresh, historical-fact retention without readiness, null stale operator validity and unchanged native error sentinels/cadence. These controlled-time behavior cases complement actual node/daemon exercises; they do not substitute for physical/public-network campaigns.
