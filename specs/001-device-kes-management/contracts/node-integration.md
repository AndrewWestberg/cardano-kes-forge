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

A forge connection file is public configuration version 1 with mandatory `version=1`, `socketPath`, `deviceId`, `deviceIdentityFile`, `poolId`, `incarnationId`, `networkBinding`, `connectionName`, `credentialFile`, `securityPolicy` (`release-required` default, or explicit isolated development policy). Exact encodings, validation, credential creation and daemon/device bootstrap schemas are defined in [cli-backup.md](cli-backup.md); use that one schema, not a native-only variant. The credential file is owner-only and used by the daemon; it is never embedded in bulk JSON. Resolve relative paths against the containing configuration file directory; do not inherit another entry's connection, certificate or mutable state.

Parse every entry and validate its certificate/cold identity, source exclusivity, file key binding, network binding and duplicate pool IDs before creating forging workers. Reject conflicting duplicate pool identity across combined singleton/bulk input, naming `FILE[index].field` without dumping envelopes or credentials. Device registration limit applies only to distinct device-backed pools; do not cap legacy file-backed entries at 32. Explicit file entries contain plaintext file-based KES state as they always did; the no-primary-secret claim applies to device-backed state, not other pools' VRF/file keys.

Static well-formedness does not require a live Pico/daemon. A valid forge entry can start in unavailable state while synchronization and file-backed pools run. A stale host certificate is a bootstrap hint bound to that pool; it cannot restore an older active generation. On authenticated reconciliation adopt the device's committed public descriptor only after validating cold identity/network/counter, never an arbitrary returned certificate.

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

## Failure scope

| Condition | Required behavior |
|---|---|
| Invalid static bulk entry or conflicting duplicate pool | Reject startup with entry-specific public error. |
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

Each native external HotKey applies the same freshness/invalidation policy to its own in-memory observation context using its local monotonic clock, never a daemon's raw monotonic timestamp. Normal operational updates refresh observations even when the pool is not leader; there is no new device polling/emission timer. At the next existing tracer emission, stale/unavailable external state uses the established update-error/zero-sentinel convention rather than a successful KESInfo event. Wall-clock adjustments, repeated monitoring queries and late responses cannot freshen it. No device countdown, expiry timestamp, telemetry-only flash record or trusted wall clock is added. Operator-only latency diagnostics follow cli-backup.md without modifying existing KES metric names, labels or cadence.

## Acceptance matrix

Executable scenarios are in [quickstart.md](../quickstart.md) and [quality-gates.md](quality-gates.md). Required: actual Rust-owned `kes-forge key-gen-KES` generation with unchanged CLI 11.4.0.0 certificate/file/query interoperability; all three single-pool sources; unchanged legacy bulk; one mixed file/device node process with ten independently accepted blocks per pool; rejection of bulk kes-agent/conflicts; device outage with zero outage-induced missed eligible file-backed opportunities; reconnect without restart; evolution and hot rotation with correct per-pool contexts. Requiring a Cardano CLI source change fails acceptance; node/consensus patches remain required. SC-012 additionally requires two transitions, final valid period/expiry, rotation, power cycle, disconnect, failed evolution and lost ACK with independent expected telemetry. Separate homogeneous processes do not satisfy mixed bulk acceptance.

Freshness qualification additionally covers ages 29999/30000/30001 ms, a connected but silent native client, repeated status reads, wall-clock jumps with unchanged monotonic age, daemon/device/node restart, session replacement, unresolved mutation and delayed old-generation replies. Verify successful normal-context refresh, historical-fact retention without readiness, null stale operator validity and unchanged native error sentinels/cadence. These controlled-time behavior cases complement actual node/daemon exercises; they do not substitute for physical/public-network campaigns.
