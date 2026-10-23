# Operator CLI, Cardano Compatibility and Backup Contract v1

Cardano compatibility baseline: unmodified **cardano-cli-11.4.0.0**, commit `25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`. All commands added below belong to the planned Rust operator interface, not Cardano CLI. No cardano-cli source changes or fork are required: it remains the conventional key/certificate/query tool and an independent interoperability oracle. The existing `cardano-cli $era node key-gen-KES --verification-key-file ... --signing-key-file ...` remains unchanged and host-generated. No device failure invokes it as a fallback. The separate node/consensus external-signing integration still requires native changes.

## Commands and authority

`kes-forge` is the Rust operator binary, built from Cargo package `cardano-kes-forge`. Common device commands take `--connection FILE`, a configured pool connection containing the expected device/pool identity and socket/credential references, and optional `--json`. Management uses `--device-config FILE --authorization FILE` instead. Default production security policy rejects development/unverified devices. Only isolated test commands accept `--allow-development`; that flag cannot unlock release hardware.

| Command | Required inputs | Outputs / authority |
|---|---|---|
| `kes-forge key-gen-KES` | `--connection FILE --request-id HEX32 --generation-number UINT --verification-key-file FILE --encrypted-signing-key-file FILE --generation-file FILE` | Device-only generation: conventional public VK, encrypted `.kes-backup` artifact, public generation/completion manifest; pool authority. No `--signing-key-file`, era argument or host-generation fallback accepted. |
| `kes-forge status` | connection or device config | Public status; `--json` emits schema below. |
| `kes-forge backup fetch` | connection, `--generation HEX32 --out-file FILE` | Identical retained artifact, never current secret export. |
| `kes-forge certify` | connection, `--generation HEX32 --operational-certificate-file FILE` | Validated staged descriptor; pool authority. |
| `kes-forge activate` | connection, generation, `--current-period UINT` | Durable activation and public descriptor; pool authority. |
| `kes-forge schedule` | connection, generation, `--activation-period UINT` | Durable intent; pool authority. |
| `kes-forge recipient create` | `--public-key-file FILE --private-key-file FILE` | Recipient public JSON and passphrase-protected private file; backup workstation only. |
| `kes-forge backup recover` | `--artifact FILE --recipient-key FILE --device-identity-file FILE --expect-device HEX32 --expect-pool HEX56 --expect-generation HEX32 --verification-key-file FILE --out-file FILE` | Conventional owner-only `kes.skey`; backup workstation only. |
| `kes-forge recipient change-password` | `--private-key-file FILE` | Atomic rewrap of same recipient identity; backup workstation only. |
| `kes-forge management prepare` | device config, `--action ACTION --payload FILE --out-file FILE` | Public unsigned canonical management request with current sequence/revision; no mutation. |
| `kes-forge management sign` | `--request FILE --management-key FILE --out-file FILE` | Signed envelope on offline management workstation. Not required for routine rotation. |
| `kes-forge management apply` | device config, authorization file | Enroll, replace/revoke credential, replace recipient, discard staged, delete pool, retire device or authorize firmware; actions from device contract. |
| `kes-forge provision inspect` | `--usb-device SELECTOR --out-file FILE` | Read-only silicon/protection inventory and proposed readiness failures. |
| `kes-forge provision prepare` / `provision apply` | `--manifest FILE`; apply also `--authorize-irreversible` | Explicit attended provisioning, reviewed hardware-specific OTP plan, readback and signed provisioning record; never called by builds/startup. |
| `kes-forge firmware update` | device config, authorization file, `--image FILE --manifest FILE` | Verified signed update to inactive slot with rollback policy; never arbitrary flashing. |
| `kes-forge dev inspect` | connection, generation, `--allow-development --out-file FILE` | Restricted current disposable state with relative period; separate dev binary/firmware capability, absent from release. |

Routine lifecycle commands obtain expected revision and certificate digest through the configured authenticated connection. They may reconcile a concurrent revision and ask the operator to retry a conflict, but may not overwrite a changed active generation or create an extra staged generation. Their request ID is generated once and persisted in a restricted public operation record before dispatch. CLI device generation requires explicit request ID/generation number for crash-safe batch use. A lost response is resolved using the same identity. `--json` changes output formatting, not authority.

`kes-forge key-gen-KES` calls the local daemon protocol directly; it does not wrap or extend cardano-cli. It validates returned VK, artifact signature/bindings and device commitment before publishing output. If one output was published before a host crash, retry accepts it only when its validated content matches this exact operation; an unrelated existing file is an error. Success is reported only after all outputs and the public completion manifest are durable. It is not an all-files atomic filesystem transaction.

## Standard Cardano artifacts

`kes.vkey`: JSON text envelope with `type="KesVerificationKey_ed25519_kes_2^6"`, human description and `cborHex` encoding a 32-byte CBOR bytestring (`5820` followed by key bytes). `kes.skey`: `type="KesSigningKey_ed25519_kes_2^6"`, description and `cborHex` encoding the 608-byte initial state (`590260` followed by state bytes). The internal Rust period suffix is NOT copied into this file. JSON spacing/description are not cryptographic identity; compare parsed bytes/type. The independent CLI 11.4 and node 11.1.3 oracles must both accept these files.

`node.cert`: unchanged `NodeOperationalCertificate` envelope encoding `(OCert, cold verification key)`. Issuance remains `cardano-cli $era node issue-op-cert` on the existing cold-key workstation. The certificate signs hot VK/counter/start period, not a network identifier. Network authorization is an additional enrolled binding, never a fictional certificate field.

## Immutable encrypted backup encoding

Binary `.kes-backup`: eight-byte ASCII magic `KESBKP01`, then deterministic CBOR map, <=2048 bytes total. Map fields:

| Field | Encoding |
|---|---|
| `version` | unsigned integer 1 |
| `kem`, `kdf`, `aead` | unsigned integers 32, 1, 3 |
| `device`, `incarnation`, `generation` | 16-byte bytestrings |
| `pool` | 28-byte bytestring |
| `generation_number` | u64 |
| `verification_key`, `recipient_public_key` | 32-byte bytestrings |
| `recipient_id` | SHA-256 of raw recipient public key, 32 bytes |
| `period` | unsigned integer 0, only initial-state backups permitted |
| `encapsulation` | 32-byte HPKE encapsulated key |
| `ciphertext` | exactly 608 encrypted bytes plus 16-byte AEAD tag |
| `device_signature` | 64-byte Ed25519 signature |

Define `header` as deterministic CBOR of fields from `version` through `period`. HPKE `info` is ASCII `cardano-kes-forge/backup/v1` concatenated with `header`; AAD is magic concatenated with `header`. Encrypt exactly the raw 608-byte initial state. Sign `"cardano-kes-forge/backup-signature/v1" || magic || deterministic-CBOR(map without device_signature)` with the pinned device identity. Reject unknown versions/suites, missing/duplicate/extra fields, malformed/noncanonical values and trailing bytes. HPKE base encryption alone does not authenticate the device; validate this signature against the externally trusted identity file before recovery. Artifact metadata must match caller expectations and supplied conventional VK; after decryption, derive VK independently and compare again.

There is one artifact per generation, produced and committed before any generation output is advertised. No replacement recipient, password change or period transition modifies those bytes. Retain/archive old recipient keys as long as their artifacts are needed. Retired artifacts may be reclaimed from device storage after rotation; the host warns before reclamation, not after data loss.

## Recipient files and passphrases

Public file: JSON `{ "version":1, "algorithm":"X25519", "publicKey":"<64 lowercase hex>", "recipientId":"<64 lowercase hex>" }`. Private file: magic `KESRCP01` followed by deterministic CBOR containing `version=1`, `kdf="argon2id"`, `argon_version=19`, `memory_kib=65536`, `iterations=3`, `parallelism=4`, `salt` (16 bytes), `aead="XChaCha20Poly1305"`, `nonce` (24 bytes), `public_key` (32 bytes), `recipient_id` (32 bytes), and `ciphertext` (32 private bytes plus 16-byte tag). The entire public header including magic is AAD. Enforce exact supported KDF parameters before allocating; do not permit a hostile file to request unbounded RAM/work. A later KDF change requires an explicit format-version decision.

Passphrases come from an echo-disabled controlling terminal, never argv, environment variables, stdout, logs or a daemon. Creation/password replacement confirms a non-empty passphrase; recommend a long unique passphrase. Byte interpretation is UTF-8 without normalization; confirmation compares exact bytes. Recovery prompts once for the existing password; password change requires successful old-key decryption first. Empty input cancels without mutation. Reject noninteractive invocation rather than falling back to an environment variable. Machine automation of password entry is not part of v1.

Create keypairs with the backup OS CSPRNG. Verify protected-file decryption and derived public identity in memory before publication. Password change generates fresh salt/nonce, decrypts/re-encrypts the same private key, verifies the new protected file, fsyncs it, atomically replaces the old encrypted file and fsyncs the directory. Only encrypted staging files may be named on disk. An interruption preserves a valid old or new protected file. It cannot revoke a copied old file/password pair.

## Secret-safe output publication

Recovery runs only on the designated separate backup/recovery workstation, selected through operator procedure and installation/OS access control; a CLI cannot cryptographically prove what physical host it runs on. Production primary packaging does not install recipient recovery/private-key workflows and must not possess recipient secrets. An operator can violate custody by manually copying secrets; the platform makes no impossible host-location guarantee against that action.

Before publishing plaintext, verify artifact structure/signature, expected identities, recipient key, AEAD tag and derived VK. Use locked, non-dumpable zeroizing memory; fail if required memory protection cannot be established. Disable core dumps and avoid swap exposure. Never log raw inputs. Restrict output parent directory to its owner and reject symlinks/path traversal through untrusted parents.

Publish only a complete owner-readable/writable (`0600`) intended output inode. On supported Linux local filesystems use an unnamed `O_TMPFILE` inode in the protected destination directory, write only the validated final key, fsync, and `linkat` without replacement followed by directory fsync. This inode is the intended output, not an incidental plaintext scratch file; no named plaintext temporary, shell pipeline or serialized secret intermediate is permitted. If anonymous/no-replace publication is unsupported, fail explicitly rather than using an unsafe fallback. Existing output path always fails for recovery. On write/validation failure no pathname is linked; release/zeroize unlocked material on every exit. A failure after linking/fsync uncertainty may leave a complete validated output, never a partial key; report publication uncertainty without overwriting it on retry.

The deliberate development output follows identical protection rules but includes current period and device/generation identity in a distinct `KESDEV01` format. It is not a node-loadable period-zero backup and is never accepted by release firmware/import paths. It uses only disposable runtime-generated keys and is excluded from version control and ordinary diagnostic bundles.

## Machine output and errors

Successful `--json` output is one JSON object on stdout: `version`, `operation`, `requestId`, `deviceId`, `poolId` (nullable), `generationId` (nullable), `revision` (nullable), `result`. Public status result includes `securityMode` (`development`, `release-unprovisioned`, `release-ready`), `releaseEvidenceVerified`, health, active/staged descriptors, certificate start, confirmed relative period, backup availability, blocking reason, and host-derived remaining validity with `observationState` (`fresh`, `stale`, `unavailable`) and observation time. Never expose credential bytes or private material. Passphrase prompts and diagnostics use stderr/terminal, not machine stdout.

Operator binary exit codes, including `kes-forge key-gen-KES`: 0 completed; 2 usage/static configuration; 3 authentication/security; 4 conflict/not-yet-valid/expiry/capacity; 5 unavailable/deadline/entropy; 6 damaged state or integrity failure; 7 filesystem/publication failure. Nonzero machine output is a bounded JSON error with stable `code`, scope and public context. Existing cardano-cli commands retain their native exit-code and output conventions unchanged.

Wrong password/recipient, modified artifact, missing archive/recipient key, output collision, unavailable device and lost acknowledgement are distinct explicit errors. No error claims to erase external copies. Primary and recovered backup evolve independently; stop one producer before starting the other. Password/recipient changes cannot undo leaked KES secrets; suspected compromise requires a fresh generation and matching externally issued certificate.
