# Hardware Security and Provisioning Contract

Scope: FR-018, FR-027–FR-030, SC-004 and SC-010. These are required hardware states and qualification procedures, **not observed passing readings**. Primary references: [RP2350 security white paper, release 1](https://pip-assets.raspberrypi.com/categories/1214-rp2350/documents/RP-009377-WP-1-Understanding%20RP2350_s%20security%20features.pdf), [RP2350 datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf), especially chapters 5/10 and applicable errata, and [picotool](https://github.com/raspberrypi/picotool). Pin downloaded manuals, silicon revision, tool 2.3.1 and policy/image hashes in provisioning evidence; register encodings must come from that supported silicon's definitions, not guessed numeric OTP addresses.

## Trust and threat model

Protect device secrets against a compromised authorized primary, malicious USB traffic, wrong-pool credentials, management replay, exposed debug/boot interfaces, unsigned firmware and command-driven rollback. Primary compromise still allows authorized signatures, premature forward evolution, routine staging/rotation when a valid external certificate is available, and denial of service. Shared hardware remains a shared availability dependency. No chain/time oracle or double-forging prevention is added.

Physical flash substitution, invasive die/OTP imaging, laboratory fault injection and side-channel resistance are not claimed. Ordinary power interruption is **not** excluded. Encrypted initial backups intentionally remove deployment-wide non-exportability/forward-erasure guarantees. Device erasure cannot revoke a copied backup, recipient private key or plaintext recovered key.

Separate authorities: pool cold signing key (external certificates), offline management key (enrollment/policy/deletion/update authorization), firmware signing key (ROM-verifiable executable authorization), pool machine key (routine operation) and backup recipient key. One human may hold multiple roles, but the primary must not hold offline authority or recovery secrets. Routine rotation is not a management ceremony.

## Capability inventory

| Capability | Required release state | Evidence and negative exercise |
|---|---|---|
| Supported silicon/ROM | RP2350 A4 or later with reviewed errata; identify fitted Pico 2, 4 MiB flash, stock clock | Read silicon/ROM identity in attended inspection and signed boot report. Reject A2/A3/unknown. The white paper documents A4 boot ROM fixes; a retail board label is insufficient. |
| Authorized signed boot | ROM secure boot enabled; correct secp256k1/SHA-256 boot-key fingerprint provisioned and marked valid; unused unauthorized key slots invalidated | Verify `CRIT1.SECURE_BOOT_ENABLE`, BOOTKEY fingerprints and `BOOT_FLAGS1.KEY_VALID/KEY_INVALID` via trusted readback. Cold boot authorized signed image; attempt unsigned/wrong-key/development image and observe refusal. Device Ed25519 identity key is not the ROM ECDSA boot key. |
| Firmware rollback | ROM-enforced security version with monotonic OTP rollback state; update manifests and image metadata agree | Read version/rollback policy; install higher allowed version, reject prohibited older signed image after reboot. Refuse update before exhausting rollback capacity. Ordinary pool periods never consume OTP version bits. |
| Debug closure | Secure and non-secure invasive/non-invasive debug closed; no escrow debug key capable of extracting release secrets | Verify `CRIT1.DEBUG_DISABLE` and `CRIT1.SECURE_DEBUG_DISABLE` and relevant debug policy; attempt SWD/debug memory access and reset sequences. Production does not ship a recoverable debug-unlock credential. |
| Alternate boot/recovery | Unneeded USB/UART/RAM boot paths disabled in `BOOT_FLAGS0`; BOOTSEL cannot read secrets, replace firmware with unauthorized code, write protected partitions or reset OTP policy | Exercise BOOTSEL, USB reset/control requests, UART boot, watchdog reboot modes and ROM-call wrappers. Only the bounded authenticated application updater remains. No raw PICOBOOT/flash/OTP command forwarding. |
| OTP trust storage | Per-device fresh root and identity, protected management/boot trust; secure-only read and irreversible write locks as applicable; non-secure/bootloader denied | Verify page locks/key policy, read controls and boot-stage soft locks. Derive separate storage/session/device-identity keys with HKDF domain separation, clear root RAM and soft-lock root page after derivation. Never provision production root through a previously compromised primary. |
| TrustZone / memory isolation | Secure code owns key state, flash journal, TRNG, OTP, crypto and access policy. USB framing executes non-secure; narrow secure gateway validates lengths/identity and copies each admitted request once into bounded secure storage | Configure SAU/secure+nonsecure MPU, non-executable data, stack guards and Secure gateway regions; attempt nonsecure CPU/DMA reads/writes into key RAM/flash/OTP and secure peripherals. No secret pointer crosses gateway. Disabled/unused core remains inaccessible; any enabled second core obeys the same policy. |
| Bus masters/access control | Lock down ACCESSCTRL, DMA channels, XIP/QMI, SRAM banks, debug/trace windows, clock/reset/TRNG/OTP peripherals; unused endpoints disabled | Readback policy before readiness; negative nonsecure/DMA access tests. Lock access-control configuration against nonsecure changes. Review ROM APIs/flash routines for caller-controlled address bypasses. |
| Persistent secret confidentiality/integrity | AEAD-encrypted per-pool journals, root-derived keys, authenticated object references and revisions, no public raw read/restore path | USB abuse, altered record and rollback-command trials; expose no decrypted snapshot. Verify old physical secret bank erased and old RAM wiped before ACK on sacrificial development fixtures; verify equivalent operation sequencing without extraction on release. |
| Hardware entropy | TRNG health checks enabled, qualified sampling, bounded errors; no pseudo-random/time fallback | Inject health failures and timeout; generation/session establishment fail `ENTROPY_FAILURE`, never produce successful output. Record configuration/health counters without raw entropy. Revalidate with CPU sleep and active workloads. |
| Glitch detectors / brownout | Enable applicable glitch detectors from OTP (not only late application startup), qualify sensitivity; BOD enabled at safe supported threshold | Record `CRIT1.GLITCH_DETECTOR_ENABLE/GLITCH_DETECTOR_SENS`, BOD settings and reset cause; power-interruption trials verify safe recovery. This does not certify laboratory glitch resistance. |
| Redundancy coprocessor | Use RCP checks around security-state validation, authorization/commit/cleanup sequencing and fail-stop paths; no random instruction delay workaround | Review emitted code/critical sequence tests. White paper warns against RCP pseudorandom delays under RP2350-E3; keep delays disabled. Deliberately broken check in sacrificial qualification build must halt/reset without secret release. |
| Firmware/update provenance | Signed release image and partition policy, reproducible manifest, no dev extraction linkage | Inspect release artifact symbol/link map as supplemental evidence; actual extraction/debug/unauthorized-update attempts must fail. Manifest records source and dependency hashes, toolchain, secure/nonsecure image digests and security policy version. |

### Justified non-applicability

- **RISC-V cores:** not used; secure boot disables that execution path. Arm security mechanisms are required, not optional substitutes.
- **Encrypted application boot:** not selected for public open-source firmware with no embedded secret literals; it protects code confidentiality and SRAM-only execution against physical flash switching, which is outside this threat model. Device-held mutable secrets are separately encrypted/authenticated with protected per-device OTP roots. If production embeds confidential material or expands physical-flash threat scope, this decision becomes invalid and requires a RAM/encrypted-image feasibility redesign before release.
- **OTP chaff/FIB-imaging countermeasures:** physical invasive imaging is excluded. Unique per-device roots remain required. Chaff may be applied only through a reviewed supported provisioning recipe, not as an unsupported claim that invasive extraction is prevented.
- **Unlocked debug, ROM download and development extraction:** applicable development facilities, explicitly forbidden release facilities. Keeping them available for convenience is not a non-applicability justification.
- **Telemetry clock/countdown storage:** not a security capability needed here; no trusted wall clock is claimed. Monotonic uptime for deadlines is distinct from authenticated node-supplied KES period.

Any required row not established means release readiness is false. Do not replace a failed protection with a host flag or acceptance waiver.

## Security modes and evidence verification

Three externally visible states:

1. `development`: unlocked boot/debug permitted; disposable keys only; explicit host development opt-in; controlled current-state inspection enabled in a separate build surface.
2. `release-unprovisioned`: release firmware lacks complete/matching hardware evidence. No production generation/signing; status and explicit provisioning diagnostics only.
3. `release-ready`: every required protection matches approved policy and image; firmware checks before secret service, and host verifies pinned identity, fresh signed challenge, provisioning record and allowed image/security-version policy.

The provisioning record contains device identity/public keys, silicon/ROM, allowed boot trust fingerprint, policy digest, measured lock states, approved firmware digest/security version, flash part/capacity, verifier/tool identity and ceremony signature. It is issued only after trusted direct readback and negative checks. Online evidence binds a fresh host challenge, boot nonce, active image/version and current security-state digest to that pinned device. A self-signed string saying `release-ready` is not hardware attestation; its trust depends on the attended enrollment and hardware-enforced signed-code boundary. Host rejects missing/stale/replayed/mismatched evidence. The device itself independently checks readiness so a compromised host cannot enable service by ignoring evidence.

No transition from release to development is offered. Management cannot restore debug, load a dev image signed by a different development root, or request current plaintext extraction. Release images exclude inspection handlers and secret-debug formatting at compile/link time; compiler release optimization is unrelated to security mode.

## Attended development-to-release transition

1. Inspect exact silicon/flash and approved provisioning manifest without mutation. Default builds/flashing never burn OTP.
2. Back up public operational records/approved encrypted artifacts as needed; stop development use. Delete every disposable development KES state and credential, including host inspection outputs according to trusted-workstation procedure. Do not promote any development KES key.
3. Determine whether every potentially exposed trust root can be replaced. If an immutable exposed root cannot be superseded safely with fresh protected material, reject that board for release and use fresh hardware.
4. On a trusted isolated provisioning machine, install authorized signed release images/policy, generate fresh per-device roots and credentials, enroll authorized management/firmware trust and recipient public keys. Keep production recipients/cold/private management material off the primary.
5. Present exact irreversible OTP changes to the operator; require explicit provisioning authorization. Program/read-verify in documented vendor order, enabling secure boot only after valid authorized image/key setup. Interrupted provisioning is `release-unprovisioned`, never success.
6. Apply/verify debug/boot/OTP/access/TRNG/fault policies; execute hardware negative matrix; seal signed provisioning record. Cold boot and verify from normal production host integration.
7. Only now generate fresh release KES keys and encrypted backups. Prove unattended reconnect/sign/evolve and approved encrypted backup still work after lockdown.

A board that cannot meet this sequence is ineligible; there is no reset/import bypass to recover a lost root or recipient private key.

## Authenticated update contract

Management authorization binds device, next management sequence, signed image/partition-manifest digests, storage schema and proposed security version. Firmware signature is independently checked against approved ROM trust. Upload only to bounded inactive firmware slot, sequential checked offsets, readback/hash before trial. Reject development images regardless of a mutable mode string. No host chooses arbitrary flash addresses.

Maintain at least one fully verified bootable image at every interruptible step. Trial-boot the new version without admitting incompatible storage mutations; v1 updates retain the same storage schema. Once health/security checks pass, preserve a verified new image while bringing both boot candidates into compliance with the impending OTP minimum, then advance the rollback floor in the vendor-supported monotonic order. Resume interrupted finalization from authenticated intent; never lower the floor. Power cuts at each upload/trial/copy/OTP/finalization step must retain an admissible image or fail closed without exposing/restoring older secrets. Automatic recoverability of the chosen ordinary update sequence must be demonstrated; this plan does NOT adopt the prototype's blanket replacement-on-finalization exception. If the vendor mechanism cannot satisfy the approved update policy, stop for an explicit design/hardware decision rather than silently weakening it.

Version/schema mismatch blocks an update before writes; a future storage migration needs its own atomicity/backward-boot design. Firmware changes are allowed maintenance downtime and may affect all device-backed pools; file-backed pools continue.

## Release evidence

Run negative matrix against qualified release hardware, not just emulation or development debug reads. Report attempts, actual observed results, device/firmware identity, public context and counterexamples, excluding secrets. Require zero unauthorized signatures, cross-pool mutations, recipient redirections and primary plaintext disclosures. Approved encrypted backup plus recipient-side recovery must succeed and be classified separately. Independent review must cover the adapted KES dependency, session transcript, journal cleanup, trust provisioning, update/rollback and node failure propagation. Unverified/missing hardware means NOT QUALIFIED, never a passing security reading.
