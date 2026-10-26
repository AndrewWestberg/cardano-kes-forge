//! Independent pinned release oracles. Disposable lab inputs only; never use
//! this interface as a production key service. Secret types have no Debug or
//! serde implementations. Driver stderr and malformed stdout are never echoed.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 16384;
const FAILURE: &str = "native oracle rejected request or transport failed";
type Result<T, E = String> = std::result::Result<T, E>;
/// Exactly the native canonical state, without any Rust period suffix.
pub struct SecretState(Zeroizing<[u8; 608]>);
impl SecretState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        protect_memory()?;
        let mut state = Self(Zeroizing::new([0; 608]));
        if bytes.len() != 608 {
            return Err(FAILURE.into());
        }
        state.0.copy_from_slice(bytes);
        Ok(state)
    }
    pub fn as_bytes(&self) -> &[u8; 608] {
        &self.0
    }
}

/// Disposable lab only: require kernel-enforced no-swap isolation for the
/// complete process tree before secret exchange, and prohibit process dumps.
/// Run in a fresh cgroup-v2 unit with MemorySwapMax=0 and LimitCORE=0. This is
/// not the production recovery/credential locked-buffer implementation.
pub fn protect_memory() -> Result<()> {
    static PROTECTION: std::sync::LazyLock<Result<()>> = std::sync::LazyLock::new(|| {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| "oracle memory protection unavailable".to_owned())?;
        let membership = fs::read_to_string("/proc/self/cgroup")
            .map_err(|_| "oracle no-swap isolation unavailable".to_owned())?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or("oracle requires cgroup-v2 no-swap isolation")?;
        let path = Path::new(relative);
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("oracle isolation path invalid".into());
        }
        let root = Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").map_err(|_| FAILURE)?);
        for name in ["memory.swap.max", "memory.swap.current"] {
            if fs::read_to_string(root.join(name))
                .map_err(|_| FAILURE)?
                .trim()
                != "0"
            {
                return Err("oracle requires a fresh MemorySwapMax=0 lab unit".into());
            }
        }
        Ok(())
    });
    PROTECTION.clone()
}

#[derive(Clone, Copy, Debug)]
pub enum Baseline {
    Cli114,
    Node1113,
}
impl Baseline {
    fn project(self) -> &'static str {
        match self {
            Self::Cli114 => "cli-11.4",
            Self::Node1113 => "node-11.1.3",
        }
    }
    fn identity(self) -> &'static [u8] {
        match self {
            Self::Cli114 => b"kes-oracle/v1 cli-11.4 API11.9.0.0 crypto2.6.0.0 Sum6KES",
            Self::Node1113 => b"kes-oracle/v1 node-11.1.3 API11.6.0.0 crypto2.5.1.0 Sum6KES",
        }
    }
}

pub struct Oracle {
    executable: PathBuf,
    pub identity: Value,
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}
fn digest_file(path: &Path) -> Result<String> {
    let mut input =
        fs::File::open(path).map_err(|_| "oracle identity input unavailable".to_owned())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16384];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| "oracle identity input unavailable".to_owned())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex(&hash.finalize()))
}
impl Oracle {
    /// Uses only separately recorded, actually built local-driver identities.
    /// Never resolves an installed cardano-cli or substitutes a baseline binary.
    pub fn pinned(baseline: Baseline) -> Result<Self> {
        protect_memory()?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or(FAILURE)?;
        let identity_path = root
            .join("target/oracles/drivers")
            .join(baseline.project())
            .join("identity.json");
        let bytes = fs::read(identity_path)
            .map_err(|_| "built oracle driver identity unavailable".to_owned())?;
        let identity: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid oracle driver identity".to_owned())?;
        if identity["schema_version"] != 1 || identity["project"] != baseline.project() {
            return Err("oracle driver identity mismatch".into());
        }
        let executable = PathBuf::from(identity["executable"].as_str().ok_or(FAILURE)?);
        let executable = executable.canonicalize().map_err(|_| FAILURE.to_owned())?;
        let build_root = root
            .join("target/oracles/drivers")
            .join(baseline.project())
            .canonicalize()
            .map_err(|_| FAILURE.to_owned())?;
        if !executable.starts_with(build_root) || identity["sha256"] != digest_file(&executable)? {
            return Err("oracle driver executable mismatch".into());
        }
        let inputs = identity["inputs"].as_object().ok_or(FAILURE)?;
        let package_file = match baseline {
            Baseline::Cli114 => "kes-oracle-cli.cabal",
            Baseline::Node1113 => "kes-oracle-node.cabal",
        };
        for name in [
            "app/Main.hs",
            package_file,
            "driver.project",
            "cabal.project",
            "cabal.project.freeze",
            "provenance.json",
        ] {
            let path = root
                .join("xtask/oracles")
                .join(baseline.project())
                .join(name);
            if inputs.get(name).and_then(Value::as_str) != Some(digest_file(&path)?.as_str()) {
                return Err("oracle driver source identity mismatch".into());
            }
        }
        if identity["plan_sha256"]
            != digest_file(
                &root
                    .join("target/oracles/drivers")
                    .join(baseline.project())
                    .join("cache/plan.json"),
            )?
        {
            return Err("oracle driver plan identity mismatch".into());
        }
        let oracle = Self {
            executable,
            identity,
        };
        if oracle.exchange(0, &[])?.as_slice() != baseline.identity() {
            return Err("oracle driver release mismatch".into());
        }
        Ok(oracle)
    }

    fn exchange(&self, operation: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if payload.len() > MAX_FRAME - 2 {
            return Err(FAILURE.into());
        }
        let mut child = Command::new(&self.executable)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| FAILURE.to_owned())?;
        let result = (|| {
            let mut input = child.stdin.take().ok_or(FAILURE)?;
            input
                .write_all(&((payload.len() + 2) as u32).to_be_bytes())
                .map_err(|_| FAILURE)?;
            input.write_all(&[1, operation]).map_err(|_| FAILURE)?;
            input.write_all(payload).map_err(|_| FAILURE)?;
            drop(input); // Exact EOF is part of the one-request protocol.
            let mut output = child.stdout.take().ok_or(FAILURE)?;
            let mut header = [0; 4];
            output.read_exact(&mut header).map_err(|_| FAILURE)?;
            let length = u32::from_be_bytes(header) as usize;
            if !(2..=MAX_FRAME).contains(&length) {
                return Err(FAILURE);
            }
            let mut envelope = [0; 2];
            output.read_exact(&mut envelope).map_err(|_| FAILURE)?;
            if envelope != [1, 0] {
                return Err(FAILURE);
            }
            let mut response = Zeroizing::new(vec![0; length - 2]);
            output.read_exact(&mut response).map_err(|_| FAILURE)?;
            let mut trailing = [0];
            if output.read(&mut trailing).map_err(|_| FAILURE)? != 0 {
                return Err(FAILURE);
            }
            Ok(response)
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().map_err(|_| FAILURE.to_owned())?;
        if !status.success() {
            return Err(FAILURE.into());
        }
        result.map_err(str::to_owned)
    }
    pub fn generate(&self) -> Result<([u8; 32], SecretState)> {
        self.generated(1, &[])
    }
    /// Cross-implementation lab generation from fresh caller-owned OS entropy.
    /// The seed is transported only through the private input pipe.
    pub fn generate_from_seed(
        &self,
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<([u8; 32], SecretState)> {
        self.generated(11, &seed[..])
    }
    fn generated(&self, operation: u8, payload: &[u8]) -> Result<([u8; 32], SecretState)> {
        let bytes = self.exchange(operation, payload)?;
        if bytes.len() != 640 {
            return Err(FAILURE.into());
        }
        Ok((
            bytes[..32].try_into().map_err(|_| FAILURE)?,
            SecretState::from_bytes(&bytes[32..])?,
        ))
    }
    pub fn derive_vk(&self, state: &SecretState) -> Result<[u8; 32]> {
        self.exchange(2, state.as_bytes())?
            .as_slice()
            .try_into()
            .map_err(|_| FAILURE.into())
    }
    pub fn evolve(&self, state: &SecretState, current: u8) -> Result<Option<SecretState>> {
        check_period(current)?;
        let mut request = Zeroizing::new(Vec::with_capacity(609));
        request.push(current);
        request.extend_from_slice(state.as_bytes());
        let response = self.exchange(3, &request)?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, bytes @ ..] if bytes.len() == 608 => Ok(Some(SecretState::from_bytes(bytes)?)),
            _ => Err(FAILURE.into()),
        }
    }
    pub fn sign(&self, state: &SecretState, period: u8, message: &[u8]) -> Result<[u8; 448]> {
        check_period(period)?;
        check_message(message)?;
        let mut request = Zeroizing::new(Vec::with_capacity(609 + message.len()));
        request.push(period);
        request.extend_from_slice(state.as_bytes());
        request.extend_from_slice(message);
        self.exchange(4, &request)?
            .as_slice()
            .try_into()
            .map_err(|_| FAILURE.into())
    }
    pub fn verify(
        &self,
        vk: &[u8; 32],
        period: u8,
        message: &[u8],
        signature: &[u8; 448],
    ) -> Result<bool> {
        check_period(period)?;
        check_message(message)?;
        let mut request = Vec::with_capacity(481 + message.len());
        request.push(period);
        request.extend_from_slice(vk);
        request.extend_from_slice(signature);
        request.extend_from_slice(message);
        boolean(&self.exchange(5, &request)?)
    }
    pub fn opcert_signable(&self, vk: &[u8; 32], counter: u64, start: u64) -> Result<[u8; 48]> {
        self.exchange(6, &cert_input(vk, counter, start))?
            .as_slice()
            .try_into()
            .map_err(|_| FAILURE.into())
    }
    pub fn validate_vk_file(&self, json: &[u8]) -> Result<[u8; 32]> {
        self.exchange(7, json)?
            .as_slice()
            .try_into()
            .map_err(|_| FAILURE.into())
    }
    /// Input must already be in protected transient memory; never read private
    /// fixture files. Returns only the independently derived public key.
    pub fn validate_signing_key_file(&self, json: &[u8]) -> Result<[u8; 32]> {
        self.exchange(8, json)?
            .as_slice()
            .try_into()
            .map_err(|_| FAILURE.into())
    }
    /// Native decode plus actual cold DSIGN verification. No network assertion.
    pub fn validate_certificate_file(&self, json: &[u8]) -> Result<CertificateValidation> {
        let bytes = self.exchange(9, json)?;
        if bytes.len() != 81 {
            return Err(FAILURE.into());
        }
        Ok(CertificateValidation {
            valid: boolean(&bytes[..1])?,
            cold_vk: bytes[1..33].try_into().map_err(|_| FAILURE)?,
            signable: bytes[33..].try_into().map_err(|_| FAILURE)?,
        })
    }
    pub fn issue_disposable_certificate(
        &self,
        vk: &[u8; 32],
        counter: u64,
        start: u64,
    ) -> Result<Vec<u8>> {
        Ok(self.exchange(10, &cert_input(vk, counter, start))?.to_vec())
    }
}
#[derive(Debug)]
pub struct CertificateValidation {
    pub valid: bool,
    pub cold_vk: [u8; 32],
    pub signable: [u8; 48],
}
fn check_period(p: u8) -> Result<()> {
    if p < 64 {
        Ok(())
    } else {
        Err("oracle period outside 0..63".into())
    }
}
fn check_message(m: &[u8]) -> Result<()> {
    if m.len() <= 4096 {
        Ok(())
    } else {
        Err("oracle message exceeds 4096 bytes".into())
    }
}
fn boolean(b: &[u8]) -> Result<bool> {
    match b {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(FAILURE.into()),
    }
}
fn cert_input(vk: &[u8; 32], counter: u64, start: u64) -> [u8; 48] {
    let mut b = [0; 48];
    b[..32].copy_from_slice(vk);
    b[32..40].copy_from_slice(&counter.to_be_bytes());
    b[40..].copy_from_slice(&start.to_be_bytes());
    b
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("independent native oracles disagree".into())
    }
}
fn key_file(kind: &str, prefix: &str, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    // May contain a private key: avoid serde Value/String copies.
    let mut out = Zeroizing::new(Vec::with_capacity(128 + bytes.len() * 2));
    write!(
        &mut *out,
        "{{\"type\":\"{kind}\",\"description\":\"disposable oracle input\",\"cborHex\":\"{prefix}"
    )
    .expect("Vec write");
    for byte in bytes {
        write!(&mut *out, "{byte:02x}").expect("Vec write");
    }
    out.extend_from_slice(b"\"}");
    out
}

/// Public counts/identities only. This executes real native crypto in both
/// independent graphs; it is not a Rust/native differential qualification.
pub fn self_check() -> Result<Value> {
    let cli = Oracle::pinned(Baseline::Cli114)?;
    let node = Oracle::pinned(Baseline::Node1113)?;
    {
        let mut seed = Zeroizing::new([0u8; 32]);
        fs::File::open("/dev/urandom")
            .and_then(|mut input| input.read_exact(&mut *seed))
            .map_err(|_| "disposable oracle entropy unavailable")?;
        let (left_vk, left) = cli.generate_from_seed(&seed)?;
        let (right_vk, right) = node.generate_from_seed(&seed)?;
        require(left_vk == right_vk && left.as_bytes() == right.as_bytes())?;
    }
    let mut signed = 0u64;
    let mut verified = 0u64;
    let mut corrupt_rejected = 0u64;
    let mut transitions = 0u64;
    let mut terminal_rejected = 0u64;
    for producer in [&cli, &node] {
        let (vk, mut left) = producer.generate()?;
        let mut right = SecretState::from_bytes(left.as_bytes())?;
        let public_file = key_file("KesVerificationKey_ed25519_kes_2^6", "5820", &vk);
        let private_file = key_file("KesSigningKey_ed25519_kes_2^6", "590260", left.as_bytes());
        for oracle in [&cli, &node] {
            require(oracle.validate_vk_file(&public_file)? == vk)?;
            require(oracle.validate_signing_key_file(&private_file)? == vk)?;
        }
        drop(private_file);
        let expected = cli.opcert_signable(&vk, u64::MAX - 1, u64::MAX)?;
        require(expected == node.opcert_signable(&vk, u64::MAX - 1, u64::MAX)?)?;
        let cert = producer.issue_disposable_certificate(&vk, u64::MAX - 1, u64::MAX)?;
        for oracle in [&cli, &node] {
            let validation = oracle.validate_certificate_file(&cert)?;
            require(validation.valid && validation.signable == expected)?;
        }
        for period in 0..64 {
            require(cli.derive_vk(&left)? == vk && node.derive_vk(&right)? == vk)?;
            require(left.as_bytes() == right.as_bytes())?;
            let (s, v, c) = check_signatures(&cli, &node, &vk, &left, &right, period)?;
            signed += s;
            verified += v;
            corrupt_rejected += c;
            let a = cli.evolve(&left, period)?;
            let b = node.evolve(&right, period)?;
            if period == 63 {
                require(a.is_none() && b.is_none())?;
                terminal_rejected += 2;
            } else {
                left = a.ok_or("native oracle ended early")?;
                right = b.ok_or("native oracle ended early")?;
                transitions += 2;
            }
        }
    }
    Ok(
        json!({"schema_version":1,"scope":"disposable-native-cross-baseline","memory_policy":"fresh-cgroup-v2-no-swap-nondumpable-lab","algorithm":"Sum6KES","periods_per_generation":64,"full_period_generations":2,"native_generations":4,"shared_seed_generation_agreements":1,"signatures":signed,"valid_verifications":verified,"corrupted_signature_rejections":corrupt_rejected,"evolutions":transitions,"terminal_update_rejections":terminal_rejected,"message_lengths":[0,256,4096],"canonical_state_bytes":608,"verification_key_bytes":32,"signature_bytes":448,"baselines":[cli.identity,node.identity]}),
    )
}

fn check_signatures(
    cli: &Oracle,
    node: &Oracle,
    vk: &[u8; 32],
    left: &SecretState,
    right: &SecretState,
    period: u8,
) -> Result<(u64, u64, u64)> {
    let mut signed = 0;
    let mut verified = 0;
    let mut rejected = 0;
    for size in [0, 256, 4096] {
        let msg = vec![period; size];
        let a = cli.sign(left, period, &msg)?;
        let b = node.sign(right, period, &msg)?;
        require(a == b)?;
        signed += 2;
        let mut corrupted = a;
        corrupted[0] ^= 1;
        for oracle in [cli, node] {
            require(oracle.verify(vk, period, &msg, &a)?)?;
            verified += 1;
            require(!oracle.verify(vk, period, &msg, &corrupted)?)?;
            rejected += 1;
        }
    }
    Ok((signed, verified, rejected))
}
