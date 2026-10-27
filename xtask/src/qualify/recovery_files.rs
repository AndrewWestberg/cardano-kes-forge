//! Disposable recovery-workstation filesystem campaign. No production secrets.
//!
//! Requires a prebuilt recovery-profile CLI, Python 3 (stdlib PTY driver), a
//! matching authentic archive/key/VK/identity, and a fresh no-swap protected lab.
//! The supplied encrypted recipient is copied, never rewrapped in place. The
//! caller retains custody of the lab, which contains recovered conventional keys.
//! Process interruption is simulated at terminal barriers, not a physical cut or
//! a claim about execution on a physically separate machine.
use crate::evidence::{self, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// All inputs must be disposable. Password is read only from this protected
/// file, never argv/environment; its contents are one UTF-8 passphrase with no
/// newline. `lab` must already exist, be owner-only, and not contain `campaign`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub recovery_cli: PathBuf,
    pub lab: PathBuf,
    pub artifact: PathBuf,
    pub recipient_key: PathBuf,
    pub password_file: PathBuf,
    pub device_identity: PathBuf,
    pub verification_key: PathBuf,
    pub expect_device: String,
    pub expect_pool: String,
    pub expect_generation: String,
    /// Operator declaration only; never treated as physical location proof.
    pub separate_workstation_declared: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseEvidence {
    pub id: String,
    pub exit_code: i32,
    pub transcript_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryFilesReport {
    pub version: u8,
    pub campaign: String,
    pub verdict: String,
    pub candidate: Option<String>,
    pub recovery_cli_sha256: String,
    pub artifact_sha256: String,
    pub cases: Vec<CaseEvidence>,
    pub separate_workstation_declared: bool,
    pub physical_workstation_proven: bool,
    pub interruption_scope: String,
    pub recipient_replacement_status: String,
    pub t049_complete: bool,
}

/// Execute real commands; fail closed before writing any passing report.
/// Parent integration owns CLI option parsing and any separate management lane.
pub fn run(inputs: &Inputs, evidence_dir: &Path) -> Result<RecoveryFilesReport> {
    crate::oracles::protect_memory()?;
    let metadata =
        fs::symlink_metadata(&inputs.lab).map_err(|_| "recovery lab unavailable".to_owned())?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || !inputs.lab.is_absolute()
    {
        return Err("recovery lab must be an absolute owner-only directory".into());
    }
    fs::create_dir_all(evidence_dir).map_err(|_| "recovery evidence directory unavailable")?;
    let public_root =
        fs::canonicalize(evidence_dir).map_err(|_| "recovery evidence path invalid")?;
    let private_root = fs::canonicalize(&inputs.lab).map_err(|_| "recovery lab path invalid")?;
    if private_root.starts_with(&public_root) || public_root.starts_with(&private_root) {
        return Err("secret recovery lab and public evidence must be disjoint".into());
    }
    let candidate = std::env::var_os("KESFORGE_CANDIDATE_ROOT")
        .map(|path| evidence::load_current(Path::new(&path)))
        .transpose()?;
    let binary_hash = evidence::file_hash(&inputs.recovery_cli)?;
    let artifact_hash = evidence::file_hash(&inputs.artifact)?;
    let configuration =
        serde_json::to_vec(inputs).map_err(|_| "recovery configuration encoding failed")?;
    let mut child = Command::new("python3")
        .args(["-I", "-c", DRIVER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Python 3 PTY driver unavailable".to_owned())?;
    child
        .stdin
        .take()
        .ok_or("recovery driver pipe unavailable")?
        .write_all(&configuration)
        .map_err(|_| "recovery driver configuration failed")?;
    let output = child
        .wait_with_output()
        .map_err(|_| "recovery driver wait failed")?;
    if !output.status.success() {
        return Err(
            "recovery campaign failed; protected lab retained; no public transcript exported"
                .into(),
        );
    }
    let cases: Vec<CaseEvidence> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "recovery driver returned invalid public evidence")?;
    if let Some(frozen) = &candidate {
        let root =
            std::env::var_os("KESFORGE_CANDIDATE_ROOT").ok_or("candidate root disappeared")?;
        if evidence::load_current(Path::new(&root))?.candidate != frozen.candidate {
            return Err("candidate changed during recovery campaign".into());
        }
    }
    if evidence::file_hash(&inputs.recovery_cli)? != binary_hash
        || evidence::file_hash(&inputs.artifact)? != artifact_hash
    {
        return Err("recovery executable or input archive changed during campaign".into());
    }
    let report = RecoveryFilesReport {
        version: 1,
        campaign: "recovery-files-real-cli".into(),
        verdict: "software-pass-replacement-unavailable".into(),
        candidate: candidate.map(|frozen| frozen.candidate),
        recovery_cli_sha256: binary_hash,
        artifact_sha256: artifact_hash,
        cases,
        separate_workstation_declared: inputs.separate_workstation_declared,
        physical_workstation_proven: false,
        interruption_scope: "simulated SIGKILL at terminal barriers; not storage fault injection or physical power loss".into(),
        recipient_replacement_status: "unavailable-not-attempted: requires separate primary/management authorized replacement and a fresh device-generated artifact; recovery profile cannot perform it".into(),
        t049_complete: false,
    };
    evidence::write_new_json(&evidence_dir.join("recovery-files.json"), &report)?;
    Ok(report)
}

// Secret material and raw diagnostics never cross this process's stdout. The
// driver inherits the kernel-enforced no-swap cgroup; CLI uses its real locked
// memory implementation. PTY prompts are answered only after echo is disabled.
const DRIVER: &str = r#"
import os, sys, json, stat, pathlib, resource, ctypes, pty, termios, select, time, signal, hashlib, subprocess
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    raise RuntimeError('protection unavailable')
os.umask(0o077)
c = json.load(sys.stdin)

def require(ok):
    if not ok:
        raise RuntimeError('recovery invariant failed')

def protected(path):
    p = pathlib.Path(path)
    require(p.is_absolute())
    for ancestor in [p, *p.parents]:
        s = ancestor.lstat()
        require(not stat.S_ISLNK(s.st_mode))
        require(s.st_uid in (0, os.getuid()))
        # Root-owned sticky /tmp is safe for an exclusive owner-only child.
        require(not (s.st_mode & 0o022) or (s.st_uid == 0 and s.st_mode & stat.S_ISVTX))
    s = p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o600)
    return p.read_bytes()

require('..' not in pathlib.Path(c['lab']).parts)
for ancestor in [pathlib.Path(c['lab']), *pathlib.Path(c['lab']).parents]:
    s = ancestor.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid()))
    require(not (s.st_mode & 0o022) or (s.st_uid == 0 and s.st_mode & stat.S_ISVTX))
password = protected(c['password_file'])
require(password and len(password) <= 1024 and b'\n' not in password and b'\r' not in password)
password.decode('utf-8')
original_key = protected(c['recipient_key'])
lab = pathlib.Path(c['lab']) / 'campaign'
lab.mkdir(mode=0o700)
cli = str(pathlib.Path(c['recovery_cli']).resolve(strict=True))
profile = subprocess.run([cli, '--installation-profile'], capture_output=True, timeout=10)
require(profile.returncode == 0)
surface = json.loads(profile.stdout)
require(surface['version'] == 1 and surface['profile'] == 'recovery')
require(set(surface['commands']) == {'backup recover', 'recipient create', 'recipient change-password'})
newpass = os.urandom(32).hex().encode()
wrongpass = os.urandom(32).hex().encode()
secrets = [password, newpass, wrongpass]
cases = []

def put(name, data):
    p = lab / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    syncdir()
    return str(p)

def syncdir():
    fd = os.open(lab, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def digest(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def invoke(name, args, answers, expected=0, kill_prompt=None):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(cli, [cli] + args)
    raw = bytearray(); consumed = 0; sent = 0; killed = False
    deadline = time.monotonic() + 90
    status = None
    try:
        while True:
            require(time.monotonic() < deadline)
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try: data = os.read(fd, 4096)
                except OSError as e:
                    if e.errno != 5: raise
                    data = b''
                if not data: break
                raw.extend(data)
                require(len(raw) <= 65536)
                while b'passphrase: ' in raw[consumed:]:
                    end = raw.index(b'passphrase: ', consumed) + len(b'passphrase: ')
                    consumed = end
                    require(not (termios.tcgetattr(fd)[3] & termios.ECHO))
                    if kill_prompt == sent:
                        os.kill(pid, signal.SIGKILL); killed = True; break
                    require(sent < len(answers))
                    os.write(fd, answers[sent] + b'\n'); sent += 1
            done, value = os.waitpid(pid, os.WNOHANG)
            if done:
                status = value
                # Drain output through PTY EOF before inspecting diagnostics.
                while True:
                    try: data = os.read(fd, 4096)
                    except OSError as e:
                        if e.errno != 5: raise
                        break
                    if not data: break
                    raw.extend(data)
                break
        if status is None: _, status = os.waitpid(pid, 0)
    finally:
        if status is None:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
        os.close(fd)
    code = os.waitstatus_to_exitcode(status)
    require(all(secret not in raw for secret in secrets))
    require(b'cborHex' not in raw and b'SigningKey' not in raw and b'KESRCP01' not in raw)
    put(name + '.pty', raw)
    require((killed and code == -signal.SIGKILL) if kill_prompt is not None else code == expected)
    if kill_prompt is None: require(sent == len(answers))
    cases.append(dict(id=name, exit_code=code, transcript_sha256=hashlib.sha256(raw).hexdigest()))

key = put('working.recipient', original_key)
archive = put('archived.recipient', original_key)
artifact_bytes = pathlib.Path(c['artifact']).read_bytes()
artifact = put('initial.kesbkp01', artifact_bytes)
archive_digest = digest(archive)
artifact_digest = digest(artifact)

for field, size in [('expect_device', 32), ('expect_pool', 56), ('expect_generation', 32)]:
    require(len(c[field]) == size and all(ch in '0123456789abcdef' for ch in c[field]))

def recover_args(out, **changes):
    values = {'--artifact': artifact, '--recipient-key': key,
        '--device-identity-file': c['device_identity'], '--expect-device': c['expect_device'],
        '--expect-pool': c['expect_pool'], '--expect-generation': c['expect_generation'],
        '--verification-key-file': c['verification_key'], '--out-file': str(lab / out)}
    values.update(changes)
    return ['backup', 'recover'] + [v for pair in values.items() for v in pair]

def recover(name, pw, **changes):
    invoke(name, recover_args(name + '.skey', **changes), [pw])
    p = lab / (name + '.skey')
    require(stat.S_IMODE(p.lstat().st_mode) == 0o600 and p.stat().st_uid == os.getuid())
    document = json.loads(p.read_bytes())
    require(document['type'] == 'KesSigningKey_ed25519_kes_2^6')
    require(len(bytes.fromhex(document['cborHex'])) > 608)
    return p.read_bytes()

def reject(name, pw, code, **changes):
    out = lab / (name + '.skey')
    invoke(name, recover_args(name + '.skey', **changes), [pw], code)
    require(not out.exists())

# A newly generated real recipient is intentionally unrelated to the archive.
public = str(lab / 'replacement.pub.json'); unrelated = str(lab / 'replacement.recipient')
invoke('recipient-create', ['recipient', 'create', '--public-key-file', public, '--private-key-file', unrelated], [newpass, newpass])
require(stat.S_IMODE(pathlib.Path(unrelated).stat().st_mode) == 0o600)
first = recover('recover-before-rewrap', password)
secrets.extend([first, json.loads(first)['cborHex'].encode()])
secrets.extend([bytes.fromhex(json.loads(first)['cborHex'])[3:],
    json.loads(first)['cborHex'][6:].encode()])
reject('wrong-password', wrongpass, 3)
reject('wrong-recipient', newpass, 3, **{'--recipient-key': unrelated})
reject('missing-artifact', password, 2, **{'--artifact': str(lab / 'absent-artifact')})
reject('missing-recipient', password, 2, **{'--recipient-key': str(lab / 'absent-recipient')})
reject('missing-identity', password, 2, **{'--device-identity-file': str(lab / 'absent-identity')})
reject('missing-verification-key', password, 2, **{'--verification-key-file': str(lab / 'absent-vkey')})
changed = bytearray(artifact_bytes); changed[0] ^= 1
altered = put('altered.kesbkp01', changed)
reject('altered-artifact', password, 6, **{'--artifact': altered})
truncated = put('truncated.kesbkp01', artifact_bytes[:16])
reject('truncated-artifact', password, 6, **{'--artifact': truncated})
signature = bytearray(artifact_bytes)
offset = signature.index(b'device_signature') + len(b'device_signature')
require(signature[offset:offset + 2] == b'\x58\x40')
signature[offset + 2] ^= 1
signed_bad = put('invalid-signature.kesbkp01', signature)
reject('invalid-device-signature', password, 3, **{'--artifact': signed_bad})
vk = json.loads(pathlib.Path(c['verification_key']).read_bytes())
vk['cborHex'] = '5820' + ('00' * 32 if vk['cborHex'][4:] != '00' * 32 else '01' * 32)
wrong_vk = put('wrong.vkey', json.dumps(vk).encode())
reject('wrong-verification-key', password, 3, **{'--verification-key-file': wrong_vk})
malformed_key = put('malformed.recipient', b'not a recipient key')
reject('malformed-recipient', password, 2, **{'--recipient-key': malformed_key})
os.chmod(malformed_key, 0o644)
reject('unsafe-recipient-permissions', password, 2, **{'--recipient-key': malformed_key})
os.chmod(malformed_key, 0o600)
os.symlink(key, lab / 'recipient-symlink')
reject('recipient-symlink', password, 2, **{'--recipient-key': str(lab / 'recipient-symlink')})
for flag, value in [('--expect-device', '00' * 16), ('--expect-pool', '00' * 28), ('--expect-generation', '00' * 16)]:
    expected = {'--expect-device': c['expect_device'], '--expect-pool': c['expect_pool'], '--expect-generation': c['expect_generation']}[flag]
    require(value != expected)
    reject('wrong-' + flag[9:], password, 3, **{flag: value})
existing = put('existing.skey', b'unchanged-output-sentinel')
invoke('output-collision', recover_args('existing.skey'), [password], 7)
require(pathlib.Path(existing).read_bytes() == b'unchanged-output-sentinel')
os.symlink(existing, lab / 'symlink.skey')
invoke('output-symlink', recover_args('symlink.skey'), [password], 7)
require(pathlib.Path(existing).read_bytes() == b'unchanged-output-sentinel')
unsafe = lab / 'unsafe'; unsafe.mkdir(mode=0o755); unsafe.chmod(0o755)
invoke('unsafe-output-parent', recover_args('unsafe/key.skey'), [password], 7)
require(not (unsafe / 'key.skey').exists())
# Deterministic process termination while the real CLI is waiting for a
# password. These barriers cannot claim interruption of fsync/link/rename.
invoke('interrupted-recovery', recover_args('interrupted.skey'), [], kill_prompt=0)
require(not (lab / 'interrupted.skey').exists())
change = ['recipient', 'change-password', '--private-key-file', key]
old_digest = digest(key)
invoke('interrupted-rewrap', change, [password], kill_prompt=1)
require(digest(key) == old_digest)
invoke('interrupted-rewrap-confirmation', change, [password, newpass], kill_prompt=2)
require(digest(key) == old_digest)
require(recover('recover-after-interruption', password) == first)
invoke('rewrap-wrong-password', change, [wrongpass], 3)
require(digest(key) == old_digest)
invoke('rewrap', change, [password, newpass, newpass])
require(digest(key) != old_digest)
require(recover('recover-after-rewrap', newpass) == first)
reject('old-password-after-rewrap', password, 3)
require(recover('recover-retained-archive', password, **{'--recipient-key': archive}) == first)
require(digest(archive) == archive_digest and digest(artifact) == artifact_digest)
require(pathlib.Path(c['recipient_key']).read_bytes() == original_key)
# Inspect every captured command again now that the recovered plaintext is known.
for transcript in lab.glob('*.pty'):
    raw = transcript.read_bytes()
    require(all(secret not in raw for secret in secrets))
syncdir()
sys.stdout.write(json.dumps(cases))
"#;
