#!/usr/bin/env python3
"""Build/identify separate native drivers; never execute private inputs here.

From repository root:
  python3 xtask/oracles/driver.py cli-11.4 build
  python3 xtask/oracles/driver.py cli-11.4 identity
  python3 xtask/oracles/driver.py node-11.1.3 build
  python3 xtask/oracles/driver.py node-11.1.3 identity

The identity action runs only the bounded public operation 0. Crypto self-check
is exposed by xtask::oracles::self_check(), not by this build helper. Both the
Rust host and Haskell driver require a fresh cgroup-v2 lab unit with
MemorySwapMax=0 / memory.swap.current=0 and disable process dumping. Invoke
identity through systemd-run --user --pipe --wait --collect --quiet
-p MemorySwapMax=0 -p LimitCORE=0, using an absolute helper path.
This is disposable lab isolation, not production recovery/credential protection.
No supplied private bytes may be passed in argv, environment, logs or files.

Wire v1: one request per process; u32be body length (2..16384), version u8=1,
operation u8, payload; exact EOF. Response: same framing, version=1/status=0,
payload; exact EOF. Nonzero exit means generic rejection; stderr is discarded.
Operations: 0 identity; 1 random generation -> VK32/state608; 2 state608 -> VK32;
3 current-u8/state608 -> 0 exhausted or 1/state608; 4 period-u8/state608/msg<=4096
-> signature448; 5 period-u8/VK32/signature448/msg<=4096 -> boolean-u8;
6 VK32/counter-u64be/start-u64be -> native OCertSignable48;
7 conventional public-key JSON -> VK32; 8 conventional private-key JSON -> VK32;
9 certificate JSON -> valid-u8/coldVK32/signable48; 10 VK32/counter/start ->
certificate JSON signed by fresh runtime disposable cold key. Secret state has
no period suffix. Native file validators receive exact JSON bytes, never paths.
11 seed32 -> VK32/state608, for fresh runtime cross-implementation generation;
the seed is supplied through the private pipe only and never retained.
Public self-check report v1 includes scope, algorithm, periods_per_generation,
full_period_generations, native_generations, shared_seed_generation_agreements,
signatures, valid_verifications, corrupted_signature_rejections,
evolutions, terminal_update_rejections, message_lengths, canonical_state_bytes,
verification_key_bytes, signature_bytes, and separate built-driver identities.
Nothing here updates or relabels T004 baseline provenance.json.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CABAL = Path('/home/westbam/.ghcup/bin/cabal-3.12.1.0')
GHC = Path('/home/westbam/.ghcup/ghc/9.6.7/bin/ghc-9.6.7')
GOLD = ROOT / 'target/oracles/tools/gold/usr/bin'


def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', choices=['cli-11.4', 'node-11.1.3'])
    parser.add_argument('action', choices=['build', 'identity'])
    args = parser.parse_args()
    project = HERE / args.project
    build = ROOT / 'target/oracles/drivers' / args.project
    name = 'kes-oracle-cli' if args.project == 'cli-11.4' else 'kes-oracle-node'
    target = f'{name}:exe:{name}'
    environment = dict(os.environ)
    environment['PATH'] = f'{GOLD}:{GHC.parent}:' + environment['PATH']
    if subprocess.check_output([str(GHC), '--numeric-version'], text=True).strip() != '9.6.7':
        raise RuntimeError('incorrect GHC')
    if subprocess.check_output([str(CABAL), '--numeric-version'], text=True).strip() != '3.12.1.0':
        raise RuntimeError('incorrect Cabal')
    base = [str(CABAL), f'--config-file={HERE / "cabal.config"}']
    options = ['--project-file=driver.project', f'--builddir={build}', '--disable-tests', '--disable-benchmarks']
    common = dict(cwd=project, env=environment)
    if args.action == 'build':
        subprocess.run(base + ['build', target] + options, check=True, **common)
        return
    executable = Path(subprocess.check_output(base + ['list-bin', target] + options, text=True, **common).strip()).resolve()
    if not executable.is_relative_to(build.resolve()):
        raise RuntimeError('driver executable outside its independent build directory')
    plan_path = build / 'cache/plan.json'
    plan = json.loads(plan_path.read_text())
    baseline = json.loads((project / 'provenance.json').read_text())
    expected = {'cardano-api': '11.9.0.0', 'cardano-crypto-class': '2.6.0.0', 'cardano-keys': '11.0.0.0'} if args.project == 'cli-11.4' else {'cardano-api': '11.6.0.0', 'cardano-crypto-class': '2.5.1.0', 'ouroboros-consensus': '4.2.1.0'}
    selected = plan['install-plan']
    for package, version in expected.items():
        versions = {p['pkg-version'] for p in selected if p['pkg-name'] == package}
        if versions != {version}:
            raise RuntimeError('driver graph release mismatch')
    originals = {(p['pkg-name'], p['pkg-version']): p for p in baseline['packages']}
    for package in selected:
        if package['pkg-name'] == name:
            continue
        original = originals.get((package['pkg-name'], package['pkg-version']))
        if original is None:
            raise RuntimeError('driver graph differs from pinned baseline')
        for field in ['pkg-cabal-sha256', 'pkg-src-sha256']:
            if field in original and package.get(field) != original[field]:
                raise RuntimeError('driver graph source checksum mismatch')
    # Public identity request only; never allow raw child output into errors.
    child = subprocess.run([str(executable)], input=b'\0\0\0\2\1\0', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={}, check=False)
    expected_text = f'kes-oracle/v1 {args.project} API{expected["cardano-api"]} crypto{expected["cardano-crypto-class"]} Sum6KES'.encode()
    expected_body = b'\1\0' + expected_text
    if child.returncode != 0 or child.stdout != len(expected_body).to_bytes(4, 'big') + expected_body:
        raise RuntimeError('native public identity operation failed (requires verified no-swap lab unit)')
    inputs = {p: digest(project / p) for p in ['app/Main.hs', f'{name}.cabal', 'driver.project', 'cabal.project', 'cabal.project.freeze', 'provenance.json']}
    identity = {'schema_version': 1, 'project': args.project, 'status': 'built-public-identity-checked', 'executable': str(executable), 'sha256': digest(executable), 'inputs': inputs, 'plan_sha256': digest(plan_path), 'source': baseline['source'], 'native_versions': expected, 'tools': {'ghc': '9.6.7', 'cabal': '3.12.1.0', 'ghc_sha256': digest(GHC), 'cabal_sha256': digest(CABAL), 'ld_gold_sha256': digest(GOLD / 'ld.gold')}}
    (build / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    print(json.dumps(identity, indent=2))


if __name__ == '__main__':
    main()
