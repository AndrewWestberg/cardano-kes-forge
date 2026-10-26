#!/usr/bin/env python3
"""Exact native-tool invocations; build/identity run only on explicit request."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CABAL = "/home/westbam/.ghcup/bin/cabal-3.12.1.0"
GHC = "/home/westbam/.ghcup/ghc/9.6.7/bin/ghc-9.6.7"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=("cli-11.4", "node-11.1.3"))
    parser.add_argument("action", choices=("update", "freeze", "build", "identity"))
    args = parser.parse_args()
    directory = HERE / args.project
    provenance = json.loads((directory / "provenance.json").read_text())
    environment = dict(os.environ)
    environment["PATH"] = str(Path(GHC).parent) + os.pathsep + environment["PATH"]
    actual_ghc = subprocess.check_output([GHC, "--numeric-version"], text=True).strip()
    actual_cabal = subprocess.check_output([CABAL, "--numeric-version"], text=True).strip()
    if actual_ghc != "9.6.7" or actual_cabal != "3.12.1.0":
        raise RuntimeError(f"wrong tools: GHC {actual_ghc}, Cabal {actual_cabal}")
    package = "cardano-cli" if args.project == "cli-11.4" else "cardano-node"
    target = f"{package}:exe:{package}"
    command = [CABAL, "--config-file=../cabal.config"]
    options = ["--project-file=cabal.project", f"--builddir=../../../target/oracles/build/{args.project}"]
    common = {"cwd": directory, "env": environment}
    if args.action == "update":
        subprocess.run(command + ["update"] + options, check=True, **common)
    elif args.action == "freeze":
        subprocess.run(command + ["freeze"] + options + ["--disable-tests", "--disable-benchmarks"], check=True, **common)
    elif args.action == "build":
        subprocess.run(command + ["build", target] + options + ["--disable-tests", "--disable-benchmarks"], check=True, **common)
    else:
        executable = Path(subprocess.check_output(command + ["list-bin", target] + options, text=True, **common).strip()).resolve()
        if not executable.is_relative_to(ROOT / "target/oracles/build" / args.project):
            raise RuntimeError(f"unexpected executable location: {executable}")
        version = subprocess.check_output([str(executable), "--version"], text=True, env=environment)
        expected_version = "11.4.0.0" if package == "cardano-cli" else "11.1.3"
        if not version.startswith(f"{package} {expected_version} ") or provenance["source"]["commit"] not in version:
            raise RuntimeError(f"wrong executable release/revision: {version}")
        print(json.dumps({"executable": str(executable), "version_output": version,
                          "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
