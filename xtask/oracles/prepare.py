#!/usr/bin/env python3
"""Provision exact, unmodified native release sources without touching user repos."""
import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
ORACLES = pathlib.Path(__file__).resolve().parent


def main():
    for name in ("cli-11.4", "node-11.1.3"):
        source = json.loads((ORACLES / name / "provenance.json").read_text())["source"]
        archive = ROOT / source["archive"]
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists():
            temporary = archive.with_suffix(".partial")
            with urllib.request.urlopen(source["url"]) as response, temporary.open("xb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            temporary.rename(archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source["sha256"]:
            raise RuntimeError(f"archive checksum mismatch: {archive}")
        destination = ROOT / source["directory"]
        with tarfile.open(archive) as release:
            members = release.getmembers()
            if any(pathlib.PurePosixPath(m.name).parts[0] != destination.name for m in members):
                raise RuntimeError(f"unexpected archive root: {archive}")
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                release.extractall(destination.parent, filter="data")
            else:
                # Do not overwrite even an isolated checkout if someone edited it.
                for member in members:
                    path = destination.parent / member.name
                    if member.isfile():
                        if path.is_symlink() or not path.is_file() or path.read_bytes() != release.extractfile(member).read():
                            raise RuntimeError(f"existing source differs; refusing overwrite: {path}")
                    elif member.issym():
                        # tar(1) preserves the original spelling; Python's data
                        # filter can normalize it. Path.readlink() also loses
                        # lexical "./" components, so compare raw link strings.
                        filtered = tarfile.data_filter(member, str(destination.parent))
                        if not path.is_symlink() or os.readlink(path) not in (member.linkname, filtered.linkname):
                            raise RuntimeError(f"existing source differs; refusing overwrite: {path}")
        git_dir = destination / ".git"
        # Real fetched Git objects let upstream Cardano.Git.Rev embed the release
        # revision, rather than accidentally finding this Rust repository's HEAD.
        if not git_dir.exists():
            subprocess.run(["git", "init", str(destination)], check=True)
            subprocess.run(["git", "-C", str(destination), "fetch", "--depth=1", source["repository"], source["commit"]], check=True)
            subprocess.run(["git", "-C", str(destination), "read-tree", source["commit"]], check=True)
            subprocess.run(["git", "-C", str(destination), "update-ref", "HEAD", source["commit"]], check=True)
        revision = subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], text=True).strip()
        if revision != source["commit"]:
            raise RuntimeError(f"existing Git revision differs: {destination}")
        print(f"{name}: {revision}; archive SHA-256 {source['sha256']}")


if __name__ == "__main__":
    main()
