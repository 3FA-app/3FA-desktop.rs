#!/usr/bin/env python3
import pathlib
import subprocess
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
with (root / "VENDORED_INTERFACES.toml").open("rb") as handle:
    manifest = tomllib.load(handle)
assert manifest["source_repository"] == "3FA-app/3fa-interfaces"
commit = manifest["source_commit"]
assert len(commit) == 40 and all(ch in "0123456789abcdef" for ch in commit)
for relative, expected in manifest["files"].items():
    path = root / relative
    assert path.is_file(), f"missing vendored interface file: {relative}"
    actual = subprocess.check_output(["git", "hash-object", str(path)], text=True).strip()
    assert actual == expected, f"vendored interface drift: {relative}"
print(f"verified vendored interfaces from {commit}")
