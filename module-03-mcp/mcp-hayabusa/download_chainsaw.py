#!/usr/bin/env python3
"""Download the latest Chainsaw release for this platform, plus its native EVTX
detection rules (rules/evtx/ from the source tree), and extract both to ./chainsaw/.

The rules come from a separate source-tarball download rather than the
"chainsaw_all_platforms+rules.zip" release asset: that asset bundles every platform's
binary plus the entire vendored Sigma rule corpus (~90MB extracted), which duplicates
what download_hayabusa.py already fetches for Hayabusa and isn't needed since
server.py's scan_chainsaw tool only uses Chainsaw's own native rules/evtx/ ruleset.
"""

import json
import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

RELEASE_API_URL = "https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest"
DEST_DIR = Path(__file__).parent / "chainsaw"
USER_AGENT = "mcp-hayabusa-installer"
RULES_SUBPATH = "rules/evtx"


def detect_asset_name():
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows" and machine in ("amd64", "x86_64"):
        return "chainsaw_x86_64-pc-windows-msvc.zip"
    if system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "chainsaw_x86_64-unknown-linux-gnu.tar.gz"
        if machine in ("aarch64", "arm64"):
            return "chainsaw_aarch64-unknown-linux-gnu.tar.gz"
    if system == "Darwin":
        if machine in ("x86_64", "amd64"):
            return "chainsaw_x86_64-apple-darwin.zip"
        if machine in ("arm64", "aarch64"):
            return "chainsaw_aarch64-apple-darwin.zip"

    raise RuntimeError(f"Unsupported platform/architecture: {system}/{machine}")


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def find_asset(release, name):
    for asset in release.get("assets", []):
        if asset["name"] == name:
            return asset
    return None


def download(url, dest_path):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as out:
        while chunk := resp.read(1024 * 1024):
            out.write(chunk)


def extract_stripped_zip(archive_path, dest_dir):
    """Extract a zip whose entries are nested one level under a wrapper dir (e.g. `chainsaw/`)."""
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.namelist():
            parts = Path(member).parts
            if len(parts) <= 1:
                continue
            target = dest_dir.joinpath(*parts[1:])
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as out:
                out.write(src.read())


def extract_stripped_tar(archive_path, dest_dir):
    with tarfile.open(archive_path) as tf:
        for member in tf.getmembers():
            parts = Path(member.name).parts
            if len(parts) <= 1:
                continue
            member.name = str(Path(*parts[1:]))
            tf.extract(member, dest_dir)


def download_rules(version, dest_dir):
    tarball_url = f"https://github.com/WithSecureLabs/chainsaw/archive/refs/tags/{version}.tar.gz"
    tmp_path = dest_dir / "_source.tar.gz"
    print(f"Downloading native detection rules from {tarball_url} ...")
    download(tarball_url, tmp_path)

    rules_dest = dest_dir / "rules"
    with tarfile.open(tmp_path) as tf:
        top_dir = tf.getnames()[0].split("/")[0]
        prefix = f"{top_dir}/{RULES_SUBPATH}/"
        for member in tf.getmembers():
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix):]
            if not relative:
                continue
            member.name = relative
            tf.extract(member, rules_dest)
    tmp_path.unlink()


def make_executable(directory):
    for path in directory.glob("chainsaw*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main():
    try:
        asset_name = detect_asset_name()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Detected platform asset: {asset_name}")

    try:
        release = fetch_json(RELEASE_API_URL)
    except OSError as e:
        print(f"Error: could not reach GitHub API: {e}", file=sys.stderr)
        sys.exit(1)

    version = release.get("tag_name", "unknown")
    print(f"Latest Chainsaw release: {version}")

    asset = find_asset(release, asset_name)
    if asset is None:
        print(f"Error: no release asset found named '{asset_name}'", file=sys.stderr)
        sys.exit(1)

    DEST_DIR.mkdir(exist_ok=True)
    archive_path = DEST_DIR / asset["name"]

    print(f"Downloading {asset['name']} ...")
    try:
        download(asset["browser_download_url"], archive_path)
    except OSError as e:
        print(f"Error: download failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracting to {DEST_DIR} ...")
    if archive_path.suffix == ".zip":
        extract_stripped_zip(archive_path, DEST_DIR)
    else:
        extract_stripped_tar(archive_path, DEST_DIR)
    archive_path.unlink()

    try:
        download_rules(version, DEST_DIR)
    except OSError as e:
        print(f"Error: failed to download rules: {e}", file=sys.stderr)
        sys.exit(1)

    make_executable(DEST_DIR)

    print(f"Done. Chainsaw {version} + native evtx rules extracted to {DEST_DIR}")


if __name__ == "__main__":
    main()
