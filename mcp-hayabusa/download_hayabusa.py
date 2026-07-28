#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/."""

import json
import platform
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

API_URL = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
DEST_DIR = Path(__file__).parent / "hayabusa"
USER_AGENT = "mcp-hayabusa-installer"


def detect_asset_suffix():
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows":
        if machine in ("amd64", "x86_64"):
            return "win-x64"
        if machine in ("arm64", "aarch64"):
            return "win-aarch64"
        if machine in ("x86", "i686", "i386"):
            return "win-x86"
    elif system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "lin-x64-gnu"
        if machine in ("aarch64", "arm64"):
            return "lin-aarch64-gnu"
    elif system == "Darwin":
        if machine in ("x86_64", "amd64"):
            return "mac-x64"
        if machine in ("arm64", "aarch64"):
            return "mac-aarch64"

    raise RuntimeError(f"Unsupported platform/architecture: {system}/{machine}")


def fetch_latest_release():
    req = urllib.request.Request(API_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def find_asset(release, suffix):
    # Match "...-<suffix>.zip" exactly, not "...-<suffix>-live-response.zip"
    for asset in release.get("assets", []):
        if asset["name"].endswith(f"-{suffix}.zip"):
            return asset
    return None


def download(url, dest_path):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as out:
        while chunk := resp.read(1024 * 1024):
            out.write(chunk)


def make_executable(directory):
    for path in directory.glob("hayabusa*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main():
    try:
        suffix = detect_asset_suffix()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Detected platform: {suffix}")

    try:
        release = fetch_latest_release()
    except OSError as e:
        print(f"Error: could not reach GitHub API: {e}", file=sys.stderr)
        sys.exit(1)

    version = release.get("tag_name", "unknown")
    print(f"Latest Hayabusa release: {version}")

    asset = find_asset(release, suffix)
    if asset is None:
        print(f"Error: no release asset found matching '-{suffix}.zip'", file=sys.stderr)
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
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(DEST_DIR)
    archive_path.unlink()

    make_executable(DEST_DIR)

    print(f"Done. Hayabusa {version} extracted to {DEST_DIR}")


if __name__ == "__main__":
    main()
