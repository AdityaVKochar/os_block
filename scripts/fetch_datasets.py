"""Download the pinned public auditd dataset and verify every file's SHA-256.

Usage: python scripts/fetch_datasets.py [--manifest datasets/manifest.json] [--out datasets/raw]
Files that already exist with the expected digest are not downloaded again.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(manifest_path: Path, out_dir: Path, workers: int = 8) -> list[Path]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    destination_root = out_dir / manifest["name"]

    def download(item: dict) -> Path:
        destination = destination_root / item["path"]
        if destination.exists() and _digest(destination) == item["sha256"]:
            return destination
        url = manifest["url_template"].format(commit=manifest["commit"], path=item["path"])
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"checksum mismatch for {item['path']}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return destination

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(download, manifest["files"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", default=str(ROOT / "datasets" / "manifest.json"))
    parser.add_argument("--out", default=str(ROOT / "datasets" / "raw"))
    args = parser.parse_args()
    try:
        files = fetch(Path(args.manifest), Path(args.out))
    except (OSError, ValueError) as error:
        sys.exit(f"dataset download failed: {error}")
    print(json.dumps({"files": len(files), "bytes": sum(path.stat().st_size for path in files), "directory": str(Path(args.out))}))


if __name__ == "__main__":
    main()
