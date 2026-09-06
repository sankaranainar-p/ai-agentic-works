#!/usr/bin/env python3
"""
data/scripts/download_rcaeval.py — Downloader for the RCAEval benchmark
(Zenodo record 14590730: https://zenodo.org/records/14590730).

Downloads one or more RE1/RE2 dataset zips, verifies each against its
published MD5 checksum, and extracts it into data/rcaeval/. RE3 is not
supported here (pre.signals.rcaeval.RCAEvalAdapter is RE1/RE2 only).

Usage:
    python data/scripts/download_rcaeval.py --dataset RE1-OB
    python data/scripts/download_rcaeval.py --dataset RE1-OB RE2-TT
    python data/scripts/download_rcaeval.py --all-re1
    python data/scripts/download_rcaeval.py --all

Checksums and file sizes below are taken directly from the Zenodo API
(https://zenodo.org/api/records/14590730) at the time this script was
written; re-verify against that endpoint if Zenodo ever republishes a
revision.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

ZENODO_RECORD = 14590730
ZENODO_BASE = f"https://zenodo.org/records/{ZENODO_RECORD}/files"

# {dataset_name: (md5, size_bytes)} — from https://zenodo.org/api/records/14590730
CHECKSUMS: dict[str, tuple[str, int]] = {
    "RE1-OB": ("47cce26ed24140e8974e68f9db2a5e9c", 30966778),
    "RE1-SS": ("d2b15cbd3bb3cf6ec5f3cc65f7fac225", 79089075),
    "RE1-TT": ("48a26925ce47fd4bcfbedbae4f31475b", 279663965),
    "RE2-OB": ("b9e23f8842c404b396ffd2becff15de4", 1191025569),
    "RE2-SS": ("bd747a8fc7c5be00c613e13fbf9dd74b", 245629018),
    "RE2-TT": ("a7fbcd1ada406067dcc50771ae398408", 2801345134),
}

RE1_DATASETS = ["RE1-OB", "RE1-SS", "RE1-TT"]
RE2_DATASETS = ["RE2-OB", "RE2-SS", "RE2-TT"]

DEFAULT_OUT_DIR = Path(__file__).parent.parent / "rcaeval"


def _md5(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def download(dataset: str, out_dir: Path, force: bool = False) -> Path:
    """Download, checksum, and extract *dataset* into out_dir.

    Returns the path to the extracted dataset directory (out_dir/{dataset}).
    Raises ValueError on checksum mismatch — never extracts unverified data.
    """
    if dataset not in CHECKSUMS:
        raise ValueError(
            f"Unknown RCAEval dataset {dataset!r}. Known: {sorted(CHECKSUMS)}"
        )

    expected_md5, expected_size = CHECKSUMS[dataset]
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir = out_dir / dataset
    zip_path = out_dir / f"{dataset}.zip"

    if extracted_dir.is_dir() and not force:
        print(f"[skip] {dataset} already extracted at {extracted_dir}")
        return extracted_dir

    url = f"{ZENODO_BASE}/{dataset}.zip?download=1"
    print(f"[download] {dataset} <- {url}")
    with urlopen(url) as response, zip_path.open("wb") as out_fh:
        total = 0
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out_fh.write(chunk)
            total += len(chunk)
        if total != expected_size:
            zip_path.unlink(missing_ok=True)
            raise ValueError(
                f"{dataset}: downloaded {total} bytes, expected {expected_size}. "
                "Aborting without extracting."
            )

    print(f"[verify] {dataset} checksum...")
    actual_md5 = _md5(zip_path)
    if actual_md5 != expected_md5:
        zip_path.unlink(missing_ok=True)
        raise ValueError(
            f"{dataset}: MD5 mismatch (expected {expected_md5}, got {actual_md5}). "
            "Aborting without extracting — the download may be corrupt or Zenodo "
            "may have republished this record; re-check CHECKSUMS against "
            f"https://zenodo.org/api/records/{ZENODO_RECORD} before retrying."
        )
    print(f"[verify] {dataset} OK ({actual_md5})")

    print(f"[extract] {dataset} -> {out_dir}")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(out_dir)
    zip_path.unlink()

    return extracted_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", nargs="+", choices=sorted(CHECKSUMS), help="one or more dataset names"
    )
    parser.add_argument("--all-re1", action="store_true", help="download all RE1 datasets")
    parser.add_argument("--all-re2", action="store_true", help="download all RE2 datasets (large: ~4.2GB total)")
    parser.add_argument("--all", action="store_true", help="download everything (large: ~4.6GB total)")
    parser.add_argument(
        "--out-dir", type=Path, default=DEFAULT_OUT_DIR, help=f"output directory (default: {DEFAULT_OUT_DIR})"
    )
    parser.add_argument("--force", action="store_true", help="re-download even if already extracted")
    args = parser.parse_args(argv)

    datasets: list[str] = list(args.dataset or [])
    if args.all_re1:
        datasets += RE1_DATASETS
    if args.all_re2:
        datasets += RE2_DATASETS
    if args.all:
        datasets += RE1_DATASETS + RE2_DATASETS
    datasets = sorted(set(datasets))

    if not datasets:
        parser.error("specify --dataset, --all-re1, --all-re2, or --all")

    for dataset in datasets:
        download(dataset, args.out_dir, force=args.force)

    return 0


if __name__ == "__main__":
    sys.exit(main())
