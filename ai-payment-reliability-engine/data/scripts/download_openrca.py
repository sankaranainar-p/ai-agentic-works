#!/usr/bin/env python3
"""
data/scripts/download_openrca.py — Downloader for OpenRCA's Bank system
telemetry (https://github.com/microsoft/OpenRCA).

OpenRCA's own README distributes its full telemetry (Bank+Market+Telecom,
~68.7GB) via a Google Drive folder with no checksum manifest and no
resumable/scriptable HTTP endpoint. This script instead downloads from
the public, directly-fetchable Hugging Face mirror
https://huggingface.co/datasets/cdreetz/OpenRCA (hand-verified against
OpenRCA's documented schema and against OpenRCA's own archived
`rca/archive/agent-Bank.csv` row count while building this project's
pre.signals.openrca.OpenRCABankAdapter — see CONVERSION.md).

Unlike download_rcaeval.py's Zenodo download (single checksummed archive
per dataset), this script downloads only the specific per-date telemetry
folders actually referenced by Bank/record.csv's timestamps — NOT the
full ~26GB Bank/telemetry/ tree — since OpenRCABankAdapter only ever
reads the date folder matching each failure's Asia/Shanghai date. This
keeps a full Bank download to ~5-6GB (Bank has 10 date folders; see
--list-dates) instead of needing the full ~26GB tree, and a
--dates-only subset makes even that avoidable when you only need a few
cases (e.g. for building a fixture, see this script's own use while
building tests/fixtures/openrca/).

No checksum manifest is published for this mirror (unlike RCAEval's
Zenodo record, which publishes per-file MD5s this project's
download_rcaeval.py verifies against). This script instead verifies
each downloaded file's byte count against the Content-Length reported
by the server's own HEAD response for that same URL, which catches
truncated/interrupted downloads but not server-side corruption --
documented here as a real limitation, not silently glossed over.

Usage:
    # metadata only (record.csv + query.csv, ~65KB total)
    python data/scripts/download_openrca.py --metadata-only

    # metadata + telemetry for every date referenced in record.csv
    # (all 9 fault dates; ~15-20GB depending on per-date file sizes)
    python data/scripts/download_openrca.py

    # metadata + telemetry for specific dates only (for fixture-building
    # or spot-checking a handful of cases)
    python data/scripts/download_openrca.py --dates 2021_03_04 2021_03_06

    # just print which dates record.csv references, without downloading
    python data/scripts/download_openrca.py --list-dates
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.request import Request, urlopen

import pandas as pd
import pytz

HF_BASE = "https://huggingface.co/datasets/cdreetz/OpenRCA/resolve/main"
SHANGHAI = pytz.timezone("Asia/Shanghai")

DEFAULT_OUT_DIR = Path(__file__).parent.parent / "openrca"

TELEMETRY_FILES = [
    "log/log_service.csv",
    "metric/metric_app.csv",
    "metric/metric_container.csv",
    "trace/trace_span.csv",
]


def _content_length(url: str) -> int | None:
    req = Request(url, method="HEAD")
    try:
        with urlopen(req) as resp:
            length = resp.headers.get("Content-Length")
            return int(length) if length is not None else None
    except Exception:
        return None


def _download(url: str, dest: Path, force: bool = False) -> None:
    if dest.exists() and not force:
        expected = _content_length(url)
        actual = dest.stat().st_size
        if expected is None or actual == expected:
            print(f"[skip] {dest} already present ({actual} bytes)")
            return
        print(f"[refetch] {dest} size mismatch (have {actual}, server reports {expected})")

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[download] {url} -> {dest}")
    req = Request(url)
    with urlopen(req) as response, dest.open("wb") as out_fh:
        total = 0
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out_fh.write(chunk)
            total += len(chunk)

    expected = _content_length(url)
    if expected is not None and total != expected:
        dest.unlink(missing_ok=True)
        raise ValueError(
            f"{url}: downloaded {total} bytes, server HEAD reports {expected}. "
            "Aborting — file left unwritten rather than keeping a truncated copy."
        )
    print(f"[ok] {dest} ({total} bytes)")


def referenced_dates(record_csv: Path) -> list[str]:
    """Return the sorted set of `{YYYY_MM_DD}` telemetry folder names
    Bank/record.csv's failures actually fall on, in Asia/Shanghai
    (see pre.signals.openrca module docstring for why Shanghai, not
    UTC, is the correct conversion here).
    """
    record = pd.read_csv(record_csv)
    dates = set()
    for ts in record["timestamp"]:
        dt = pd.Timestamp(float(ts), unit="s", tz="UTC").tz_convert(SHANGHAI)
        dates.add(dt.strftime("%Y_%m_%d"))
    return sorted(dates)


def download_metadata(out_dir: Path, force: bool = False) -> Path:
    bank_dir = out_dir / "Bank"
    _download(f"{HF_BASE}/Bank/record.csv", bank_dir / "record.csv", force=force)
    _download(f"{HF_BASE}/Bank/query.csv", bank_dir / "query.csv", force=force)
    return bank_dir


def download_telemetry_for_dates(bank_dir: Path, dates: list[str], force: bool = False) -> None:
    for date in dates:
        for rel_path in TELEMETRY_FILES:
            url = f"{HF_BASE}/Bank/telemetry/{date}/{rel_path}"
            dest = bank_dir / "telemetry" / date / rel_path
            _download(url, dest, force=force)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--out-dir", type=Path, default=DEFAULT_OUT_DIR, help=f"output directory (default: {DEFAULT_OUT_DIR})"
    )
    parser.add_argument(
        "--dates", nargs="+", help="download telemetry only for these YYYY_MM_DD dates (default: all referenced by record.csv)"
    )
    parser.add_argument("--metadata-only", action="store_true", help="download only record.csv/query.csv, no telemetry")
    parser.add_argument("--list-dates", action="store_true", help="print the dates record.csv references and exit")
    parser.add_argument("--force", action="store_true", help="re-download even if a same-size file already exists")
    args = parser.parse_args(argv)

    bank_dir = download_metadata(args.out_dir, force=args.force) if not args.list_dates else args.out_dir / "Bank"
    if args.list_dates and not (bank_dir / "record.csv").exists():
        bank_dir = download_metadata(args.out_dir, force=args.force)

    dates = referenced_dates(bank_dir / "record.csv")
    print(f"record.csv references {len(dates)} date(s): {dates}")

    if args.list_dates:
        return 0
    if args.metadata_only:
        return 0

    target_dates = args.dates if args.dates else dates
    unknown = set(target_dates) - set(dates)
    if unknown:
        print(f"[warn] requested dates not referenced by record.csv: {sorted(unknown)}")

    download_telemetry_for_dates(bank_dir, target_dates, force=args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
