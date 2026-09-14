#!/usr/bin/env python3
"""
bench/build_rating_harness.py — blinded human-rating harness for Task 1.5.

Splits docs/faithfulness/judge_scores.jsonl into two files:
  - rater_payload.jsonl : shown to raters. Allow-listed fields only.
  - rating_key.jsonl    : kept server-side. Maps rating_id back to
                          case_id, evidence_ids, is_adversarial (population
                          label), and every automated judge score, for
                          joining after rating completes.

Allow-list, not block-list: RATER_FIELDS below is the complete set of
fields a rater ever sees. A new field added to judge_scores.jsonl in the
future is excluded by default, not leaked by an incomplete blocklist.

Usage:
    python bench/build_rating_harness.py --source docs/faithfulness/judge_scores.jsonl \
        --n 88 --seed 42 --out-dir results/rating_harness
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from pathlib import Path

# The ONLY fields a rater's UI ever receives. Nothing else reaches the
# rater-facing file regardless of what the source record contains.
RATER_FIELDS = ("claim_text", "evidence_rendered")


def build_rater_payload(record: dict, rating_id: str) -> dict:
    payload = {"rating_id": rating_id}
    for field in RATER_FIELDS:
        payload[field] = record[field]
    payload["verdict"] = None  # rater fills in: "pass" | "fail"
    payload["rater_note"] = ""  # optional free text
    return payload


def build_key_entry(record: dict, rating_id: str) -> dict:
    return {
        "rating_id": rating_id,
        "case_id": record["case_id"],
        "evidence_ids": record["evidence_ids"],
        "is_adversarial": record["is_adversarial"],
        "chat_score": record["chat_score"],
        "nli_score": record["nli_score"],
        "ground_truth_service": record["ground_truth_service"],
        "ground_truth_fault": record["ground_truth_fault"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="docs/faithfulness/judge_scores.jsonl")
    ap.add_argument("--n", type=int, default=None, help="sample size; omit to use all records")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default="results/rating_harness")
    args = ap.parse_args()

    records = [json.loads(line) for line in Path(args.source).read_text().splitlines() if line.strip()]

    if args.n is not None:
        if args.n > len(records):
            print(f"WARNING: requested n={args.n} exceeds available records ({len(records)}). "
                  f"Using all {len(records)}; sample size gap must be closed before rating begins.")
        else:
            records = random.Random(args.seed).sample(records, args.n)

    # Shuffle presentation order independent of any case/population grouping,
    # then assign IDs unrelated to source order or case_id.
    order = list(range(len(records)))
    random.Random(args.seed + 1).shuffle(order)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload_path = out_dir / "rater_payload.jsonl"
    key_path = out_dir / "rating_key.jsonl"

    with payload_path.open("w") as pf, key_path.open("w") as kf:
        for i in order:
            record = records[i]
            rating_id = uuid.uuid4().hex
            pf.write(json.dumps(build_rater_payload(record, rating_id)) + "\n")
            kf.write(json.dumps(build_key_entry(record, rating_id)) + "\n")

    print(f"{len(records)} records -> {payload_path} (rater-facing, {len(RATER_FIELDS) + 3} fields)")
    print(f"{len(records)} records -> {key_path} (server-side only, NOT for raters)")


def _demo():
    """ponytail: smallest runnable check — assert the allow-list actually excludes everything else."""
    fake_record = {
        "case_id": "RE1-OB_x_1",
        "claim_text": "claim",
        "evidence_ids": ["kpi:a:b"],
        "evidence_rendered": "a:b spiked to 1.0 (z=1.0)",
        "is_adversarial": True,
        "chat_score": 0.9,
        "nli_score": 0.1,
        "ground_truth_service": "x",
        "ground_truth_fault": "cpu",
    }
    payload = build_rater_payload(fake_record, "abc123")
    forbidden = {"case_id", "is_adversarial", "chat_score", "nli_score",
                 "ground_truth_service", "ground_truth_fault", "evidence_ids"}
    leaked = forbidden & payload.keys()
    assert not leaked, f"leaked fields into rater payload: {leaked}"
    assert set(payload.keys()) == {"rating_id", "claim_text", "evidence_rendered", "verdict", "rater_note"}
    key = build_key_entry(fake_record, "abc123")
    assert key["is_adversarial"] is True and key["chat_score"] == 0.9
    print("OK: rater payload contains only the allow-listed fields; key file retains everything else.")


if __name__ == "__main__":
    import sys
    if "--demo" in sys.argv:
        _demo()
    else:
        main()
