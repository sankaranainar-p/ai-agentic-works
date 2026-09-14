#!/usr/bin/env python3
"""
bench/run_faithfulness_study.py — Run both A9 stage-2 judges on real RCA output.

For each of N real RCAEval RE1-OB cases:
  1. synthesise the A5 alert, build the A8 evidence pack
  2. generate an evidence-grounded RCAResult with an LLM (ollama:llama3.1)
  3. score every claim with BOTH stage-2 judges:
       - NLI cross-encoder  (cross-encoder/nli-deberta-v3-base)
       - chat model         (ollama:qwen3.8:27b — different family than the RCA model)

Plus a handful of DELIBERATELY MISMATCHED claims (real evidence ID, wrong claim
text) so we can confirm the judges score them below well-grounded claims.

Outputs (results/ is gitignored):
  results/faithfulness/<ts>/judge_scores.jsonl   one record per (case_id, claim)
  results/faithfulness/<ts>/manifest.json        models, digests, git SHA, counts

The JSONL is keyed on (case_id, claim_text) so the (separate, unstarted) human
rating study can compute Cohen's kappa by joining on those fields.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from bench.faithfulness import (
    DEFAULT_CHAT_JUDGE_DIGEST,
    NLI_MODEL_NAME,
    FaithfulnessChecker,
    JudgeBackend,
)
from pre.agents.evidence import EvidenceRanker
from pre.agents.rca import Claim, RCAAgent, RCAResult
from pre.llm.client import LLMClient
from pre.signals.alert_synth import synthesize_alert
from pre.signals.rcaeval import RCAEvalAdapter

RCA_MODEL_DIGEST = "ollama:llama3.1"

# 10 real RE1-OB cases spanning all five injected fault types.
CASE_IDS = [
    "RE1-OB_cartservice_cpu_1",
    "RE1-OB_checkoutservice_cpu_1",
    "RE1-OB_currencyservice_mem_1",
    "RE1-OB_adservice_mem_1",
    "RE1-OB_productcatalogservice_disk_1",
    "RE1-OB_cartservice_disk_1",
    "RE1-OB_checkoutservice_delay_1",
    "RE1-OB_adservice_delay_1",
    "RE1-OB_currencyservice_loss_1",
    "RE1-OB_productcatalogservice_loss_1",
]


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _load_cases(rcaeval_root: str, wanted: list[str]):
    want = set(wanted)
    out = {}
    for case, gt in RCAEvalAdapter(rcaeval_root, "RE1-OB"):
        if case.case_id in want:
            out[case.case_id] = (case, gt)
    missing = want - set(out)
    if missing:
        raise SystemExit(f"cases not found under {rcaeval_root}: {sorted(missing)}")
    return [out[cid] for cid in wanted]


def _adversarial_claims(pack) -> list[Claim]:
    """Real, anomalous evidence IDs paired with claim text that clearly does
    not follow from them. Stage 1 passes; stage 2 must score these low."""
    kpi = {i.id: i for i in pack.items if i.type == "kpi" and i.score >= 0.3}
    picks = []
    cpu = next((i for i in kpi.values() if i.id.endswith(":cpu")), None)
    mem = next((i for i in kpi.values() if i.id.endswith(":mem")), None)
    any_item = next(iter(kpi.values()), None)

    if cpu is not None:
        picks.append(Claim(
            text="The email service ran out of disk space, causing message delivery to halt.",
            evidence_ids=[cpu.id], confidence=0.9,
        ))
    if mem is not None:
        picks.append(Claim(
            text="A DNS misconfiguration made the payment gateway unreachable from the frontend.",
            evidence_ids=[mem.id], confidence=0.9,
        ))
    if not picks and any_item is not None:
        picks.append(Claim(
            text="An expired TLS certificate blocked all inbound checkout requests.",
            evidence_ids=[any_item.id], confidence=0.9,
        ))
    return picks


def _grounded_control_claim(pack) -> Claim | None:
    """A hand-built claim that DOES follow from real evidence, as a positive
    control for the adversarial comparison."""
    for it in pack.items:
        if it.type == "kpi" and it.id.endswith(":cpu") and it.score >= 0.3:
            svc = it.service
            return Claim(
                text=f"{svc} experienced CPU saturation, with its CPU metric spiking far above baseline.",
                evidence_ids=[it.id], confidence=0.9,
            )
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rcaeval-root", default="data/rcaeval")
    ap.add_argument("--out-root", default="results/faithfulness")
    ap.add_argument("--llm-cache", default=".llm_cache")
    ap.add_argument("--limit", type=int, default=len(CASE_IDS), help="first N cases (for a quick run)")
    args = ap.parse_args()

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = Path(args.out_root) / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    client = LLMClient(cache_dir=args.llm_cache)
    cases = _load_cases(args.rcaeval_root, CASE_IDS[: args.limit])

    records: list[dict] = []
    mis_synthesised: list[dict] = []
    print(f"{'case_id':<34} {'kind':<5} {'s1':<3} {'nli':>6} {'chat':>6}  claim")
    print("-" * 130)

    for case, gt in cases:
        alert = synthesize_alert(case)
        # Mis-synthesis: the alert fired (not silent) but matched a service
        # other than the case's ground-truth root cause — see PROTOCOL.md's
        # mis_synthesised counter (A20 review). Reported for all 10 cases,
        # not just RE1-OB_cartservice_disk_1 where it was first found.
        if not alert.silent and alert.service != gt.root_cause_service:
            mis_synthesised.append({
                "case_id": case.case_id,
                "matched_service": alert.service,
                "ground_truth_service": gt.root_cause_service,
            })
        pack = EvidenceRanker(case, alert).rank()
        agent = RCAAgent(pack)
        rca: RCAResult = agent.generate(alert.text, client, model_digest=RCA_MODEL_DIGEST, seed=0)

        tagged: list[tuple[str, Claim]] = [("rca", c) for c in rca.claims]
        gc = _grounded_control_claim(pack)
        if gc is not None:
            tagged.append(("control", gc))
        tagged += [("adversarial", c) for c in _adversarial_claims(pack)]

        nli_checker = FaithfulnessChecker(pack, JudgeBackend.NLI_CROSS_ENCODER)
        chat_checker = FaithfulnessChecker(pack, JudgeBackend.CHAT_MODEL, chat_model_digest=DEFAULT_CHAT_JUDGE_DIGEST, llm_client=client)

        for kind, claim in tagged:
            nli = nli_checker.check_claim(claim)
            chat = chat_checker.check_claim(claim)
            ev_rendered = " | ".join(
                nli_checker.evidence_by_id[e].description
                for e in claim.evidence_ids if e in nli_checker.evidence_by_id
            )
            rec = {
                "case_id": case.case_id,
                "ground_truth_service": gt.root_cause_service,
                "ground_truth_fault": gt.fault_type,
                "kind": kind,
                "claim_text": claim.text,
                "evidence_ids": list(claim.evidence_ids),
                "evidence_rendered": ev_rendered,
                "stage1_pass": nli.stage1_pass,
                "stage1_reason": nli.stage1_reason,
                "nli_score": round(nli.stage2_score, 4),
                "nli_raw": nli.judge_output,
                "nli_model": NLI_MODEL_NAME,
                "chat_score": round(chat.stage2_score, 4),
                "chat_valid": chat.stage2_valid,
                "chat_raw": chat.judge_output,
                "chat_model_digest": DEFAULT_CHAT_JUDGE_DIGEST,
                "is_adversarial": kind == "adversarial",
            }
            records.append(rec)
            s1 = "Y" if nli.stage1_pass else "n"
            n = f"{nli.stage2_score:.3f}" if nli.stage1_pass else "  -  "
            c = f"{chat.stage2_score:.3f}" if chat.stage1_pass else "  -  "
            print(f"{case.case_id:<34} {kind:<5} {s1:<3} {n:>6} {c:>6}  {claim.text[:70]}")

    # --- write outputs -------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "judge_scores.jsonl"
    jsonl_path.write_text("".join(json.dumps(r) + "\n" for r in records))

    grounded = [r for r in records if not r["is_adversarial"] and r["stage1_pass"]]
    adversarial = [r for r in records if r["is_adversarial"] and r["stage1_pass"]]

    def _mean(rs, k):
        return sum(r[k] for r in rs) / len(rs) if rs else float("nan")

    # Faithfulness metric (chat judge only) + NLI corroboration, via the same
    # aggregator the pipeline uses.
    from bench.faithfulness import FaithfulnessScore, compute_faithfulness_metrics

    def _fs(r, judge, key):
        valid = r.get("chat_valid", True) if judge == "chat_model" else True
        return FaithfulnessScore(
            claim_text=r["claim_text"], evidence_ids=tuple(r["evidence_ids"]),
            stage1_pass=r["stage1_pass"], stage1_reason=r["stage1_reason"],
            stage2_score=r[key], stage2_judge=judge, judge_output="",
            overall_faithful=(judge == "chat_model" and r["stage1_pass"] and valid and r[key] >= 0.5),
            stage2_valid=valid,
        )

    production = [r for r in records if r["kind"] == "rca"]
    chat_scores = [_fs(r, "chat_model", "chat_score") for r in records]

    # Canonical nli_corroboration_rate is production-only: chat-faithful REAL
    # RCA claims (kind=="rca") whose NLI score also clears the threshold,
    # over a production-only denominator. control/adversarial claims are
    # judge-calibration probes, not production output, and must not dilute
    # this denominator (see the reproducibility-audit finding this fixes).
    faithfulness = compute_faithfulness_metrics(
        chat_scores,
        nli_scores=[_fs(r, "nli_cross_encoder", "nli_score") for r in production],
    )
    # Retained for reference only, not the canonical metric.
    faithfulness["nli_corroboration_rate_all_populations"] = compute_faithfulness_metrics(
        chat_scores,
        nli_scores=[_fs(r, "nli_cross_encoder", "nli_score") for r in records],
    )["nli_corroboration_rate"]

    summary = {
        "n_records": len(records),
        "n_cases": len(cases),
        "n_mis_synthesised": len(mis_synthesised),
        "mis_synthesised_cases": mis_synthesised,
        "n_grounded_stage1_pass": len(grounded),
        "n_adversarial_stage1_pass": len(adversarial),
        "faithfulness": faithfulness,  # avg_faithfulness_score, nli_corroboration_rate, caveats
        # --- NLI characterisation ONLY (not faithfulness numbers): shows the
        #     capability ceiling — grounded ~ adversarial ~ 0 (see PROTOCOL.md) ---
        "nli_characterisation": {
            "mean_grounded": round(_mean(grounded, "nli_score"), 4),
            "mean_adversarial": round(_mean(adversarial, "nli_score"), 4),
            "mean_near_verbatim_grounded": round(
                _mean([r for r in grounded if r["nli_score"] >= 0.8], "nli_score"), 4
            ),
        },
        "chat_grounded_mean": round(_mean(grounded, "chat_score"), 4),
        "chat_adversarial_mean": round(_mean(adversarial, "chat_score"), 4),
    }
    manifest = {
        "timestamp": ts,
        "git_sha": _git_sha(),
        "rca_model_digest": RCA_MODEL_DIGEST,
        "chat_judge_model_digest": DEFAULT_CHAT_JUDGE_DIGEST,
        "nli_model": NLI_MODEL_NAME,
        "primary_judge": "chat_model",
        "nli_note": (
            "NLI scores are NOT averaged into any faithfulness number (see "
            "PROTOCOL.md). summary.faithfulness.* is the chat judge only; NLI "
            "enters only as nli_corroboration_rate, computed over PRODUCTION "
            "claims only (kind=='rca') -- control/adversarial claims are "
            "judge-calibration probes excluded from this denominator. The "
            "same rate computed over all populations is retained for "
            "reference as nli_corroboration_rate_all_populations. "
            "summary.nli_characterisation documents the capability ceiling "
            "and is not a faithfulness metric."
        ),
        "case_ids": [c.case_id for c, _ in cases],
        "summary": summary,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print("\n" + json.dumps(summary, indent=2))
    print(f"\nwrote {jsonl_path}")
    print(f"wrote {out_dir / 'manifest.json'}")

    nli_c = summary["nli_characterisation"]
    ok = (
        adversarial and grounded
        # Primary judge: real separation between grounded and adversarial.
        and summary["chat_grounded_mean"] - summary["chat_adversarial_mean"] > 0.3
        # NLI precision: it must FLOOR adversarial claims (its grounded mean is
        # expected to be low too — the documented capability ceiling).
        and nli_c["mean_adversarial"] < 0.1
        and nli_c["mean_adversarial"] < nli_c["mean_grounded"]
    )
    if not ok:
        print("\nFAIL: judges did not separate grounded from adversarial as required.", file=sys.stderr)
        sys.exit(1)
    print("\nPASS: chat judge separates grounded/adversarial; NLI floors adversarial.")


if __name__ == "__main__":
    main()
