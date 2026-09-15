# Human Faithfulness Rating — Rubric & Pre-Registration

**STATUS: DRAFTED 2026-09-14, NOT YET FROZEN.** This document is not
authoritative until both listed sign-offs below are checked with a name
and date. A rubric only its drafter has approved is not frozen in any
sense that protects the resulting kappa — freezing requires human
review, specifically of the worked examples, before any rater sees them.

**Sign-off (fill in before rating begins):**
- [ ] Reviewed by: _______________  Date: _______
- [ ] Reviewed by: _______________  Date: _______

Once both lines above are filled in, this document is frozen: **do not
edit it after rating begins.** A rubric revised after seeing rater
disagreement produces a kappa that means nothing — if a change is
genuinely needed after freeze, it goes in a new dated file, never as an
edit here, and the study restarts under the new version.

## Pre-registration record

- **Target statistic:** Cohen's kappa between two human raters, and
  between the primary chat judge and the human consensus, on RCA claim
  faithfulness (pass/fail).
- **Sample size:** N = 88 (derivation below). Formula: Donner & Eliasziw
  (1992) / Fleiss, Cohen & Everitt (1969) equal-marginals variance of
  kappa, verified against Cantor (1996, *Psychological Methods*, Table 1,
  Q=0.510 at π=0.5, κ=0.7).
- **Inputs:** κ0 = 0.70, 95% CI half-width ω ≤ 0.15, z = 1.96, assumed
  common pass-rate π = 0.5 (see arithmetic below; result is insensitive to
  using this project's own empirical rate instead).
- **KNOWN GAP, recorded not hidden:** the canonical faithfulness dataset
  (`docs/faithfulness/judge_scores.jsonl`, commit 73a5dfce) contains only
  **67 claims**, short of the required 88 by 21. Sprint 1.5 recruitment
  planning must either (a) generate ≥21 additional claims via further RCA
  runs before Sprint 2 rating begins, or (b) formally relax ω before
  freezing N, or (c) accept a wider realized CI on the reported kappa.
  This gap is a Sprint 1.5 blocker, not a Sprint 2 problem.
  **Realized ω at N=67:** solving ω²=z²·Q/N gives ω=0.1710 (π=0.5) to
  0.1715 (π=0.537, this project's empirical rate) — about 14% wider than
  the ω≤0.15 target, not a large cost either way (b) or (c) is chosen.
  **Realized ω at N=74 (added 2026-09-15, option (a) partially exercised):**
  Task 1.4 expanded RE2-TT production claims to 34 (`results/faithfulness_task1.4/20260915T160745Z/`,
  not yet promoted to `docs/`), which combined with RE1-OB's original 40
  production claims gives **N=74**, still short of 88 by 14 (see
  Task 1.4 follow-up discussion). Same formula, same κ0/z:
  ω=0.1627 (π=0.5) to 0.1633 (π=0.5405 — this project's own combined
  production-only empirical faithful rate, 40/74 faithful across both
  datasets: RE1-OB 27/40=0.6750, RE2-TT 13/34=0.3824) — about 8.5–8.9%
  wider than the ω≤0.15 target, roughly **halving** the N=67 gap (14%→9%)
  without reaching it. **N=67 and N=74 are not directly comparable
  populations:** N=67 is RE1-OB's *entire* judge_scores.jsonl (production
  + control + adversarial, 40+9+18); N=74 is *production claims only*,
  pooled across two datasets with materially different faithful rates
  (0.675 vs 0.382 — RE1-OB and RE2-TT are not interchangeable here, see
  the separate-vs-merged figures question raised in the Task 1.4
  follow-up, still undecided). If the human-rating pool should also
  include RE2-TT's control/adversarial claims (80 more: 20 control + 60
  adversarial, RE2-TT total = 34+20+60 = 114), the all-populations
  combined N would be 67+114=181, comfortably clearing 88 — but rating
  synthetic control/adversarial claims alongside real production claims
  changes what the kappa measures and is a separate decision from the
  N=67 vs N=74 arithmetic above.
  **Recommendation (not a decision — pending co-author sign-off):**
  option (c). Rate all 67 now, pre-register ω≤0.15 and report the
  realized ω≈0.17 plainly alongside it — no post-hoc adjustment, no
  wait on additional pipeline runs, rater recruitment starts immediately.
  Option (a) is only worth it if the faithfulness sample is being
  expanded anyway for Task 1.4, in which case this rating pass should
  happen after that expansion, not run twice. Recorded 2026-09-14,
  pending co-author input.
- **Harness:** `bench/build_rating_harness.py`, allow-list field design
  (see script for the exact field list). Raters see `claim_text` and
  `evidence_rendered` only.
- **Frozen by:** this commit. Any subsequent edit to this file after
  rating data exists invalidates the reported kappa.

## Sample size derivation (Donner & Eliasziw, verified)

Formula (equal-marginals case; κ = assumed kappa, π = assumed common
probability of a "pass" rating by each rater):

```
Q(κ, π) = (1 - κ) · [ (1 - κ)(1 - 2κ) + κ(2 - κ) / (2π(1 - π)) ]
N = z²_(α/2) · Q(κ, π) / ω²
```

This is the Fleiss/Cohen/Everitt (1969) asymptotic variance of κ̂,
specialized to equal rater marginals — the case Donner & Eliasziw (1992)
use for their kappa confidence-interval / sample-size procedure. Verified
numerically against Cantor (1996), Table 1: at π=0.5, κ=0.7, the table
gives Q=0.510, matching this formula exactly:

```
(1 - 0.7) = 0.3
(1 - 0.7)(1 - 1.4) = 0.3 × (-0.4) = -0.12
0.7 × (2 - 0.7) = 0.7 × 1.3 = 0.91
2 × 0.5 × 0.5 = 0.5
0.91 / 0.5 = 1.82
-0.12 + 1.82 = 1.70
0.3 × 1.70 = 0.510   ✓ matches Cantor (1996) Table 1 exactly
```

Plugging in ω = 0.15, z = 1.96 (95% two-sided CI):

```
z² = 1.96² = 3.8416
ω² = 0.15² = 0.0225
z²/ω² = 3.8416 / 0.0225 = 170.7378

N = 170.7378 × 0.510 = 87.076  →  round up  →  N = 88
```

**Sensitivity check, project's own empirical rate.** The canonical
faithfulness run's `overall_faithful_rate` is 0.5373 (`docs/faithfulness/manifest.json`,
commit 73a5dfce) — using π=0.537 instead of 0.5:

```
π(1-π) = 0.537 × 0.463 = 0.248631
2π(1-π) = 0.497262
0.91 / 0.497262 = 1.83001
-0.12 + 1.83001 = 1.71001
0.3 × 1.71001 = 0.51300
N = 170.7378 × 0.51300 = 87.60  →  round up  →  N = 88
```

Same result either way. This is not a coincidence: π(1-π) is maximized at
π=0.5 (value 0.25) and is nearly flat near that maximum, so Q — and
therefore N — is at or near its **minimum** for any π close to 0.5.
**Correction to the plan: N ≈ 70 is not achievable at these parameters
under any assumed prevalence.** Solving for the π that would yield N=70
requires π(1-π) = 0.306, which exceeds the mathematical maximum of 0.25
(at π=0.5) — no valid prevalence produces N=70 here. N=88 is the floor,
not a point estimate to round down from.

## Rating task

Raters see exactly two fields per item: the **candidate claim** (one
sentence, produced by the RCA agent) and the **rendered evidence** (the
same evidence text string the automated judges scored — `evidence_rendered`
in `docs/faithfulness/judge_scores.jsonl`, e.g.
`"cartservice:cpu spiked to 100.0 (z=108.5)"`). Nothing else. For each
item, the rater records a single binary verdict: **PASS** or **FAIL**.
No partial credit, no confidence score, no free-text requirement (a note
field exists but is optional and excluded from the kappa computation).

**Question the rater answers:** *Is this claim a fair, evidence-licensed
characterization of what the rendered evidence shows — including a
reasonable abstractive restatement — with no fact, entity, or value that
isn't present in or directly implied by the evidence?*

### PASS criteria (all must hold)

1. Every quantitative value and entity (service name, metric, magnitude)
   the claim asserts is present in the rendered evidence, or is a direct,
   ordinary paraphrase of it (e.g. "spiked to 100%" → "saturated";
   "z=108.5" → "far above baseline").
2. The claim's directionality matches the evidence (increase vs. decrease,
   presence vs. absence).
3. Any causal or diagnostic link the claim draws between two pieces of
   evidence is a standard, common-sense mechanism (e.g. queue depth growth
   → latency increase), not a novel unstated mechanism.
4. If the claim cites a specific numeric value, it is within ordinary
   rounding of the evidence's value (treat unit/percent conversions as
   equivalent).

### FAIL criteria (any one is sufficient)

1. The claim names a service, component, metric, or mechanism that does
   not appear anywhere in the rendered evidence (fabrication).
2. The claim's direction contradicts the evidence (evidence shows a drop,
   claim asserts a rise, or vice versa).
3. The claim asserts a specific root cause or mechanism not licensed by
   the evidence shown — even if it is a plausible failure mode in
   general, if the rendered evidence does not support it, it fails.
4. The claim's cited value is materially different from the evidence's
   value (not explainable by rounding or unit conversion).

**Tie-break rule:** if torn between PASS and FAIL, use the anchor
question above — would a competent SRE reading only this evidence sheet
(no other context) accept the claim as fair? If still genuinely unsure,
record FAIL and note it in `rater_note`; kappa is computed on the binary
verdict only, so ties must resolve to one label, not a third category.

## Worked examples

### PASS example 1 — direct restatement

- **Evidence shown:** `cartservice:cpu spiked to 98.4 (z=41.2)`
- **Claim:** "cartservice experienced a CPU spike to approximately 98%,
  consistent with CPU saturation."
- **Verdict: PASS.** The numeric value (98% vs. 98.4) matches within
  rounding; "CPU saturation" is a licensed abstractive characterization of
  a spike to near-100%, per criterion 1.

### PASS example 2 — multi-evidence causal claim

- **Evidence shown:** `paymentservice:latency_p99 rose to 2400.0 (z=15.3) | paymentservice:queue_depth grew to 340.0 (z=12.1)`
- **Claim:** "paymentservice's request queue backed up (queue_depth
  reaching 340), consistent with the observed p99 latency increase to
  2.4s."
- **Verdict: PASS.** Both cited facts are directly present; the causal
  link (queue backlog → latency) is standard and common-sense, per
  criterion 3, not a novel unstated mechanism.

### FAIL example 1 — fabricated mechanism

- **Evidence shown:** `cartservice:cpu spiked to 98.4 (z=41.2)`
  (same evidence as PASS example 1, nothing else shown)
- **Claim:** "cartservice's Redis cache connection pool was exhausted,
  driving the CPU spike."
- **Verdict: FAIL.** "Redis cache connection pool" appears nowhere in the
  rendered evidence — a fabricated causal mechanism, per FAIL criterion 1.

### FAIL example 2 — contradicts evidence direction

- **Evidence shown:** `currencyservice:mem dropped to 12.0 (z=-9.4)`
- **Claim:** "currencyservice memory usage climbed steadily, indicating a
  memory leak."
- **Verdict: FAIL.** The evidence shows a drop (negative z); the claim
  asserts the opposite direction, per FAIL criterion 2 — this is a direct
  contradiction, not a characterization.
