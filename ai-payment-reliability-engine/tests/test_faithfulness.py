"""
tests/test_faithfulness.py — Tests for two-stage faithfulness checking.

Tests stage 1 (existence and anomaly) and stage 2 (entailment judgment).
"""

import pytest

from bench.faithfulness import (
    FaithfulnessChecker,
    FaithfulnessScore,
    JudgeBackend,
    _get_nli_model,
    compute_faithfulness_metrics,
    nli_probs,
)
from pre.agents.evidence import EvidenceItem, EvidencePack
from pre.agents.rca import Claim, RCAResult
from pre.llm.client import LLMResponse


class _FakeLLM:
    """Returns a scripted LLMResponse per call; records the max_tokens seen."""

    def __init__(self, reply_fn):
        self.reply_fn = reply_fn  # (call_index, max_tokens) -> LLMResponse
        self.max_tokens_seen: list[int] = []

    def call(self, prompt, model_digest, system_prompt=None, max_tokens=2000, seed=None):
        self.max_tokens_seen.append(max_tokens)
        return self.reply_fn(len(self.max_tokens_seen) - 1, max_tokens)


def _resp(text, truncated):
    return LLMResponse(text=text, model_digest="ollama:qwen3.8:27b",
                       cached=False, tokens_used=999, truncated=truncated)


@pytest.fixture(scope="session")
def nli_ready():
    """Load the NLI cross-encoder once; skip NLI tests if it can't be loaded
    (offline CI with no cached model)."""
    try:
        _get_nli_model()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"NLI model unavailable: {e}")


def _pack(*items):
    return EvidencePack(case_id="TEST", items=list(items), token_estimate=50)


def test_faithfulness_checker_stage1_missing_id():
    """Test stage 1 fails when evidence ID is missing."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service overload",
        evidence_ids=["kpi:unknown:metric"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert not score.stage1_pass
    assert "Missing evidence IDs" in score.stage1_reason
    assert not score.overall_faithful


def test_faithfulness_checker_stage1_weak_anomaly():
    """Test stage 1 fails when evidence has low anomaly score."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.2, "Weak signal", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service issue",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert not score.stage1_pass
    assert "Weak anomalies" in score.stage1_reason
    assert not score.overall_faithful


def test_faithfulness_checker_stage1_pass():
    """Test stage 1 passes with valid anomalous evidence."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.8, "CPU spiked", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service overload",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert score.stage1_reason == "All evidence IDs present and anomalous"


def _nli_stage2(pack_item_desc, claim_text):
    pack = _pack(EvidenceItem("kpi:svc:m", "kpi", 1.0, pack_item_desc, "svc"))
    checker = FaithfulnessChecker(pack, JudgeBackend.NLI_CROSS_ENCODER)
    return checker.stage2_check(
        Claim(text=claim_text, evidence_ids=["kpi:svc:m"], confidence=0.9)
    )[0]


def test_nli_backend_varies_by_pair(nli_ready):
    """The NLI backend must produce DIFFERENT scores for different (evidence,
    claim) pairs — the old stub returned a constant 0.5 for everything, and a
    later blend parked every uncertain claim at exactly 0.5."""
    restatement = _nli_stage2("svc:cpu spiked to 98.0 (z=61.0)", "svc CPU spiked to about 98")
    contradiction = _nli_stage2("svc:cpu spiked to 98.0 (z=61.0)", "svc CPU stayed at its normal level")
    unrelated = _nli_stage2("svc:cpu spiked to 98.0 (z=61.0)", "a database on another service ran out of disk space")

    assert len({restatement, contradiction, unrelated}) == 3
    for v in (restatement, contradiction, unrelated):
        assert v != 0.5
    assert restatement > 0.8            # near-verbatim -> strong entailment
    assert contradiction < 0.1
    assert unrelated < 0.1


def test_nli_backend_grounded_beats_contradiction(nli_ready):
    supported = _nli_stage2(
        "currencyservice:latency spiked to 1.0s (z=12158)", "currencyservice latency increased sharply"
    )
    contradicted = _nli_stage2(
        "currencyservice:latency spiked to 1.0s (z=12158)", "currencyservice latency stayed flat and healthy"
    )
    assert supported > 0.5 > contradicted


def test_nli_known_failure_paraphrase_with_inference_scores_low(nli_ready):
    """DOCUMENTED FAILURE (PROTOCOL.md): a supported claim that is not a strict
    textual entailment is routed to `neutral`, so P(entailment) is ~0. This is
    locked in as known behaviour, not a bug — the chat judge is the primary
    signal precisely because of this."""
    inferred = _nli_stage2("svc:cpu spiked to 98.0 (z=61.0)", "svc was under severe CPU pressure")
    assert inferred < 0.2  # true, but the NLI judge cannot tell


# --- Characterisation of the NLI judge's capability (PROTOCOL.md cites these) ---
def test_nli_capability_general_paraphrase_head_works(nli_ready):
    """The entailment head is NOT broken: on general-language pairs it does
    real paraphrase entailment. The task failure below is domain/format +
    abstraction specific, not a dead model."""
    assert nli_probs(
        "A man is playing a guitar on stage.", "A person is performing music."
    )["entailment"] > 0.8
    assert nli_probs(
        "CPU usage on the host reached 100 percent.", "The host CPU was saturated."
    )["entailment"] > 0.8


def test_nli_capability_one_hop_substitution_is_recognised(nli_ready):
    """It DOES entail a claim that is one lexical/directional step from the
    evidence's literal text."""
    ev = "cartservice:cpu spiked to 100.0 (z=108.5)"
    for claim in (
        "cartservice CPU rose to 100",
        "cartservice CPU reached 100 percent",
        "cartservice experienced very high CPU usage",
    ):
        assert nli_probs(ev, claim)["entailment"] > 0.8, claim


def test_nli_capability_abstraction_and_zscore_fail(nli_ready):
    """It CANNOT name an implied failure mode or interpret the z-score — the
    move most real RCA claims make. These are all TRUE given the evidence."""
    ev = "cartservice:cpu spiked to 100.0 (z=108.5)"
    for claim in (
        "cartservice CPU was saturated",
        "cartservice CPU was fully utilized",
        "cartservice CPU deviated far from its normal range",   # z=108.5 literally means this
        "cartservice experienced CPU saturation",
    ):
        assert nli_probs(ev, claim)["entailment"] < 0.2, claim
    # and the two-hop chain it refuses even though it accepts each hop alone:
    assert nli_probs(ev, "cartservice CPU reached 100 percent")["entailment"] > 0.8
    assert nli_probs("cartservice CPU reached 100 percent", "cartservice CPU was saturated")["entailment"] > 0.8
    assert nli_probs(ev, "cartservice CPU was saturated")["entailment"] < 0.2


def test_deliberately_mismatched_claim_scores_lower_nli(nli_ready):
    """Requirement (4): a claim citing evidence that clearly does not support
    it must score below a well-grounded claim on the SAME evidence."""
    pack = _pack(
        EvidenceItem("kpi:cartservice:cpu", "kpi", 1.0, "cartservice:cpu spiked to 100.0 (z=108.5)", "cartservice"),
    )
    checker = FaithfulnessChecker(pack, JudgeBackend.NLI_CROSS_ENCODER)

    well_grounded = checker.check_claim(
        Claim(text="cartservice CPU spiked to 100", evidence_ids=["kpi:cartservice:cpu"], confidence=0.9)
    )
    mismatched = checker.check_claim(
        Claim(text="the email service ran out of disk space, halting message delivery",
              evidence_ids=["kpi:cartservice:cpu"], confidence=0.9)
    )

    assert well_grounded.stage1_pass and mismatched.stage1_pass  # both cite real anomalous evidence
    assert mismatched.stage2_score < well_grounded.stage2_score
    assert well_grounded.stage2_score > 0.8
    assert not mismatched.overall_faithful


# --- chat judge: truncated-response handling (no live LLM needed) ---
def _chat_checker(fake):
    pack = _pack(EvidenceItem("kpi:svc:cpu", "kpi", 0.9, "svc:cpu spiked to 99 (z=40)", "svc"))
    return pack, FaithfulnessChecker(pack, JudgeBackend.CHAT_MODEL, llm_client=fake)


def _claim():
    return Claim(text="svc CPU spiked to about 99", evidence_ids=["kpi:svc:cpu"], confidence=0.9)


def test_chat_judge_retries_on_truncation_then_succeeds():
    # first call (800 tok) truncated; retry (2400 tok) returns a full reply
    fake = _FakeLLM(lambda i, mt: _resp(
        '{"entailment": 90, "reason": "ok"}' if mt > 800 else '{"entailment": 9',
        truncated=(mt <= 800),
    ))
    _, checker = _chat_checker(fake)
    result = checker.check_claim(_claim())

    assert fake.max_tokens_seen == [800, 2400]        # retried with a bigger budget
    assert result.stage2_valid is True
    assert result.stage2_score == pytest.approx(0.9)  # parsed from the RETRY, not the partial
    assert result.overall_faithful is True


def test_chat_judge_flags_truncation_after_retry_as_invalid():
    # every call is truncated — even the retry
    fake = _FakeLLM(lambda i, mt: _resp('{"entailment": 55, "reason": "the ev', truncated=True))
    _, checker = _chat_checker(fake)
    result = checker.check_claim(_claim())

    assert fake.max_tokens_seen == [800, 2400]
    assert result.stage2_valid is False              # NOT silently trusted
    assert "TRUNCATED" in result.judge_output
    assert result.overall_faithful is False          # invalid -> never faithful
    # even though "55" is present in the partial text and would regex-parse to 0.55


def test_chat_judge_flags_unparseable_reply_as_invalid():
    fake = _FakeLLM(lambda i, mt: _resp("I cannot answer that.", truncated=False))
    _, checker = _chat_checker(fake)
    result = checker.check_claim(_claim())

    assert fake.max_tokens_seen == [800]             # no retry (not truncated)
    assert result.stage2_valid is False
    assert "UNPARSED" in result.judge_output
    assert result.overall_faithful is False


def test_faithfulness_score_multiple_evidence(nli_ready):
    """Test faithfulness score with multiple evidence IDs."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "payment:cpu spiked to 95.0 (z=40)", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "payment→bank errors 2%→60%", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=80)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service degraded, with CPU spiking and its error rate climbing",
        evidence_ids=["kpi:payment:cpu", "span:t1a2b"],
        confidence=0.85,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert len(score.evidence_ids) == 2
    assert score.judge_output.startswith("[NLI ")


def test_faithfulness_checker_rca_result(nli_ready):
    """Test checking all claims in an RCA result."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "payment:cpu spiked to 97.0 (z=55)", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "payment to bank errors rose from 1% to 70%", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=80)
    checker = FaithfulnessChecker(pack)

    result = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU overload",
        claims=[
            Claim(text="payment CPU spiked to about 97", evidence_ids=["kpi:payment:cpu"], confidence=0.9),
            Claim(text="the payment to bank error rate rose sharply", evidence_ids=["span:t1a2b"], confidence=0.85),
            Claim(text="Misconfiguration issue", evidence_ids=["kpi:unknown:metric"], confidence=0.5),
        ],
    )

    scores = checker.check_rca_result(result)

    assert len(scores) == 3
    assert scores[0].stage1_pass and scores[1].stage1_pass
    assert not scores[2].stage1_pass  # unknown evidence id
    assert not scores[2].overall_faithful
    # the two near-verbatim claims are strict entailments -> out-score the
    # stage-1 failure (0.0)
    assert min(scores[0].stage2_score, scores[1].stage2_score) > scores[2].stage2_score


def _fs(claim, ids, s1, score, judge, faithful, reason="Pass"):
    return FaithfulnessScore(claim, ids, s1, reason, score, judge, "", faithful)


def test_compute_faithfulness_metrics_empty():
    m = compute_faithfulness_metrics([])
    assert m["stage1_pass_rate"] == 0.0
    assert m["stage2_pass_rate"] is None
    assert m["overall_faithful_rate"] is None
    assert m["avg_faithfulness_score"] is None


def test_compute_faithfulness_metrics_chat_only_all_pass():
    """The faithfulness numbers come from the chat judge."""
    scores = [
        _fs("Claim 1", ["id1"], True, 0.90, "chat_model", True),
        _fs("Claim 2", ["id2"], True, 0.85, "chat_model", True),
    ]
    m = compute_faithfulness_metrics(scores)

    assert m["stage1_pass_rate"] == 1.0
    assert m["stage2_pass_rate"] == 1.0
    assert m["overall_faithful_rate"] == 1.0
    assert m["avg_faithfulness_score"] == pytest.approx(0.875)
    assert m["caveats"] == []


def test_compute_faithfulness_metrics_nli_low_scores_enter_no_average():
    """Item #2, done properly: NLI's near-zero scores must not be averaged into
    ANY faithfulness statistic — only their HIGH scores, as corroboration."""
    scores = [
        # claim c1: chat says faithful; NLI near-verbatim confirms it
        _fs("c1", ["id1"], True, 0.02, "nli_cross_encoder", False),
        _fs("c1", ["id1"], True, 0.95, "chat_model", True),
        # claim c2: chat says faithful (abstractive but grounded); NLI scores ~0
        _fs("c2", ["id2"], True, 0.001, "nli_cross_encoder", False),
        _fs("c2", ["id2"], True, 0.80, "chat_model", True),
        # claim c3: NLI HIGH corroboration of a chat-faithful claim
        _fs("c3", ["id3"], True, 0.97, "nli_cross_encoder", True),
        _fs("c3", ["id3"], True, 0.90, "chat_model", True),
    ]
    m = compute_faithfulness_metrics(scores)

    # faithfulness score is the chat mean ONLY — no NLI values in it
    assert m["avg_faithfulness_score"] == pytest.approx((0.95 + 0.80 + 0.90) / 3)
    assert "avg_entailment_score" not in m  # the old mixed mean is gone
    # NLI enters exactly one aggregate, and only via its high scores:
    # of 3 chat-faithful claims, NLI scores >= 0.8 on 1 (c3) -> 1/3
    assert m["nli_corroboration_rate"] == pytest.approx(1 / 3)
    assert m["nli_confirm_threshold"] == 0.8
    assert any("NOT averaged" in c for c in m["caveats"])


def test_compute_metrics_excludes_invalid_stage2():
    scores = [
        _fs("c1", ["i1"], True, 0.90, "chat_model", True),
        _fs("c2", ["i2"], True, 0.80, "chat_model", True),
        FaithfulnessScore("c3", ["i3"], True, "Pass", 0.5, "chat_model", "<<TRUNCATED>>",
                          overall_faithful=False, stage2_valid=False),
    ]
    m = compute_faithfulness_metrics(scores)

    assert m["n_stage2_invalid"] == 1
    assert m["avg_faithfulness_score"] == pytest.approx(0.85)   # 0.5 not averaged in
    assert m["stage2_pass_rate"] == pytest.approx(1.0)          # 2/2 valid claims faithful
    assert m["overall_faithful_rate"] == pytest.approx(2 / 3)   # invalid counts against
    assert any("invalid" in c for c in m["caveats"])


def test_compute_faithfulness_metrics_nli_only_cannot_report_faithfulness():
    scores = [
        _fs("c1", ["id1"], True, 0.02, "nli_cross_encoder", False),
        _fs("c2", ["id2"], True, 0.97, "nli_cross_encoder", True),
    ]
    m = compute_faithfulness_metrics(scores)
    assert m["avg_faithfulness_score"] is None
    assert m["stage2_pass_rate"] is None
    assert any("cannot be computed from NLI alone" in c for c in m["caveats"])


def test_compute_faithfulness_metrics_partial_pass():
    scores = [
        _fs("Claim 1", ["id1"], True, 0.90, "chat_model", True),
        _fs("Claim 2", ["id2"], False, 0.0, "none", False, reason="Missing ID"),
        _fs("Claim 3", ["id3"], True, 0.30, "chat_model", False),
    ]
    m = compute_faithfulness_metrics(scores)

    assert m["stage1_pass_rate"] == pytest.approx(2.0 / 3.0)
    assert m["stage2_pass_rate"] == pytest.approx(0.5)          # 1 of 2 stage-1 passers
    assert m["overall_faithful_rate"] == pytest.approx(1.0 / 3.0)
    assert m["avg_faithfulness_score"] == pytest.approx(0.6)    # (0.9 + 0.3) / 2
