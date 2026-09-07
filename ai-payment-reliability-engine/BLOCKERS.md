# Phase 2 Blockers — A7, A9, A11

## Status: Three components need real implementation before Phase 3

### A7 (Calibrated Triage Agent) — SCAFFOLDING ONLY

**Issue**: The triage agent has the schema and interface, but the ML model is untrained and the LLM ensemble is a stub.

**What exists**:
- `pre/agents/triage.py` with `TriageModel`, `TriageResult`, `KPIFeatures`
- Placeholder logistic regression and isotonic calibration imports
- Tests pass because they don't validate model outputs

**What's missing**:
1. **Model training**: Fit logistic regression on RCAEval train split (60%)
2. **Isotonic calibration**: Fit on validation split (20%), using predicted probabilities
3. **LLM reliability weights**: Learn per-class weights on validation split from LLM votes
4. **Tau tuning**: Precision-vs-threshold sweep on validation set to find tau for 95% precision
5. **Model persistence**: Save fitted model + calibrator + weights + tau to `models/triage_model.joblib`

**Current state**:
- `abstention_tau = 0.65` is hardcoded (untuned guess)
- `_ml_predict()` returns `(0.5, "unknown")` (stub)
- LLM reliability weights are empty dict

**To fix**: Implement `tools/calibrate_triage.py` to actually train on RCAEval/OpenRCA validation split and generate a report showing precision at tau.

**Blocking**: Phase 3 cannot use triage for real incident classification until this is done.

---

### A9 (Faithfulness Checker) — JUDGE BACKENDS ARE STUBS

**Issue**: Two-stage faithfulness logic is correct, but both judge backends return hardcoded scores.

**What exists**:
- `pre/audit/faithfulness.py` with two-stage checking
- `FaithfulnessChecker.stage1_check()` works (existence + anomaly)
- `FaithfulnessChecker.stage2_check()` calls judge but gets constant 0.5

**What's missing**:
1. **NLI cross-encoder backend**: 
   - `_judge_nli()` currently returns `similarity = 0.5`
   - Needs: `from sentence_transformers import CrossEncoder`
   - Call: `cross_encoder.predict([[evidence_text, claim_text]])`
   - Add `sentence-transformers==3.0.1` to requirements.txt

2. **Chat model backend**:
   - `_judge_chat()` currently returns `similarity = 0.5`
   - Needs: Call Ollama/Groq with entailment prompt
   - Parse response to extract confidence score
   - Currently just a placeholder

**Current state**:
- Tests pass because they only check that the structure records outputs
- Both backends return 0.5 regardless of input
- Human rating study has no real judge output to compare

**To fix**: 
1. Wire sentence-transformers NLI model into `_judge_nli()`
2. Implement actual LLM entailment prompting in `_judge_chat()`
3. Re-run human rating study with real judge outputs to validate

**Blocking**: Phase 3 cannot validate RCA faithfulness against human consensus until judges are real.

---

### A11 (Orchestrator) — LIVE CALLS NEVER TESTED

**Issue**: LLM client and orchestrator are scaffolded with working test coverage, but the end-to-end pipeline has never been run.

**What exists**:
- `pre/llm/client.py` with HTTP calls to Ollama and vLLM
- Disk cache layer (works, tested)
- `pre/agents/orchestrator.py` with step execution
- No-live-calls mode for replaying from cache (works)

**What's missing**:
1. **Live call validation**:
   - No Ollama or vLLM instance was brought up to test HTTP handshake
   - Field names assumed: `eval_count` (Ollama), `completion_tokens` (vLLM) — unverified
   - Token counting logic never validated against real responses

2. **End-to-end pipeline**:
   - No actual pipeline steps wired together (alert → triage → RCA → evidence → actions)
   - Orchestrator tested with mock steps only
   - Never run full flow on a real FailureCase fixture

3. **Reproducibility claim**:
   - Cache reproducibility: verified (identical cache hits work)
   - Pipeline reproducibility: unverified (no two full runs compared)

**Current state**:
- `_call_ollama()` and `_call_vllm()` have real HTTP code but no live testing
- `Orchestrator.run()` works with mock steps, never with real steps
- vllm SDK not in requirements (just commented as "needs validation")

**To fix**:
1. Spin up Ollama or vLLM instance
2. Call it from LLM client, verify response field names
3. Wire together all pipeline steps (synthesize alert → triage → RCA → evidence → actions)
4. Run full pipeline on RCAEval fixture once with live calls
5. Run same fixture again in no-live-calls mode
6. Diff ledgers to verify reproducibility

**Blocking**: Phase 3 cannot deploy the orchestrator for production until live calls are validated.

---

## Requirements.txt Now Pinned

`requirements.txt` created with:
- Core working dependencies pinned (numpy, pandas, sklearn, networkx, pydantic, httpx)
- sentence-transformers and vllm commented out with blockers noted
- Next phases should uncomment once blockers are resolved

---

## Summary

**A6 (Dependency Graph)**: ✅ Complete, tested, ready  
**A8 (Evidence Agent)**: ✅ Complete, tested, ready  
**A10 (Policy Verifier)**: ✅ Complete, tested, ready  

**A7 (Triage)**: ⚠️ Scaffolding — needs model training + tau tuning from validation set  
**A9 (Faithfulness)**: ⚠️ Scaffolding — needs real NLI + LLM judges, sentence-transformers installed  
**A11 (Orchestrator)**: ⚠️ Scaffolding — needs live Ollama/vLLM test, end-to-end pipeline wiring  

Phase 3 should prioritize these three in order: A7 (simplest, just train model), A9 (wire judges), A11 (full integration).
