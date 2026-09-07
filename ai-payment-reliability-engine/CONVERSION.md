# CONVERSION.md — Setting up the RCAEval Python 3.12 environment

`tests/test_b2_rcaeval_parity.py` and `scripts/generate_b2_parity_report.py`
need the real `RCAEval` package, which requires Python 3.12 or 3.14 (its own
`README`/install docs say so — it depends on packages that don't support
older interpreters). This project's own test suite has no such requirement
and runs fine on whatever Python invokes `pytest` day to day; RCAEval is
therefore kept out of `requirements.txt` entirely and set up in a disposable
side venv instead. This file records exactly how that venv was built during
development, so it isn't lost/reinvented from scratch next time.

## 1. Install Python 3.12 (macOS/Homebrew)

```bash
brew install python@3.12
# installs as /opt/homebrew/bin/python3.12 (Apple Silicon) or
# /usr/local/bin/python3.12 (Intel); does not touch the system `python3`.
```

## 2. Create the venv and install RCAEval

```bash
python3.12 -m venv /tmp/rcaeval_env
source /tmp/rcaeval_env/bin/activate
python -m pip install --upgrade pip
pip install 'RCAEval[default]'

# RCAEval's own installer misses a couple of runtime deps it imports
# lazily; the ImportErrors only surface when you actually call into
# RCAEval.e2e / RCAEval.utility, not at `pip install` time:
pip install tqdm openpyxl

# Also needed by this project's own code that the venv imports
# (pre.signals.rcaeval, bench.baselines.rcaeval_baseline, pytest):
pip install pytest pyyaml networkx pandas numpy
```

Sanity check:

```bash
python -c "from RCAEval.e2e import baro; print('baro imported ok')"
```

`/tmp/rcaeval_env` is disposable — it's under `/tmp`, not inside the repo,
and is not referenced by `requirements.txt` or any committed config. If it
disappears (reboot, `/tmp` cleanup, etc.), repeat steps 1-2 to rebuild it;
nothing else depends on its exact path except the `source .../activate`
step below, which you re-run each session anyway.

## 3. Download the real RE2-TT dataset (2.8GB, ~22GB extracted)

```bash
# from the repo root, using either interpreter (download_rcaeval.py has
# no RCAEval-specific dependency, only stdlib + no third-party imports)
python3 data/scripts/download_rcaeval.py --dataset RE2-TT --out-dir /tmp/re2tt_extract
```

This downloads `RE2-TT.zip` from Zenodo record 14590730, verifies its MD5
against the pinned checksum in `download_rcaeval.py`, and extracts it to
`/tmp/re2tt_extract/RE2-TT/`. Takes roughly 10-15 minutes depending on
network speed; the file is 2,801,345,134 bytes.

## 4. Run the B2 parity test

```bash
source /tmp/rcaeval_env/bin/activate
cd /path/to/ai-payment-reliability-engine
RCAEVAL_RE2TT_DIR=/tmp/re2tt_extract/RE2-TT python -m pytest tests/test_b2_rcaeval_parity.py -v
```

Takes roughly 10-11 minutes (loading logs.csv/traces.csv for all 90 cases
dominates the runtime, even though B2/BARO itself only needs the metrics
file — the adapter loads the full FailureCase regardless of which fields a
given baseline uses).

## 5. Regenerate the committed parity report

```bash
source /tmp/rcaeval_env/bin/activate
cd /path/to/ai-payment-reliability-engine
python scripts/generate_b2_parity_report.py --re2tt-dir /tmp/re2tt_extract/RE2-TT
```

Writes `docs/b2_rcaeval_parity_report.md` and `.csv`. Commit both after
regenerating — they're deliberately committed artifacts, not gitignored,
so a reviewer can read the actual published-vs-observed numbers without
re-running any of the above.

## Known gotchas

- **Don't compare raw Avg@5 to the published table without rounding.**
  RCAEval's own `main.py` prints `round(evaluator.average(5), 2)` — the
  README table is already rounded to 2 decimal places. Comparing an
  unrounded observed value against it can show a spurious diff of up to
  `1/300 ≈ 0.0033` whenever the true hit-count fraction `k/75` isn't a
  round number at 2dp. `scripts/generate_b2_parity_report.py` rounds
  before diffing for exactly this reason — see its `observed_avg_at_5_raw`
  vs `observed_avg_at_5_rounded` columns if you need to check which
  case you're in.
- **`RCAEval.e2e.baro(..., dataset=...)` needs a non-`None` string.**
  Passing `dataset=None` silently disables `RCAEval.io.time_series.
  preprocess()`'s column-dropping/MB-conversion logic instead of raising.
  `bench.baselines.rcaeval_baseline.rank()` always passes `case.dataset`
  (e.g. `"RE2-TT"`); if you call `RCAEval.e2e.baro` directly for
  debugging, remember to pass something.
- **RE2 datasets ship `simple_metrics.csv`, not `data.csv`.** Only RE1
  cases and RCAEval's own smaller `multi-source-data.zip` demo release use
  `data.csv`. `pre.signals.rcaeval._resolve_metrics_file()` already
  handles this fallback; if you're poking at a RE2 case directory by hand,
  don't be surprised there's no `data.csv` there.
