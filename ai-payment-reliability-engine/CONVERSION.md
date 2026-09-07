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

# CONVERSION.md — OpenRCA Bank adapter (`pre/signals/openrca.py`)

This section documents every non-obvious schema decision made while
building `pre.signals.openrca.OpenRCABankAdapter`, and exactly how each
one was verified against real data (not just OpenRCA's README/paper),
so a second person can audit them without re-downloading everything
from scratch.

## 1. Why the Hugging Face mirror, not OpenRCA's own Google Drive link

OpenRCA's README points to a Google Drive folder
(`https://drive.google.com/drive/folders/1wGiEnu4OkWrjPxfx5ZTROnU37-5UDoPM`)
for the full telemetry. That link has no checksum manifest, no stable
per-file HTTP endpoint, and (per this project's own standing rule —
established for RCAEval in the section above) can't be scripted/verified
the way a direct HTTPS download can. A public mirror exists at
`https://huggingface.co/datasets/cdreetz/OpenRCA` (68.7GB total across
Bank/Market/Telecom); this project downloads only from there.

**How this was verified as trustworthy, not just convenient:**
- `Bank/record.csv` (8,668 bytes, 136 rows) and `Bank/query.csv`
  (56,803 bytes, 136 rows) were downloaded and their row count (136)
  cross-checked against OpenRCA's own archived
  `rca/archive/agent-Bank.csv` (136 rows) — an independently-published
  file from OpenRCA's own GitHub repo, not from this mirror. Matching
  row counts from two independently-hosted sources is strong evidence
  the mirror's `Bank/` data is the genuine OpenRCA Bank dataset, not a
  corrupted or partial copy.
- `Bank/record.csv`'s `component` values (`Mysql02`, `Redis02`, `Tomcat01`
  .. `Tomcat04`, `MG01`, `MG02`, `IG01`, `IG02`, `apache01`, `apache02`)
  and `reason` values (`high memory usage`, `network packet loss`, etc.)
  match the vocabulary described in OpenRCA's paper/README for a
  pod-level enterprise banking system.
- The claimed per-file schemas (`log_service.csv`,
  `metric_app.csv`/`metric_container.csv`, `trace_span.csv`) and
  granularities were independently re-derived from the raw downloaded
  bytes (see sections 2-4 below) rather than taken on faith from any
  README — every claim below was checked against actual downloaded rows.

## 2. Timezone: `record.csv`'s `timestamp` is UTC, `datetime` is UTC+8

Verified directly:

```python
>>> import pandas as pd
>>> pd.to_datetime(1614841020, unit="s", utc=True)
Timestamp('2021-03-04 06:57:00+0000', tz='UTC')
>>> pd.to_datetime(1614841020, unit="s", utc=True).tz_convert("Asia/Shanghai")
Timestamp('2021-03-04 14:57:00+0800', tz='Asia/Shanghai')
```

`record.csv` row 0's `datetime` column literally says
`2021-03-04 14:57:00` — matching the Shanghai conversion, not the raw
UTC value. This also matches OpenRCA's own README FAQ ("All faults are
recorded in the UTC+8 timezone"). **Getting this backwards silently
looks up the wrong day's telemetry folder** for any case within 8 hours
of UTC midnight (00:00-08:00 UTC = the *previous* day in Shanghai). No
such case exists in this dataset's actual 136 rows (spot-checked: no
`record.csv` timestamp falls in that UTC window), so this specific bug
would not have been caught by output-shape testing alone — only by
explicitly walking the timezone arithmetic, which is why
`_shanghai_date_folder()` and `evidence_window()` both do the UTC+8
conversion explicitly with a comment pointing back here.

## 3. Evidence window: 30-minute, minute-aligned Asia/Shanghai bucket

Reproduces OpenRCA's own `main/generate.py::timestamp2timeperiod`
line-for-line (`minute - (minute % 30)` to `+30min`). Verified against
every one of 4 spot-checked `query.csv` instruction strings, which state
this exact window in prose (generated by that same function):

| record.csv timestamp (Shanghai) | query.csv instruction says |
|---|---|
| 2021-03-04 14:57:00 | "within the time range of 14:30 to 15:00" |
| 2021-03-04 18:09:00 | "between 18:00 and 18:30" |
| 2021-03-06 06:20:00 | "from 06:00 to 06:30" |
| 2021-03-06 18:52:00 | "between 18:30 and 19:00" |

`tests/test_openrca_adapter.py::test_evidence_window_matches_query_csv_instruction_text`
checks the first 3 of these programmatically against real fixture data.

## 4. Telemetry file schemas (verified against raw downloaded bytes)

All four confirmed via `curl -r <byte-range>` partial downloads plus
`head`/`awk`/pandas inspection of the real files under
`Bank/telemetry/2021_03_04/` before writing any adapter code:

| File | Columns | Cadence | Verified how |
|---|---|---|---|
| `metric/metric_container.csv` | `timestamp,cmdb_id,kpi_name,value` | 60s (with real gaps up to 120s, see below) | sorted-unique timestamps across a byte range: `1614787200, 1614787260, 1614787320, ...` |
| `metric/metric_app.csv` | `timestamp,rr,sr,cnt,mrt,tc` | 60s | same check; `tc` is a synthetic transaction name (`ServiceTest1`..`11`), not a `record.csv` component |
| `log/log_service.csv` | `log_id,timestamp,cmdb_id,log_name,value` | ~1s (10-digit unix seconds) | digit-count of raw timestamp column + monotonic-order check on a sample |
| `trace/trace_span.csv` | `timestamp,cmdb_id,parent_id,span_id,trace_id,duration` | ~1ms (13-digit unix milliseconds) | digit-count of raw timestamp column (13 digits vs logs' 10) |

**`cmdb_id`** in `metric_container.csv`/`log_service.csv`/`trace_span.csv`
uses the same pod-component vocabulary as `record.csv`'s `component`
column (e.g. `Tomcat01`, `MG02`) — confirmed by intersecting the
`cmdb_id` value sets from all three files against `record.csv`'s
`component` column; all of `record.csv`'s 14 distinct components appear
in `metric_container.csv`'s `cmdb_id` values.

**`trace_span.csv`'s `duration` unit is NOT documented anywhere** in
OpenRCA's README, paper, or DeepWiki summary. This adapter assumes
milliseconds — consistent with the millisecond-resolution `timestamp`
column and the observed magnitude (values up to ~1691 in sampled data,
i.e. spans up to ~1.7 seconds, a plausible duration for a bank
transaction). `pre/signals/openrca.py::_load_traces` documents this as
an explicit assumption (not a verified fact) and converts to
`Span.duration_us` as `duration_ms * 1000`. **If you find authoritative
evidence of the true unit, only this one conversion needs fixing.**

**Real data gaps exist in `metric_container.csv` at native 60s
cadence** — e.g. for `Mysql02`'s `MEMUsedMemPerc` KPI in the
2021-03-04 14:30-15:00 window, consecutive real samples are 120s apart
in three places instead of the expected 60s (verified by directly
querying `metric_container_full_20210304.csv` for that
`cmdb_id`+`kpi_name` pair and observing timestamps
`..., 1614839400, 1614839520, 1614839580, ...` — a genuine gap in the
source telemetry, not an adapter bug). The 1s-resampling's
`is_forward_filled` flags correctly reflect these longer real gaps by
marking more consecutive seconds as forward-filled than a uniform 60s
cadence would produce.

## 5. Granularity unification: forward-fill flags

Metrics (60s) are upsampled to 1s resolution with
`MetricSeries.is_forward_filled[i]` set per-second: `False` for the one
second matching a real sample, `True` for the 59 (or more, given real
gaps — see above) synthesised seconds between real samples. Verified by
hand on `Mysql02:OSLinux-OSLinux_MEMORY_MEMORY_MEMUsedMemPerc` across the
2021-03-04 14:30-15:00 window: 20 real samples, 1780 forward-filled
seconds, out of 1800 total (`tests/test_openrca_adapter.py::
test_forward_fill_flags_correctly_mark_synthesised_seconds` checks this
property generically, not just for this one series). Logs and traces are
already sub-minute native cadence and are not resampled — see
`pre/signals/openrca.py` module docstring for the full rationale.

Leading seconds before a metric's first real sample within the window
are dropped, not zero-filled — this project's standing "never silently
fabricate data" stance (also applied in `pre/verification.py`'s
`NotImplementedError` stubs) extends to not inventing pre-history values
with no basis.

## 6. Fault-type mapping (`_REASON_TO_FAULT_CLASS`)

OpenRCA's `record.csv` `reason` strings (`"high memory usage"`,
`"network packet loss"`, `"JVM Out of Memory (OOM) Heap"`, etc.) don't
correspond to RCAEval's resource/network fault codes, so this project's
`data/taxonomy.yaml` `fault_class` list adds two new OpenRCA-specific
entries (`configuration_error`, `dependency_failure`). Reasons that are
conceptually the same class of fault RCAEval already names (e.g. "high
memory usage" ~ RCAEval's "memory") reuse that existing fault_class
rather than duplicating it; reasons with no RCAEval analogue currently
fall back to `dependency_failure`. **This mapping is this project's own
best-effort categorisation, not something OpenRCA itself defines** — the
verbatim original string is always preserved in `GroundTruth.
raw_fault_type` so no information is lost if this mapping needs revising.

All 8 distinct `reason` values actually present in `record.csv` were
enumerated (`awk -F, 'NR>1{print $5}' record.csv | sort -u`) and each one
explicitly mapped — none fall through to an unhandled default silently.

## 7. Building the real-data fixture (`tests/fixtures/openrca_bank/`)

Unlike `tests/fixtures/rcaeval/` (trimmed from a full evidence
window), `tests/fixtures/openrca_bank/` keeps only a narrow slice (±15s to
±60s depending on telemetry type) around 3 real `record.csv` rows
(indices 0, 1, 3 — components `Mysql02`, `Redis02`, `Tomcat02`), because
the full 30-minute window's `trace_span.csv` volume alone (~20K rows per
case at native ms cadence) would make the checked-in fixture roughly
200x larger for no additional structural coverage. The full,
un-truncated 30-minute window for these same 3 cases was independently
downloaded and verified (case 0: 1693 metrics / 59,476 logs / 589,067
traces over the real 2021-03-04 date folder) before truncating — see
`tests/test_openrca_adapter.py` module docstring for the exact
narrowing rationale, and the exact extraction commands are reproducible via:

```bash
python data/scripts/download_openrca.py --dates 2021_03_04
# then filter metric_container.csv / metric_app.csv / log_service.csv /
# trace_span.csv rows to the ±15s-to-±60s windows around record.csv
# rows 0, 1, 3's timestamps (1614841020, 1614852540, 1614856920)
```

## 8. Spot-check: root-cause timestamp reproduction for 3 published cases

Run for real (not asserted from memory) against the full, un-truncated
2021-03-04 telemetry download, before any fixture-trimming:

| record.csv row | component | reason | ground truth timestamp (Shanghai) | adapter `GroundTruth.inject_time` | evidence window reproduces query.csv instruction? |
|---|---|---|---|---|---|
| 0 | Mysql02 | high memory usage | 2021-03-04 14:57:00 | 1614841020 (matches) | yes — "14:30 to 15:00" |
| 1 | Redis02 | high memory usage | 2021-03-04 18:09:00 | 1614852540 (matches) | yes — "18:00 and 18:30" |
| 3 | Tomcat02 | network latency | 2021-03-04 19:22:00 | 1614856920 (matches) | yes — "19:00 to 19:30" |

Additionally, for case 0, the real telemetry itself was checked (not
just the metadata plumbing): `Mysql02:OSLinux-OSLinux_MEMORY_MEMORY_
MEMUsedMemPerc` is pegged at 98% used memory throughout the entire
14:30-15:00 window — physical evidence consistent with the "high memory
usage" ground truth, not just a label with no supporting signal.

## 9. Selective downloader (`data/scripts/download_openrca.py`)

Unlike `download_rcaeval.py` (single checksummed zip per dataset from
Zenodo), OpenRCA's telemetry has no single-archive-per-dataset structure
and no published checksum manifest on the Hugging Face mirror. The
downloader instead:
  - downloads `record.csv`/`query.csv` first and computes which
    `{YYYY_MM_DD}` telemetry folders are actually referenced (in
    Asia/Shanghai, per section 2) — `--list-dates` prints these without
    downloading telemetry;
  - defaults to downloading only those referenced dates, not the full
    ~26GB `Bank/telemetry/` tree (Bank's `record.csv` references only 9
    of the 10 date folders actually present — `2021_03_05` has telemetry
    but no recorded failure, and is never fetched by default);
  - verifies each downloaded file's byte count against the server's own
    `Content-Length` HEAD response (catches truncated downloads; does
    NOT catch server-side corruption, since no independent checksum
    exists to compare against — documented as a real limitation in the
    script's own docstring).

Verified end-to-end: `--list-dates` against the real mirror returned
exactly `['2021_03_04', '2021_03_06', '2021_03_07', '2021_03_09',
'2021_03_10', '2021_03_12', '2021_03_23', '2021_03_24', '2021_03_25']`
(9 dates), and `--dates 2021_03_06` downloaded and size-verified all 4
telemetry files for that one date (log_service.csv 328,804,568 bytes;
metric_app.csv 639,422 bytes; metric_container.csv 84,110,809 bytes;
trace_span.csv 2,632,745,307 bytes), after which `OpenRCABankAdapter`
was pointed at that fresh download (independent of the fixture-building
download above) and successfully loaded case 2 (Tomcat01, high memory
usage, 2021-03-06 06:20:00) with 1721 metrics / 3782 logs / 51227 traces.
