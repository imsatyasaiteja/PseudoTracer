# PseudoTracer

PseudoTracer compares correlation utility and privacy risk across RAW, MASKED and
HMAC versions of the same IAM event stream. It generates sign-ins, injects four
attack scenarios, normalizes events to OCSF Authentication records, and scores
correlation and privacy attacks against separate ground truth.

## Setup

Requires Python 3.10+ and Node.js with npm. From the repository root:

```powershell
python -m pip install -r requirements.txt
npm --prefix ui ci
```

The optional RBA input belongs at `data/source/rba-dataset.csv`.
If it is missing or unusable, the generator uses synthetic data and records that
choice in `data_source.json`.

## Dashboard

Start the API from the repository root:

```powershell
python ui/server.py
```

In a second terminal:

```powershell
cd ui
npm run dev -- --port 5173 --strictPort
```

Open http://127.0.0.1:5173. Vite forwards API requests to port 8765; keep both
terminals running. Restart the API after Python changes, when no experiment is
running. The server is intended for local use. `npm run preview` alone does not
connect the API. If PowerShell blocks `npm.ps1`, use `npm.cmd` instead.

The Guide tab covers filters, measurements and the privacy policy. Analyze compares
saved results and replays detector thresholds against the selected experiment.

## Command line

```powershell
python src/experiment_cli.py interactive
python src/experiment_cli.py run --seed 42 --events 3000 --users 20 --devices 30 --attacks all
python src/experiment_cli.py list
```

Use `--attacks none` for a control, or a comma-separated selection of
`password_spray`, `mfa_fatigue`, `impossible_travel`, and `credential_compromise`.
`--arms` selects `raw,masked,hmac`. Devices must be at least the user count.

Use `--config-dir` to run with edited policy, rule or attack YAML files. Each run
saves a configuration snapshot. Use `--key` to reuse a private key when repeating
an HMAC release; otherwise each run gets a new key.

For a multi-seed study:

```powershell
python src/evaluate.py --seeds 7,42,101 --events 3000 --experiments none,all
```

Studies save measurements, means, sample standard deviations, paired differences
from RAW, and timings under `data/studies/`. Undefined observations are excluded
from averages; check the measured count `n`.

## Files and results

| Location | Contents |
| --- | --- |
| `src/` | Event generation, transforms, correlation, scoring and CLI runners |
| `configs/` | Privacy policies, detector rules and attack settings |
| `ui/src/pages/` | One JSX file per tab |
| `ui/src/shared.jsx` | Shared UI components and helpers |
| `ui/src/style.css` | All dashboard styles |
| `ui/*.py` | Local API, event queries, alert views and Python charts |
| `tests/`, `ui/tests/` | Backend and dashboard checks |
| `assets/` | Logos and architecture diagrams |
| `docs/validation/` | Archived evaluation CSVs |
| `data/runs/<run-id>/` | Isolated experiment inputs, releases, labels and results |
| `data/keys/` | Private HMAC keys |

Each run includes `config.json`, `configs/`, `data_source.json`, `status.json`,
and `results/utility.csv`, `privacy.csv`, `cost.csv`, and
`transformation_cost.csv`. Existing runs are not overwritten.
`python src/experiment_cli.py clean` removes run outputs and generated keys after
confirmation; study summaries remain.

## Interpreting results

HMAC retains stable relationships but does not guarantee anonymity. Retained
behavior and stable tokens can still identify or link users. The source is a
bounded RBA sample enriched with synthetic behavior; privacy attacks use a
same-dataset RAW reference. These results do not establish production detection
accuracy or privacy guarantees. Keep keys, RAW releases and ground truth private.

See [experiment definitions](docs/experiment_contract.md) for metric denominators
and assumptions, and [evaluation results](docs/evaluation.md) for the archived
study. The [architecture diagram](assets/architecture.png) provides an overview.

## Checks

```powershell
python -m unittest discover -s tests
python -m unittest discover -s ui/tests
node --test ui/tests/pages.test.mjs ui/tests/shared.test.mjs
npm --prefix ui run build
```
