# PseudoTracer

PseudoTracer is a Privacy-Preserving IAM telemetry research prototype. It builds
Entra-like sign-in events from a sample of [RBA dataset](https://www.kaggle.com/datasets/dasgroup/rba-dataset/data), injects configured attacks,
normalizes them to OCSF, applies privacy transformations, and evaluates utility
and privacy through Phase 5B.

## Quick Start

Run a default experiment:

```powershell
python src\experiment_cli.py interactive
```

Or run a custom experiment directly:

```powershell
python src\experiment_cli.py run --seed 42 --events 3000 --attacks all
```

Each command creates a new isolated directory under `data/runs/`. Existing runs
are never overwritten.

## Common Experiments

Use a different seed or normal-event count:

```powershell
python src\experiment_cli.py run --seed 7 --events 5000
```

Choose attack scenarios. Available attack scenarios are `password_spray`, `mfa_fatigue`,
`impossible_travel`, and `credential_compromise`:

```powershell
python src\experiment_cli.py run --seed 7 --events 2500 --attacks password_spray,mfa_fatigue
```

Run normal traffic only:

```powershell
python src\experiment_cli.py run --seed 7 --events 2500 --attacks none
```

Change the IAM population or name a run yourself. Devices must be at least the
number of users:

```powershell
python src\experiment_cli.py run --seed 11 --events 4000 --users 25 --devices 40 --run-id study_a
```

Choose result arms. `raw`, `masked`, and `hmac` are available:

```powershell
python src\experiment_cli.py run --seed 11 --arms masked,hmac
```

To make an HMAC experiment byte-for-byte repeatable across separate runs, reuse
the same private key:

```powershell
python src\experiment_cli.py run --seed 42 --events 3000 --key data\keys\my_experiment.key
```

## Outputs

A run such as `data/runs/seed42_events3000_20260905_120000/` contains:

- `config.json`: complete experiment settings and paths
- `generated/`: normal and attack-injected Entra-like sign-in events
- `ground_truth/`: sidecar labels used only for evaluation
- `normalized/`: OCSF Authentication events
- `releases/`: selected RAW, MASKED, and HMAC telemetry arms
- `correlated/`: incident hypotheses for utility evaluation
- `privacy_attacks/`: attacker guesses and snapshot-link results
- `results/utility.csv`: correlation utility metrics
- `results/privacy.csv`: privacy-risk metrics

Per-run HMAC keys are placed in `data/keys/` and should remain private. They are
not version controlled.

## Manage Experiment Data

List isolated runs:

```powershell
python src\experiment_cli.py list
```

Clear isolated run files and their generated keys. The command asks for confirmation:

```powershell
python src\experiment_cli.py clean
```

For automated cleanup:

```powershell
python src\experiment_cli.py clean --yes
```

## Running Individual Scripts

These command runs
the full pipeline with the default seed and attack set:

```powershell
python src\data_builder.py
python src\attack_injector.py --attacks all
python src\ocsf_normalizer.py
python src\transforms.py
python src\correlation.py
python src\utility_metrics.py
python src\privacy_attacks.py
python src\privacy_metrics.py
```

## Tests

```powershell
python -m unittest discover -s tests -v
```
