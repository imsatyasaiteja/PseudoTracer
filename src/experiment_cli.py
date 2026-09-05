"""Run repeatable PseudoTracer experiments from one small command-line interface."""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "data" / "runs"
KEYS_DIR = ROOT / "data" / "keys"
ATTACKS = ("password_spray", "mfa_fatigue", "impossible_travel", "credential_compromise")
ARMS = ("raw", "masked", "hmac")
LEGACY_OUTPUTS = [
    ROOT / "data" / "generated",
    ROOT / "data" / "ground_truth",
    ROOT / "data" / "normalized",
    ROOT / "data" / "releases",
    ROOT / "data" / "correlated",
    ROOT / "data" / "privacy_attacks",
    ROOT / "results",
]


def safe_run_id(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value):
        raise SystemExit("Run IDs may contain letters, numbers, underscores, and hyphens only.")
    return value


def selected_names(value, allowed, label):
    names = [name.strip() for name in value.split(",") if name.strip()]
    unknown = set(names) - set(allowed)
    if not names or unknown:
        options = ", ".join(allowed)
        raise SystemExit(f"Choose one or more {label}s from: {options}")
    return list(dict.fromkeys(names))


def new_run_id(seed, events):
    base = f"seed{seed}_events{events}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    candidate = base
    number = 2
    while (RUNS_DIR / candidate).exists():
        candidate = f"{base}_{number}"
        number += 1
    return candidate


def run_command(script, *arguments):
    command = [sys.executable, str(ROOT / "src" / script), *map(str, arguments)]
    print("\n> " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def run_experiment(args):
    if args.events < 1 or args.users < 1 or args.devices < args.users:
        raise SystemExit("Use at least 1 event and user, with devices greater than or equal to users.")
    selected_arms = selected_names(args.arms, ARMS, "privacy arm")
    selected_attacks = list(ATTACKS) if args.attacks == "all" else []
    if args.attacks not in {"all", "none"}:
        selected_attacks = selected_names(args.attacks, ATTACKS, "attack")
    arms = ",".join(selected_arms)
    attacks = args.attacks if args.attacks in {"all", "none"} else ",".join(selected_attacks)

    run_id = safe_run_id(args.run_id) if args.run_id else new_run_id(args.seed, args.events)
    run_dir = RUNS_DIR / run_id
    if run_dir.exists():
        raise SystemExit(f"Run '{run_id}' already exists. Choose another --run-id.")

    paths = {
        "normal_events": run_dir / "generated" / "normal_events.jsonl",
        "normal_truth": run_dir / "ground_truth" / "normal_truth.jsonl",
        "events": run_dir / "generated" / "events.jsonl",
        "truth": run_dir / "ground_truth" / "truth.jsonl",
        "normalized": run_dir / "normalized" / "ocsf_authentication.jsonl",
        "releases": run_dir / "releases",
        "correlated": run_dir / "correlated",
        "privacy_attacks": run_dir / "privacy_attacks",
        "utility": run_dir / "results" / "utility.csv",
        "privacy": run_dir / "results" / "privacy.csv",
    }
    key_path = args.key or KEYS_DIR / f"{run_id}.key"
    run_dir.mkdir(parents=True)

    transform_arms = arms if "raw" in selected_arms else f"raw,{arms}"
    manifest = {
        "run_id": run_id,
        "created_at": datetime.now().astimezone().isoformat(),
        "seed": args.seed,
        "events": args.events,
        "users": args.users,
        "devices": args.devices,
        "attacks": attacks,
        "arms": arms,
        "generated_arms": transform_arms,
        "rba_csv": str(args.rba_csv),
        "key_path": str(key_path),
    }
    (run_dir / "config.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    run_command(
        "data_builder.py",
        "--seed", args.seed,
        "--events", args.events,
        "--users", args.users,
        "--devices", args.devices,
        "--rba-csv", args.rba_csv,
        "--events-out", paths["normal_events"],
        "--truth-out", paths["normal_truth"],
    )
    if attacks == "none":
        shutil.copyfile(paths["normal_events"], paths["events"])
        shutil.copyfile(paths["normal_truth"], paths["truth"])
    else:
        run_command(
            "attack_injector.py",
            "--seed", args.seed,
            "--attacks", attacks,
            "--events-in", paths["normal_events"],
            "--events-out", paths["events"],
            "--truth-out", paths["truth"],
        )

    run_command("ocsf_normalizer.py", "--events-in", paths["events"], "--events-out", paths["normalized"])
    run_command(
        "transforms.py",
        "--events-in", paths["normalized"],
        "--output-dir", paths["releases"],
        "--key", key_path,
        # Privacy attacks use RAW as their private reference set. Generate it even
        # when it was not selected as an experiment result arm.
        "--arms", transform_arms,
        "--run", run_id,
    )
    run_command(
        "correlation.py",
        "--arms", arms,
        "--run", run_id,
        "--releases-dir", paths["releases"],
        "--incidents-dir", paths["correlated"],
    )
    run_command(
        "utility_metrics.py",
        "--arms", arms,
        "--run", run_id,
        "--truth", paths["truth"],
        "--incidents-dir", paths["correlated"],
        "--out", paths["utility"],
    )
    run_command(
        "privacy_attacks.py",
        "--arms", arms,
        "--run", run_id,
        "--releases-dir", paths["releases"],
        "--attacks-dir", paths["privacy_attacks"],
    )
    run_command(
        "privacy_metrics.py",
        "--arms", arms,
        "--run", run_id,
        "--releases-dir", paths["releases"],
        "--attacks-dir", paths["privacy_attacks"],
        "--truth", paths["truth"],
        "--out", paths["privacy"],
    )
    print_summary(run_dir, paths)


def print_summary(run_dir, paths):
    print(f"\nExperiment complete: {run_dir}")
    for title, path in [("Utility", paths["utility"]), ("Privacy", paths["privacy"])]:
        with path.open(encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        print(f"{title} results: {path}")
        for row in rows:
            if row.get("scenario", "all") == "all":
                print("  " + ", ".join(f"{key}={value}" for key, value in row.items() if key != "scenario"))


def ask(prompt, default, convert=str):
    value = input(f"{prompt} [{default}]: ").strip()
    return convert(value) if value else default


def interactive_run(_args):
    values = argparse.Namespace(
        seed=ask("Seed", 42, int),
        events=ask("Number of normal events", 3000, int),
        users=ask("Users", 20, int),
        devices=ask("Devices", 30, int),
        attacks=ask("Attacks (all, none, or comma-separated names)", "all"),
        arms=ask("Privacy arms (raw,masked,hmac)", "raw,masked,hmac"),
        run_id=ask("Optional run ID", "") or None,
        rba_csv=ROOT / "data" / "source" / "rba-dataset.csv",
        key=None,
    )
    run_experiment(values)


def remove_contents(path):
    if not path.exists():
        return 0
    removed = 0
    for item in path.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
        removed += 1
    return removed


def clean_runs(args):
    run_keys = []
    if RUNS_DIR.exists():
        run_keys = [KEYS_DIR / f"{directory.name}.key" for directory in RUNS_DIR.iterdir() if directory.is_dir()]

    targets = [RUNS_DIR]
    if args.legacy:
        targets.extend(LEGACY_OUTPUTS)
    print("This removes generated experiment outputs only:")
    for target in targets:
        print(f"  {target}")
    if run_keys:
        print("  automatically generated per-run HMAC keys")
    if not args.yes and input("Type DELETE to continue: ").strip() != "DELETE":
        print("Nothing removed.")
        return
    removed = sum(remove_contents(target) for target in targets)
    for key in run_keys:
        if key.exists():
            key.unlink()
            removed += 1
    print(f"Removed {removed} generated files or run directories. data/source was not changed.")


def list_runs(_args):
    if not RUNS_DIR.exists() or not any(RUNS_DIR.iterdir()):
        print("No isolated runs found.")
        return
    for directory in sorted(path for path in RUNS_DIR.iterdir() if path.is_dir()):
        print(directory.name)


def add_run_options(parser):
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--events", type=int, default=3000)
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--devices", type=int, default=30)
    parser.add_argument("--attacks", default="all", help="all, none, or comma-separated attack names")
    parser.add_argument("--arms", default="raw,masked,hmac")
    parser.add_argument("--run-id")
    parser.add_argument("--rba-csv", type=Path, default=ROOT / "data" / "source" / "rba-dataset.csv")
    parser.add_argument("--key", type=Path, help="Existing key to reuse for byte-for-byte HMAC repeatability.")


def main():
    parser = argparse.ArgumentParser(description="Guided runner for PseudoTracer experiments through Phase 5B.")
    commands = parser.add_subparsers(dest="command")
    run_parser = commands.add_parser("run", help="Run one isolated experiment.")
    add_run_options(run_parser)
    interactive_parser = commands.add_parser("interactive", help="Prompt for experiment settings.")
    interactive_parser.set_defaults(func=interactive_run)
    clean_parser = commands.add_parser("clean", help="Remove prior run outputs without touching source data.")
    clean_parser.add_argument("--yes", action="store_true", help="Do not ask for DELETE confirmation.")
    clean_parser.add_argument("--legacy", action="store_true", help="Also clear old shared outputs outside data/runs.")
    clean_parser.set_defaults(func=clean_runs)
    list_parser = commands.add_parser("list", help="List isolated experiment runs.")
    list_parser.set_defaults(func=list_runs)
    args = parser.parse_args()

    if args.command == "run":
        run_experiment(args)
    elif hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
