from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_DIR = ROOT / "results"
MPL_DIR = RESULTS_DIR / ".mpl-cache"
os.environ.setdefault("MPLCONFIGDIR", str(MPL_DIR))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def latest_checkpoint(output_dir: Path) -> Path | None:
    checkpoints = sorted(
        (p for p in output_dir.glob("checkpoint-*") if p.is_dir()),
        key=lambda p: int(p.name.rsplit("-", 1)[-1]),
    )
    return checkpoints[-1] if checkpoints else None


def load_trainer_state(output_dir: Path) -> dict:
    candidates = [output_dir / "trainer_state.json"]
    ckpt = latest_checkpoint(output_dir)
    if ckpt is not None:
        candidates.append(ckpt / "trainer_state.json")
    for path in candidates:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        f"Could not find trainer_state.json under {output_dir}. "
        "Pass --output-dir pointing at the directory passed to GRPOTrainer."
    )


def plot_curve(steps, values, title, ylabel, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(steps, values, marker="o", color="#23765a", linewidth=1.5)
    ax.set_xlabel("Training step")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def directory_size_mb(path: Path) -> float:
    total = 0
    for sub in path.rglob("*"):
        if sub.is_file():
            total += sub.stat().st_size
    return round(total / (1024 * 1024), 2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot TRL training curves and dump run metadata.")
    parser.add_argument("--output-dir", required=True, help="Path passed to GRPOTrainer (contains trainer_state.json or checkpoint-*/).")
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    results_dir = Path(args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    MPL_DIR.mkdir(exist_ok=True)

    state = load_trainer_state(output_dir)
    log_history = state.get("log_history", [])

    reward_steps, reward_vals = [], []
    loss_steps, loss_vals = [], []
    for entry in log_history:
        step = entry.get("step")
        if step is None:
            continue
        if "reward" in entry:
            reward_steps.append(step)
            reward_vals.append(float(entry["reward"]))
        if "loss" in entry:
            loss_steps.append(step)
            loss_vals.append(float(entry["loss"]))

    if reward_steps:
        plot_curve(reward_steps, reward_vals, "GRPO Training Reward", "Mean reward", results_dir / "training_reward_curve.png")
    if loss_steps:
        plot_curve(loss_steps, loss_vals, "GRPO Training Loss", "Loss", results_dir / "training_loss_curve.png")

    (results_dir / "training_metrics.json").write_text(
        json.dumps({"log_history": log_history}, indent=2),
        encoding="utf-8",
    )

    ckpt = latest_checkpoint(output_dir)
    try:
        import torch
        device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")
        device_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    except Exception:
        device = "unknown"
        device_name = None

    metadata = {
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime()),
        "output_dir": str(output_dir),
        "final_checkpoint": str(ckpt) if ckpt else None,
        "final_checkpoint_size_mb": directory_size_mb(ckpt) if ckpt else None,
        "device": device,
        "device_name": device_name,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "trainer_state": {
            "global_step": state.get("global_step"),
            "epoch": state.get("epoch"),
            "max_steps": state.get("max_steps"),
            "num_train_epochs": state.get("num_train_epochs"),
            "best_metric": state.get("best_metric"),
            "best_model_checkpoint": state.get("best_model_checkpoint"),
        },
        "final_reward": reward_vals[-1] if reward_vals else None,
        "final_loss": loss_vals[-1] if loss_vals else None,
        "reward_points": len(reward_vals),
        "loss_points": len(loss_vals),
    }
    (results_dir / "run_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
