#!/bin/bash
# Runs the full Context Breach training pipeline inside an HF Jobs container.
# Expects:
#   - /data mounted read-only with the code (via -v hf://datasets/.../context-breach-code:/data)
#   - HF_TOKEN secret set (via --secrets HF_TOKEN)
#
# Modes (controlled by env vars):
#   SMOKE=1        — runs 1 training step with tiny config, skips uploads
#   SKIP_UPLOAD=1  — runs full training but skips HF Hub uploads at the end
#   (default)      — full training + eval + upload

set -e
set -o pipefail

echo "=== [1/8] Stage code into writable dir ==="
cp -r /data /tmp/work
cd /tmp/work
ls

echo "=== [2/8] Install system + Python deps ==="
apt-get update -qq && apt-get install -y -qq git
# Upgrade torch first — TRL needs FSDPModule which requires torch >= 2.4
pip install -q -U "torch>=2.4"
pip install -q -e .
pip install -q -r requirements-training.txt
pip install -q weave wandb mergekit llm-blender

echo "=== [3/8] Patch llm_blender (transformers 5.x compatibility) ==="
python - <<'PY'
import sys, os
for p in sys.path:
    candidate = os.path.join(p, "llm_blender", "__init__.py")
    if os.path.exists(candidate):
        with open(candidate, "w") as f:
            f.write(
                "def _stub(name):\n"
                "    return type(name, (), {})\n"
                "def __getattr__(name):\n"
                "    return _stub(name)\n"
                "Blender = _stub('Blender')\n"
            )
        print(f"Stubbed {candidate}")
        break
else:
    print("llm_blender not installed — no stub needed.")
PY

echo "=== [4/8] Verify GPU + library versions ==="
python - <<'PY'
import torch, trl, transformers
print("torch       :", torch.__version__)
print("trl         :", trl.__version__)
print("transformers:", transformers.__version__)
print("cuda        :", torch.cuda.is_available())
if torch.cuda.is_available():
    print("device      :", torch.cuda.get_device_name(0))
PY

if [ "${SMOKE:-0}" = "1" ]; then
  MODEL="${MODEL:-Qwen/Qwen3-1.7B}"
  EPISODES="${EPISODES:-4}"
  MAX_STEPS="${MAX_STEPS:-1}"
  NUM_GEN="${NUM_GEN:-2}"
  GRAD_ACCUM="${GRAD_ACCUM:-1}"
  MAX_COMPLETION="${MAX_COMPLETION:-1024}"
  LR="${LR:-2e-6}"
  OUTPUT_DIR="/tmp/smoke"
  SKIP_UPLOAD=1
else
  MODEL="${MODEL:-Qwen/Qwen3-1.7B}"
  EPISODES="${EPISODES:-80}"
  MAX_STEPS="${MAX_STEPS:-80}"
  NUM_GEN="${NUM_GEN:-4}"
  GRAD_ACCUM="${GRAD_ACCUM:-4}"
  MAX_COMPLETION="${MAX_COMPLETION:-2048}"
  LR="${LR:-2e-6}"
  OUTPUT_DIR="/tmp/work/outputs/context-breach-grpo-v2"
fi

mkdir -p /tmp/work/results

echo "=== [5/8] Training ==="
echo "model=$MODEL episodes=$EPISODES max_steps=$MAX_STEPS lr=$LR"
python scripts/train_trl_grpo.py \
  --device cuda \
  --model "$MODEL" \
  --episodes "$EPISODES" \
  --max-steps "$MAX_STEPS" \
  --num-generations "$NUM_GEN" \
  --gradient-accumulation-steps "$GRAD_ACCUM" \
  --max-completion-length "$MAX_COMPLETION" \
  --learning-rate "$LR" \
  --output-dir "$OUTPUT_DIR" 2>&1 | tee /tmp/work/results/training.log

if [ "${SMOKE:-0}" = "1" ]; then
  echo "=== SMOKE TEST PASSED ==="
  exit 0
fi

echo "=== [6/8] Plot training curves + run metadata ==="
python scripts/plot_training_curves.py --output-dir "$OUTPUT_DIR"

echo "=== [7/8] Evaluate trained model + 3-way comparison ==="
CHECKPOINT=$(ls -d "$OUTPUT_DIR"/checkpoint-* 2>/dev/null | sort -V | tail -1)
if [ -z "$CHECKPOINT" ]; then
  echo "ERROR: no checkpoint found under $OUTPUT_DIR"
  exit 1
fi
echo "Checkpoint: $CHECKPOINT"
python scripts/eval_trained_model.py --checkpoint "$CHECKPOINT" --episodes 9
python scripts/generate_after_results.py || echo "generate_after_results.py failed (non-fatal)"

if [ "${SKIP_UPLOAD:-0}" = "1" ]; then
  echo "=== SKIP_UPLOAD set, training+eval done, no upload ==="
  exit 0
fi

echo "=== [8/8] Upload model + results to HF Hub ==="
python - <<PY
from huggingface_hub import HfApi
api = HfApi()
api.create_repo("jaswanth28/context-breach-qwen3-grpo", repo_type="model", private=True, exist_ok=True)
api.upload_folder(
    folder_path="$CHECKPOINT",
    repo_id="jaswanth28/context-breach-qwen3-grpo",
    repo_type="model",
    ignore_patterns=["optimizer.pt", "rng_state.pth", "scheduler.pt"],
)
print("Model uploaded to jaswanth28/context-breach-qwen3-grpo")

api.create_repo("jaswanth28/context-breach-results", repo_type="dataset", private=True, exist_ok=True)
api.upload_folder(
    folder_path="/tmp/work/results",
    repo_id="jaswanth28/context-breach-results",
    repo_type="dataset",
)
print("Results uploaded to jaswanth28/context-breach-results")
PY

echo "=== ALL DONE ==="
