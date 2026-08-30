from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any

os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


def torch_report() -> dict[str, Any]:
    import torch

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    return {
        "torch_version": torch.__version__,
        "mps_built": bool(torch.backends.mps.is_built()),
        "mps_available": bool(torch.backends.mps.is_available()),
        "selected_device": device,
    }


def tensor_smoke(size: int) -> dict[str, Any]:
    import torch

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    start = time.perf_counter()
    a = torch.randn(size, size, device=device)
    b = torch.randn(size, size, device=device)
    c = (a @ b).mean()
    if device == "mps":
        torch.mps.synchronize()
    elapsed_s = time.perf_counter() - start
    return {
        "device": device,
        "matrix_size": size,
        "mean": float(c.detach().cpu()),
        "elapsed_s": round(elapsed_s, 4),
    }


def model_smoke(model_name: str) -> dict[str, Any]:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    dtype = torch.float32 if device == "mps" else None
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype=dtype)
    model.to(device)
    inputs = tokenizer("Context Breach MPS smoke test:", return_tensors="pt").to(device)
    with torch.no_grad():
        outputs = model.generate(**inputs, max_new_tokens=12)
    return {
        "device": device,
        "model": model_name,
        "text": tokenizer.decode(outputs[0], skip_special_tokens=True),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether Mac MPS is usable for testing.")
    parser.add_argument("--size", type=int, default=512)
    parser.add_argument(
        "--model",
        default=None,
        help="Optional Hugging Face model name for a tiny generation smoke test.",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "torch": torch_report(),
        "tensor_smoke": tensor_smoke(args.size),
    }
    if args.model:
        result["model_smoke"] = model_smoke(args.model)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
