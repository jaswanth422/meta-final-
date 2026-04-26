---
title: Context Breach Demo
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: gradio
sdk_version: 5.20.0
app_file: app.py
pinned: false
hardware: cpu-basic
license: apache-2.0
short_description: Multi-agent prompt-injection containment demo
---

# Context Breach — Live Demo

Pick a scenario, pick a policy (trained / naive / guarded), and watch the Commander agent run a full enterprise workflow under prompt injection. The trained policy uses a Qwen3-0.6B checkpoint fine-tuned with TRL GRPO inside the Context Breach OpenEnv environment.

Each rollout returns:

- The full action trace
- Per-step reward breakdown
- Final reward
- Contamination graph depth
- Whether the agent leaked restricted fields
- Whether the underlying business task was completed

Trained-model inference runs on a ZeroGPU A10G slice. Baselines run on CPU.
