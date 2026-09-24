#!/usr/bin/env bash

set -e

# Always run from the repo root, regardless of where this script is invoked from.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Runs the benign_benchmark task against the CVSS-filtered subset
# (data/benign_subset/<cwe>_benign_top10cvss.jsonl — top 10 highest-CVSS
# benign fixes per CWE, 100 samples total) across the models used in the
# paper.

cwes=("cwe22" "cwe78" "cwe79" "cwe89" "cwe94" "cwe125" "cwe352" "cwe416" "cwe787" "cwe862")

tool_modes=("sandbox")
prompt_variants=("security")

models=(
  "bedrock/global.anthropic.claude-opus-4-7"
  "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
  "openai/azure/gpt-5.5"
  "openai/azure/gpt-5.4-nano"
  "openai/azure/grok-code-fast-1"
  "openai/azure/DeepSeek-V4-Flash"
  "bedrock/zai.glm-5"
  "bedrock/moonshotai.kimi-k2.5"
)

# Base command parts
TASK="benchmark/task.py@benign_benchmark"
# inspect eval chdirs into the task file's directory (benchmark/) before
# loading it, so -T jsonl_path must be an absolute path, not one relative
# to the repo root.
DATA_DIR="$(pwd)/data/benign_subset"
LOG_BASE="logs/benign_top10cvss"

# Loop over combinations
for prompt_variant in "${prompt_variants[@]}"; do
  for cwe in "${cwes[@]}"; do
    for tool_mode in "${tool_modes[@]}"; do
      for model in "${models[@]}"; do

        jsonl_path="${DATA_DIR}/${cwe}_benign_top10cvss.jsonl"
        log_dir="${LOG_BASE}/${model//\//_}_${tool_mode}_${prompt_variant}_${cwe}"

        # Skip if this config has already been run
        if [ -d "$log_dir" ]; then
          echo "Skipping: model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe (already exists)"
          continue
        fi

        echo "Running: model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe"

        uv run inspect eval "$TASK" \
          --model "$model" \
          -T hf_dataset="" \
          -T jsonl_path="$jsonl_path" \
          -T tool_mode="$tool_mode" \
          -T prompt_variant="$prompt_variant" \
          --log-dir "$log_dir"

      done
    done
  done
done
