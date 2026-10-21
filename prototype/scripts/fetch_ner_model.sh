#!/usr/bin/env bash
# Fetch only the files veil's optional NER layer needs (~50 MB) into prototype/models/.
# (huggingface_hub would download every variant in the repo, ~500 MB.)
set -euo pipefail
M="$(cd "$(dirname "$0")/.." && pwd)/models/gliner-pii-edge-v1.0"; mkdir -p "$M/onnx"
B=https://huggingface.co/knowledgator/gliner-pii-edge-v1.0/resolve/main   # Apache-2.0
for f in gliner_config.json tokenizer.json tokenizer_config.json special_tokens_map.json onnx/model_quint8.onnx; do
  curl -fsSL -o "$M/$f" "$B/$f"
done
echo "model ready in $M"
