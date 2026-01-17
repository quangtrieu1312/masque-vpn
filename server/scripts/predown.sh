#!/usr/bin/env bash
SCRIPT_DIR=$(realpath $(dirname $0))
for script in "$SCRIPT_DIR"/predown_*; do
    chmod +x "$script"
    bash -c "$script"
done
