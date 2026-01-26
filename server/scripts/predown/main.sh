#!/usr/bin/env bash
SCRIPT_DIR=$(realpath $(dirname $0))
ls "$SCRIPT_DIR" | grep -E '^[0-9]+_.*' | sort | while read script; do
    chmod +x "$script"
    bash -c "$script"
done
