#!/usr/bin/env bash
SCRIPT_DIR=$(realpath $(dirname $0))
ls "$SCRIPT_DIR" | grep -E '^[0-9]+_.*' | sort | while read script; do
    chmod +x "$SCRIPT_DIR/$script"
    bash -c "$SCRIPT_DIR/$script"
done
