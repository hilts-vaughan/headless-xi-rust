#!/usr/bin/env sh
set -eu

cargo run --bin headless-xi -- sea-all --server 66.85.159.114:54002 "$@"
