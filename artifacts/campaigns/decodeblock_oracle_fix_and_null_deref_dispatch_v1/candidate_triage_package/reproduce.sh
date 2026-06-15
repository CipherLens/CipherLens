#!/usr/bin/env bash
set -euo pipefail
cc min_repro.c -lssl -lcrypto
