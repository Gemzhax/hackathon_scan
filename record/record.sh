#!/usr/bin/env bash
# record/record.sh — Demo recording for WSL/Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$SCRIPT_DIR/redcheck.log"

cd "$ROOT_DIR"

timestamp="$(date -Iseconds)"
echo "[RedCheck RECORD] $timestamp" | tee "$LOG_FILE"

if command -v asciinema &>/dev/null; then
    echo "[record] asciinema found"
    asciinema rec "$SCRIPT_DIR/redcheck.cast" \
        --command "bash -c 'python -m redcheck.runner --mode vuln && python -m redcheck.runner --mode hardened && python -m redcheck.report --vuln out/redcheck_vuln.json --hardened out/redcheck_hardened.json --out out/compare.html'"
else
    echo "[record] asciinema not found — logging to $LOG_FILE"
    {
        echo "=== redcheck-vuln ==="
        python -m redcheck.runner --mode vuln
        echo "=== redcheck-hardened ==="
        python -m redcheck.runner --mode hardened
        echo "=== compare ==="
        python -m redcheck.report --vuln out/redcheck_vuln.json --hardened out/redcheck_hardened.json --out out/compare.html
    } 2>&1 | tee -a "$LOG_FILE"
fi

echo "[record] Done. Log: $LOG_FILE"
