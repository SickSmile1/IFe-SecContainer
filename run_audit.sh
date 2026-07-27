#!/bin/bash
set -euo pipefail

show_help() {
    cat <<EOF
Usage: run_audit.sh [OPTIONS] [TARGET_DIR]

Static security audit pipeline. Runs inside the scanner container
on the mounted workspace.

Options:
  --fail-on LEVEL  Exit non-zero for findings >= LEVEL (low, medium, high, critical)
                   Default: no fail (always exits 0 from findings)
  --output-dir DIR Output directory (default: ./security-output)
  -h, --help       Show this help

TARGET_DIR defaults to /workspace (the container mount point).

Examples:
  run_audit.sh                                          # scan /workspace
  run_audit.sh --fail-on high /path/to/project          # scan project, fail on high+
  run_audit.sh --output-dir /tmp/report /workspace/app  # custom output dir
EOF
    exit 0
}

FAIL_ON=""
OUTPUT_DIR="$(pwd)/security-output"
TARGET_DIR="/workspace"

while [[ $# -gt 0 ]]; do
    case $1 in
        --fail-on) FAIL_ON="$2"; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift ;;
        -h|--help) show_help ;;
        *) TARGET_DIR="$1" ;;
    esac
    shift
done

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: target directory '$TARGET_DIR' not found"
    exit 1
fi

cd "$TARGET_DIR"
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  Security Audit - $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  Target: $TARGET_DIR"
echo "  Output: $OUTPUT_DIR"
echo "============================================"

EXIT_CODE=0

# ---- 1. GITLEAKS ----
echo ""
echo "--- [1/6] Gitleaks (secret scanning) ---"
gitleaks detect --source . \
    --report-format json \
    --report-path "$OUTPUT_DIR/gitleaks.json" \
    --no-git \
    2>&1 | tee "$OUTPUT_DIR/gitleaks.log" || true

# ---- 2. HADOLINT ----
echo ""
echo "--- [2/6] Hadolint (Dockerfile linting) ---"
if ls Dockerfile* 2>/dev/null | grep -q .; then
    hadolint --format json Dockerfile* > "$OUTPUT_DIR/hadolint.json" 2>"$OUTPUT_DIR/hadolint-err.log" || true
    if [ ! -s "$OUTPUT_DIR/hadolint.json" ]; then
        echo '[]' > "$OUTPUT_DIR/hadolint.json"
    fi
    echo "  Done"
else
    echo "  No Dockerfiles found, skipping"
    echo '[]' > "$OUTPUT_DIR/hadolint.json"
fi

# ---- 3. SEMGREP ----
echo ""
echo "--- [3/6] Semgrep (SAST) ---"
semgrep scan --config auto \
    --json \
    --output "$OUTPUT_DIR/semgrep.json" \
    . 2>&1 | tee "$OUTPUT_DIR/semgrep.log" || true

# ---- 4. BANDIT ----
echo ""
echo "--- [4/6] Bandit (Python SAST) ---"
bandit -r . \
    -f json \
    -o "$OUTPUT_DIR/bandit.json" \
    2>&1 | tee "$OUTPUT_DIR/bandit.log" || true

# ---- 5. SAFETY ----
echo ""
echo "--- [5/6] Safety (dependency check) ---"
if [ -f requirements.txt ] || [ -f pyproject.toml ]; then
    safety scan --output json > "$OUTPUT_DIR/safety.json" 2>/dev/null || true
    if [ ! -s "$OUTPUT_DIR/safety.json" ]; then
        echo '[]' > "$OUTPUT_DIR/safety.json"
    fi
    echo "  Done"
else
    echo "  No requirements.txt or pyproject.toml found, skipping"
    echo '[]' > "$OUTPUT_DIR/safety.json"
fi

# ---- 6. TRIVY ----
echo ""
echo "--- [6/6] Trivy (filesystem scan) ---"
trivy fs --format json \
    --output "$OUTPUT_DIR/trivy.json" \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --ignore-unfixed \
    . 2>&1 | tee "$OUTPUT_DIR/trivy.log" || true

# ---- AGGREGATE ----
echo ""
echo "============================================"
echo "  Generating unified report..."
echo "============================================"

if [ -n "$FAIL_ON" ]; then
    python3 /opt/aggregate_report.py "$OUTPUT_DIR" --fail-on "$FAIL_ON"
else
    python3 /opt/aggregate_report.py "$OUTPUT_DIR"
fi
AGG_EXIT=$?

if [ $AGG_EXIT -ne 0 ]; then
    EXIT_CODE=$AGG_EXIT
fi

exit $EXIT_CODE
