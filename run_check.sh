#!/usr/bin/env bash
#
# run_check.sh - Wrapper für die tägliche System- und Sicherheitsprüfung
# Geeignet für interaktive Nutzung und cron-Ausführung
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LC_ALL="C.UTF-8"
export LANG="C.UTF-8"

mkdir -p logs

LOG_FILE="${SCRIPT_DIR}/logs/cron_execution.log"

echo "=== [$(date '+%Y-%m-%d %H:%M:%S')] Start täglicher System-Check ===" >> "${LOG_FILE}"

# Ausführung loggen und gleichzeitig auf stdout ausgeben (damit OMV Mail funktioniert)
/usr/bin/python3 "${SCRIPT_DIR}/system_check.py" "$@" 2>&1 | tee -a "${LOG_FILE}"
EXIT_CODE="${PIPESTATUS[0]}"

echo "=== [$(date '+%Y-%m-%d %H:%M:%S')] Check beendet (Exit-Code ${EXIT_CODE}) ===" >> "${LOG_FILE}"
exit "${EXIT_CODE}"
