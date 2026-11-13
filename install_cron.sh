#!/usr/bin/env bash
#
# install_cron.sh - Cronjob-Verwaltung für die tägliche Systemprüfung
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER_SCRIPT="${SCRIPT_DIR}/run_check.sh"

CRON_TAG_START="# BEGIN: DAILY SYSTEM & SECURITY CHECK"
CRON_TAG_END="# END: DAILY SYSTEM & SECURITY CHECK"
CRON_SCHEDULE="30 6 * * *"
CRON_LINE="${CRON_SCHEDULE} ${WRAPPER_SCRIPT} >/dev/null 2>&1"

usage() {
    cat <<EOF
Verwendung: $0 [OPTION]

Optionen:
  --install     Richtet den täglichen Cronjob (06:30 Uhr) in der Crontab ein
  --status      Zeigt den aktuellen Status des Cronjobs an
  --remove      Entfernt den Cronjob aus der Crontab
  --run-now     Führt die Systemprüfung sofort aus
  --help        Zeigt diese Hilfe an
EOF
}

check_status() {
    echo "=== Aktueller Cronjob-Status für Benutzer '$(whoami)' ==="
    if crontab -l 2>/dev/null | grep -q "${CRON_TAG_START}"; then
        echo "🟢 Cronjob ist AKTIV:"
        crontab -l | sed -n "/${CRON_TAG_START}/,/${CRON_TAG_END}/p"
    else
        echo "⚪ Kein Cronjob für die tägliche Systemprüfung eingerichtet."
    fi
    echo ""
}

install_cron() {
    echo "Richte täglichen Cronjob ein (Zeit: 06:30 Uhr)..."

    # Bestehende Crontab ohne alten Block lesen
    CURRENT_CRON=$(crontab -l 2>/dev/null || true)
    FILTERED_CRON=$(echo "${CURRENT_CRON}" | sed "/${CRON_TAG_START}/,/${CRON_TAG_END}/d")

    # Neuen Block anhängen
    NEW_CRON=$(cat <<EOF
${FILTERED_CRON}
${CRON_TAG_START}
${CRON_LINE}
${CRON_TAG_END}
EOF
)

    # Bereinigte Leerzeilen am Anfang/Ende vermeiden
    echo "${NEW_CRON}" | grep -v '^[[:space:]]*$' | crontab -

    echo "✅ Cronjob erfolgreich installiert!"
    check_status
}

remove_cron() {
    echo "Entferne Cronjob..."
    CURRENT_CRON=$(crontab -l 2>/dev/null || true)
    if echo "${CURRENT_CRON}" | grep -q "${CRON_TAG_START}"; then
        FILTERED_CRON=$(echo "${CURRENT_CRON}" | sed "/${CRON_TAG_START}/,/${CRON_TAG_END}/d")
        if [ -z "$(echo "${FILTERED_CRON}" | tr -d '[:space:]')" ]; then
            crontab -r 2>/dev/null || true
        else
            echo "${FILTERED_CRON}" | crontab -
        fi
        echo "✅ Cronjob erfolgreich entfernt."
    else
        echo "⚪ Kein Eintrag vorhanden."
    fi
}

case "${1:---install}" in
    --install)
        install_cron
        ;;
    --status)
        check_status
        ;;
    --remove)
        remove_cron
        ;;
    --run-now)
        echo "Führe Systemprüfung jetzt aus..."
        "${WRAPPER_SCRIPT}"
        ;;
    --help|-h)
        usage
        ;;
    *)
        echo "Unbekannte Option: $1"
        usage
        exit 1
        ;;
esac
