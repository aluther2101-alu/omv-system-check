# 🛡️ Tägliche Systemprüfung auf Aktualität und Sicherheit

Automatisiertes Prüf-, Diagnose- und Monitoring-System für Debian 12 (Bookworm), OpenMediaVault und Docker-Umgebungen.

---

## 📌 Die 8 Prüf-Säulen

Das Skript überwacht das System täglich umfassend und generiert strukturierte Berichte nach folgenden 8 Schwerpunkten:

1. **🩺 Systemgesundheit & Performance:**
   - System-Uptime und Boot-Status.
   - CPU-Last (`loadavg` 1m, 5m, 15m), Kern-Anzahl und Last-pro-Kern-Berechnung.
   - Arbeitsspeicher (RAM) und Swap-Speichernutzung (`/proc/meminfo`).
   - Kernel-Gesundheit und OOM-Killer-Audit (Erkennung getöteter Prozesse in den letzten 24h).
   - Prüfung auf ausstehende System-Neustarts (`/run/reboot-required`).

2. **📦 Updates & Paketaktualität (Debian 12):**
   - Ausstehende Betriebssystem-Updates (`apt list --upgradable`).
   - Gesonderte Identifikation und Warnung vor Debian-Sicherheitsupdates.
   - Historie und Status von `unattended-upgrades`.

3. **⚙️ System-Dienste & Daemons:**
   - Status und SubStates der Kern-Dienste (`ssh`, `docker`, `fail2ban`, `openmediavault-engined`, `postfix`, `cron`).
   - Überwachung von Dienst-Neustarts (`NRestarts`).
   - Tiefenprüfung für Postfix via IPC-Warteschlangenabfrage (`postqueue -p`).
   - Automatische Erkennung abgestürzter Systemd-Dienste (`systemctl --failed`).

4. **🐳 Docker Container & Image-Aktualität:**
   - Laufzeitstatus aller Container (`running`, `exited`, `restarting`).
   - Docker Health-Check-Status (`healthy`, `unhealthy`).
   - Registry-Aktualitätsprüfung für remote getaggte Images (Docker Hub, GHCR).
   - Docker-Storage Aufteilung (Build-Cache, Images, Volumes) mit Schwellenwert-Warnungen.

5. **💾 Dateisystem & Speicher-Integrität:**
   - Speicherplatzbelegung und freier Speicher auf `/`.
   - Inode-Auslastung.
   - Mount-Modus-Überprüfung (Erkennung versehentlicher `read-only` Mounts).
   - Wurzelverzeichnis-Integrität: Warnung bei unerwarteten Ordnern auf `/` (z. B. durch Fehl-Backups oder fehlerhafte SCP-Transfers).
   - Suche nach übergroßen Backup-Duplikaten (`.fsa` Dumps).
   - Dateisystem- und I/O-Fehler im Kernel-Ringpuffer.

6. **🧱 Firewall & Netzwerksicherheit:**
   - Status aktiver Firewall-Daemons (`nftables`, `ufw`).
   - Überprüfung der Default-Eingangsregeln (Default `INPUT` Policy).
   - Audit aller lauschenden Ports (`ss -tuln`), unterteilt nach:
     - Öffentlich exponiert (`0.0.0.0` / `::`)
     - Nur lokal gebunden (`127.0.0.1` / `::1`)
     - VPN-gebunden (WireGuard / OpenVPN)
   - Risikobewertung bei öffentlich exponierten sensitiven Diensten (SSH, Samba, Web-UIs, Datenbanken, KI-APIs).

7. **🛡️ Sicherheitsvorfälle & Authentifizierung:**
   - SSH Brute-Force Analyse der letzten 24 Stunden (Fehlversuche, Top 5 Angreifer-IPs, erfolgreiche Logins).
   - Alarmierung bei direktem SSH-Login des Benutzers `root`.
   - Fail2Ban Status und Anzahl gesperrter IPs der letzten 24 Stunden.
   - Aktive Benutzersitzungen (`who` / `w`).
   - Sudo-Audit: Erkennung und Warnung bei fehlgeschlagenen `sudo`-Authentifizierungen.
   - Kontenprüfung: Audit auf unberechtigte Konten mit UID 0 in `/etc/passwd` und Sudo-Gruppenmitglieder.

8. **⚠️ Fehlermeldungen & Systemprotokolle:**
   - Systemd Journal Fehleranalyse der letzten 24 Stunden (Priorität 0..3: `emerg`, `alert`, `crit`, `err`).
   - Intelligente Filterung von bekanntem kosmetischem Rauschen.
   - Gruppierung und Aggregation der häufigsten Fehlermuster zur schnellen Diagnose.
   - Kernel-Hardware- und Treiber-Fehlermeldungen (`journalctl -k -p 0..3`).

---

## 🚀 Schnellstart

### 1. Manuelle Ausführung
```bash
cd /srv/user/andreas/Cronjob
./run_check.sh
```

Mit Berichtsausgabe auf Konsole (z. B. für Mailversand):
```bash
./run_check.sh --report
```

### 2. Geplanter Lauf in OpenMediaVault (OMV)
In OMV unter **System ➔ Geplante Aufgaben (Scheduled Tasks)**:
- **Aktivieren:** Ein
- **Befehl:** `/srv/user/andreas/Cronjob/run_check.sh --report`
- **Ausführung:** Täglich (Minute: `30`, Stunde: `6`)
- **Benutzer:** `andreas` (oder `root` für vollständige Firewall-Inspektion)
- **E-Mail senden:** Ein
- **Kommentar:** `Tägliche System- & Sicherheitsprüfung`

---

## ⚙️ Konfiguration (`config.json`)

Schwellenwerte und aktive Module können in `config.json` angepasst werden:

```json
{
  "system": {
    "hostname": "server01",
    "schedule": "06:30 täglich",
    "log_retention_days": 30
  },
  "thresholds": {
    "disk_warn_percent": 85,
    "disk_crit_percent": 95,
    "inode_warn_percent": 85,
    "inode_crit_percent": 95,
    "docker_build_cache_warn_gb": 40,
    "memory_warn_percent": 90,
    "swap_warn_percent": 80,
    "load_warn_per_core": 2.5,
    "ssh_failed_warn": 100,
    "sudo_failed_warn": 5,
    "journal_errors_warn": 100
  },
  "critical_services": [
    "ssh",
    "docker",
    "fail2ban",
    "openmediavault-engined",
    "postfix",
    "cron"
  ],
  "checks": {
    "system_health": true,
    "os_updates": true,
    "unattended_upgrades": true,
    "reboot_required": true,
    "critical_services": true,
    "failed_services": true,
    "docker_status": true,
    "docker_image_updates": true,
    "docker_storage": true,
    "filesystem": true,
    "firewall": true,
    "listening_ports": true,
    "security_incidents": true,
    "ssh_logins": true,
    "fail2ban": true,
    "root_users": true,
    "system_errors": true
  },
  "paths": {
    "log_dir": "logs",
    "latest_report": "latest_report.md"
  }
}
```

---

## 📂 Dateistruktur

```
/srv/user/andreas/Cronjob/
├── config.json          # Schwellenwerte und Einstellungen
├── system_check.py      # Kern-Prüflogik für alle 8 Säulen
├── run_check.sh         # Wrapper-Skript für Cron / OMV
├── install_cron.sh      # CLI-Hilfsskript zur Crontab-Verwaltung
├── latest_report.md     # Der jeweils aktuellste Prüfbericht
└── logs/                # Historische Logs (mit 30 Tage Log-Rotation)
```
