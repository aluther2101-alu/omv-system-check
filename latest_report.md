# 🛡️ Täglicher System- & Sicherheitsbericht: server01
**Prüfzeitpunkt:** `2026-11-13 19:10:43` | **Auslöser:** Täglicher Cronjob (06:30 Uhr)

### 🟡 **STATUS: WARNUNG** - Aufmerksamkeit oder Wartung empfohlen

#### 📌 Wichtigste Feststellungen:
- 5 Docker-Image-Update(s) in Registry verfügbar
- 3725 fehlgeschlagene SSH-Logins in 24h
- Erhöhte Fehleranzahl im Systemd-Journal: 1793 Fehlermeldungen (Priorität 0-3) in 24h
- Kernel I/O-Wartezeit-Meldungen (hung_task/io_wait) in 24h (31 Meldung(en))

---

## 🩺 1. Systemgesundheit & Performance
- **System-Uptime:** `19h 58m`
- **CPU-Auslastung:** `Load 1m: 0.15` | `5m: 0.3` | `15m: 0.25` (12 CPU-Kerne, `0.01` pro Kern)
- **Arbeitsspeicher (RAM):** `8022.0 MB` von `23997.0 MB` genutzt (**33.4%**)
- **Swap-Speicher:** *Kein Swap konfiguriert*
- **Kernel OOM-Killer:** 🟢 Keine OOM-Ereignisse festgestellt.

---

## 📦 2. Betriebssystem & Paketaktualität (Debian 12)
- **Ausstehende Updates gesamt:** `0`
- **Debian Sicherheitsupdates:** `0`
- **System-Neustart erforderlich:** 🟢 Nein
- **Letzter Unattended-Upgrades Lauf:** `2026-11-13 06:08:58` (keine neuen Pakete)

*Alle Betriebssystempakete sind aktuell.*

---

## ⚙️ 3. System-Dienste & Daemons
**Status der Kern-Dienste:**
| Dienst | Status | SubState | Restarts |
|---|---|---|---|
| `ssh` | 🟢 aktiv | `running` | 0 |
| `docker` | 🟢 aktiv | `running` | 0 |
| `fail2ban` | 🟢 aktiv | `running` | 0 |
| `openmediavault-engined` | 🟢 aktiv | `running` | 0 |
| `postfix` | 🟢 aktiv | `running` | 0 |
| `cron` | 🟢 aktiv | `running` | 0 |

- **Systemd Units:** 🟢 Alle Systemdienste laufen fehlerfrei (0 failed units).

---

## 🐳 4. Docker Container & Image-Aktualität
- **Container Gesamt:** `10` (Laufend: `10`)
- **Problematische Container:** `0`

| Container | Status | Health | Image |
|---|---|---|---|
| `ollama` | Up 19 hours | 🟡 none | `ollama/ollama:latest` |
| `open-webui` | Up 19 hours (healthy) | 🟢 healthy | `ghcr.io/open-webui/open-webui:latest` |
| `acd-voice-assistant-web` | Up 20 hours (healthy) | 🟢 healthy | `acd-voice-assistant-web:1.0.0` |
| `acd-voice-assistant-gov` | Up 20 hours (healthy) | 🟢 healthy | `acd-voice-assistant-gov:1.0.0` |
| `acd-voice-assistant-stt` | Up 20 hours (healthy) | 🟢 healthy | `acd-voice-assistant-stt:1.0.0` |
| `openvpn-as` | Up 19 hours | 🟡 none | `openvpn/openvpn-as` |
| `tika` | Up 19 hours | 🟡 none | `apache/tika:latest` |
| `crafty_container` | Up 19 hours | 🟡 none | `registry.gitlab.com/crafty-controller/crafty-4:latest` |
| `stunnel-proxy` | Up 19 hours | 🟡 none | `stunnel-terminator` |
| `acd-voice-assistant-db` | Up 20 hours (healthy) | 🟢 healthy | `acd-voice-assistant-db:1.0.0` |

**Registry-Aktualitätsprüfung der Images:**
| Image | Registry Status | Details |
|---|---|---|
| `ollama/ollama:latest` | 🟡 Update verfügbar | Neueres Image in Registry verfügbar |
| `ghcr.io/open-webui/open-webui:latest` | 🟡 Update verfügbar | Neueres Image in Registry verfügbar |
| `acd-voice-assistant-web:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `acd-voice-assistant-gov:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `acd-voice-assistant-stt:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `openvpn/openvpn-as` | 🟡 Update verfügbar | Neueres Image in Registry verfügbar |
| `apache/tika:latest` | 🟡 Update verfügbar | Neueres Image in Registry verfügbar |
| `registry.gitlab.com/crafty-controller/crafty-4:latest` | 🟡 Update verfügbar | Neueres Image in Registry verfügbar |
| `stunnel-terminator` | ⚪ LOCAL_ONLY | Lokales Image oder keine Remote-Registry |
| `acd-voice-assistant-db:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |

**Docker Storage Aufteilung:**
- **Build-Cache:** `1.96GB`
- **Images:** `16.27GB`
- **Volumes:** `4.696GB`

---

## 💾 5. Dateisystem & Speicher-Integrität
- **Festplatte `/`:** `171.4 GB` von `708.5 GB` belegt (**24.2%**)
- **Freier Speicherplatz:** `508.2 GB`
- **Inode-Belegung (`/`):** `702253` von `47177728` (**2.0%**)
- **Mount-Modus:** 🟢 Read-Write (Normal)
- **Verzeichnis-Integrität:** 🟢 Keine unberechtigten oder verdächtigen Ordner auf `/`.

---

## 🧱 6. Firewall & Netzwerksicherheit
- **Dienststatus:** `nftables`: ⚪ Inaktiv | `ufw`: ⚪ Inaktiv
- **Öffentlich lauschende Ports (`0.0.0.0` / `::`):** `31` TCP, `194` UDP
- **Nur lokal gebundene Ports (`127.0.0.1`):** `4` TCP

**Gefundene sensitive / öffentlich exponierte Ports:**
| Port | Dienst | Bewertung / Empfehlung |
|---|---|---|
| `22` | `SSH` | Brute-Force Angriffsziel (Empfehlung: Fail2Ban oder Portwechsel) |
| `8080` | `Web-UI / Proxy` | Verwaltungs-Oberfläche |
| `8081` | `Web-UI / Crafty` | Management-Interface |
| `11434` | `Ollama API` | KI-Schnittstelle ohne zwingende Auth |
| `25565` | `Minecraft Server` | Game-Server |

---

## 🛡️ 7. Sicherheitsvorfälle & Authentifizierung
### SSH-Aktivität (letzte 24 Stunden)
- **Fehlgeschlagene Logins:** `3725`
- **Erfolgreiche Logins:** `13`

**Top Angreifer-IPs:**
| IP-Adresse | Fehlversuche |
|---|---|
| `77.239.124.71` | 500 |
| `77.239.124.63` | 500 |
| `77.239.124.156` | 237 |
| `92.118.39.77` | 50 |
| `2.57.122.209` | 38 |

### Fail2Ban & Abwehr
- **Dienststatus:** 🟢 Aktiv
- **Gesperrte IPs (Bans im Log):** `8`
  - Kürzlich gebannte IPs: `1.234.80.94, 117.247.23.131, 104.244.79.113, 192.169.232.223`

### Sitzungen & Berechtigungen
- **Aktive interaktive Benutzersitzungen (2):**
  - Benutzer `andreas` an `pts/0` von `192.168.2.41` (seit 2026-11-13 15:43)
  - Benutzer `andreas` an `pts/3` von `192.168.2.23` (seit 2026-11-13 00:28)
- **Sudo-Fehlversuche (24h):** `1`
- **Root-Konten (UID 0):** `root`
- **Sudo-Berechtigte Benutzer:** `andreas`

---

## ⚠️ 8. Fehlermeldungen & Systemprotokolle
- **Systemd-Journal Fehler (Priorität 0-3, letzte 24h):** `1793` Ereignisse

**Häufigste Fehlermuster im Journal:**
| Häufigkeit | Dienst / Fehlermeldung |
|---|---|
| `286x` | `monit: Alert handler failed, retry scheduled for next cycle` |
| `187x` | `monit: Cannot connect to [127.0.0.1]:25 -- Connection timed out` |
| `187x` | `monit: Cannot open a connection to the mailserver 127.0.0.1:25 -- Operation now in` |
| `187x` | `monit: Mail: Delivery failed -- no mail server is available` |
| `107x` | `postfix/smtpd: fatal: connect #11 to subsystem private/proxymap: Connection refused` |
| `101x` | `monit: Mail: Error receiving data from the mailserver -- Resource temporarily unav` |
| `37x` | `omv-engined: ----------` |
| `29x` | `omv-engined: ` |

🔴 **Kernel-Hardware- / Treiberfehler (letzte 24h):**
- `Nov 13 00:30:45 server01 kernel: INFO: task kworker/u513:6:95 blocked in I/O wait for more than 120 seconds.`
- `Nov 13 00:30:45 server01 kernel:       Tainted: G               X    7.2.12+deb13-amd64 #1 Debian 7.2.12-1~bpo13+1`
- `Nov 13 00:30:45 server01 kernel: "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.`

---

## 💡 Empfohlene Maßnahmen
1. Docker Images aktualisieren: z.B. `docker pull <image>` oder `docker-compose pull && docker-compose up -d`

*Automatischer Prüfbericht generiert durch `system_check.py`.*
