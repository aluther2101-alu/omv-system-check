# 🛡️ Täglicher System- & Sicherheitsbericht: server01
**Prüfzeitpunkt:** `2026-11-14 12:02:59` | **Auslöser:** Täglicher Cronjob (06:30 Uhr)

### 🟡 **STATUS: WARNUNG** - Aufmerksamkeit oder Wartung empfohlen

#### 📌 Wichtigste Feststellungen:
- 428 fehlgeschlagene SSH-Logins in 24h
- Kernel I/O-Wartezeit-Meldungen (hung_task/io_wait) in 24h (11 Meldung(en))

---

## 🩺 1. Systemgesundheit & Performance
- **System-Uptime:** `1d 12h 50m`
- **CPU-Auslastung:** `Load 1m: 0.2` | `5m: 0.3` | `15m: 0.27` (12 CPU-Kerne, `0.02` pro Kern)
- **Arbeitsspeicher (RAM):** `8009.0 MB` von `23997.0 MB` genutzt (**33.4%**)
- **Swap-Speicher:** `0.0 MB` von `4096.0 MB` genutzt (**0.0%**)
- **Kernel OOM-Killer:** 🟢 Keine OOM-Ereignisse festgestellt.

---

## 📦 2. Betriebssystem & Paketaktualität (Debian 12)
- **Ausstehende Updates gesamt:** `0`
- **Debian Sicherheitsupdates:** `0`
- **System-Neustart erforderlich:** 🟢 Nein
- **Letzter Unattended-Upgrades Lauf:** `2026-11-14 06:07:21` (keine neuen Pakete)

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
| `ollama` | Up 12 hours | 🟡 none | `ollama/ollama:latest` |
| `open-webui` | Up 12 hours (healthy) | 🟢 healthy | `ghcr.io/open-webui/open-webui:latest` |
| `acd-voice-assistant-web` | Up 37 hours (healthy) | 🟢 healthy | `acd-voice-assistant-web:1.0.0` |
| `acd-voice-assistant-gov` | Up 37 hours (healthy) | 🟢 healthy | `acd-voice-assistant-gov:1.0.0` |
| `acd-voice-assistant-stt` | Up 37 hours (healthy) | 🟢 healthy | `acd-voice-assistant-stt:1.0.0` |
| `openvpn-as` | Up 12 hours | 🟡 none | `openvpn/openvpn-as` |
| `tika` | Up 12 hours | 🟡 none | `apache/tika:latest` |
| `crafty_container` | Up 12 hours | 🟡 none | `registry.gitlab.com/crafty-controller/crafty-4:latest` |
| `stunnel-proxy` | Up 12 hours | 🟡 none | `stunnel-terminator` |
| `acd-voice-assistant-db` | Up 37 hours (healthy) | 🟢 healthy | `acd-voice-assistant-db:1.0.0` |

**Registry-Aktualitätsprüfung der Images:**
| Image | Registry Status | Details |
|---|---|---|
| `ollama/ollama:latest` | 🟢 Aktuell | Aktuell |
| `ghcr.io/open-webui/open-webui:latest` | 🟢 Aktuell | Aktuell |
| `acd-voice-assistant-web:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `acd-voice-assistant-gov:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `acd-voice-assistant-stt:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |
| `openvpn/openvpn-as` | 🟢 Aktuell | Aktuell |
| `apache/tika:latest` | 🟢 Aktuell | Aktuell |
| `registry.gitlab.com/crafty-controller/crafty-4:latest` | 🟢 Aktuell | Aktuell |
| `stunnel-terminator` | ⚪ LOCAL_ONLY | Lokales Image oder keine Remote-Registry |
| `acd-voice-assistant-db:1.0.0` | ⚪ LOCAL_BUILD | Projektinternes/lokales Image |

**Docker Storage Aufteilung:**
- **Build-Cache:** `1.96GB`
- **Images:** `16.73GB`
- **Volumes:** `4.576GB`

---

## 💾 5. Dateisystem & Speicher-Integrität
- **Festplatte `/`:** `175.9 GB` von `708.5 GB` belegt (**24.8%**)
- **Freier Speicherplatz:** `503.7 GB`
- **Inode-Belegung (`/`):** `718167` von `47177728` (**2.0%**)
- **Mount-Modus:** 🟢 Read-Write (Normal)
- **Verzeichnis-Integrität:** 🟢 Keine unberechtigten oder verdächtigen Ordner auf `/`.

---

## 🧱 6. Firewall & Netzwerksicherheit
- **Dienststatus:** `iptables`: 🟢 Aktiv (openmediavault-firewall) | `nftables`: ⚪ Inaktiv | `ufw`: ⚪ Inaktiv
- **Regelwerk:** 🟢 OpenMediaVault IPTables-Regelsatz aktiv geladen.
- **Lauschende Ports auf Host (`0.0.0.0` / `::`):** `31` TCP, `118` UDP
- **Nur lokal gebundene Ports (`127.0.0.1`):** `4` TCP

**Gefundene sensitive Ports & Firewall-Filterstatus:**
| Port | Dienst | Socket-Bindung | IPTables Schutzstatus | Bewertung / Empfehlung |
|---|---|---|---|---|
| `22` | `SSH` | `0.0.0.0:22` | 🟢 IPTables OMV-Firewall aktiv | Brute-Force Angriffsziel (Empfehlung: Fail2Ban oder Portwechsel) |
| `8080` | `Web-UI / Proxy` | `0.0.0.0:8080` | 🟢 IPTables OMV-Firewall aktiv | Verwaltungs-Oberfläche |
| `8081` | `Web-UI / Crafty` | `0.0.0.0:8081` | 🟢 IPTables OMV-Firewall aktiv | Management-Interface |
| `11434` | `Ollama API` | `0.0.0.0:11434` | 🟢 IPTables OMV-Firewall aktiv | KI-Schnittstelle ohne zwingende Auth |
| `25565` | `Minecraft Server` | `0.0.0.0:25565` | 🟢 IPTables OMV-Firewall aktiv | Game-Server |

---

## 🛡️ 7. Sicherheitsvorfälle & Authentifizierung
### SSH-Aktivität (letzte 24 Stunden)
- **Fehlgeschlagene Logins:** `428`
- **Erfolgreiche Logins:** `2`

**Top Angreifer-IPs:**
| IP-Adresse | Fehlversuche |
|---|---|
| `117.247.23.131` | 8 |
| `1.234.80.94` | 6 |
| `213.209.159.228` | 4 |
| `104.244.79.113` | 4 |
| `156.232.13.246` | 3 |

### Fail2Ban & Abwehr
- **Dienststatus:** 🟢 Aktiv
- **Gesperrte IPs (Bans im Log):** `24`
  - Kürzlich gebannte IPs: `193.24.211.206, 92.118.39.71, 194.163.152.211, 186.96.158.180, 71.6.245.76`

### Sitzungen & Berechtigungen
- **Aktive interaktive Benutzersitzungen (1):**
  - Benutzer `andreas` an `pts/0` von `192.168.2.93` (seit 2026-11-14 11:15)
- **Sudo-Fehlversuche (24h):** `0`
- **Root-Konten (UID 0):** `root`
- **Sudo-Berechtigte Benutzer:** `andreas`

---

## ⚠️ 8. Fehlermeldungen & Systemprotokolle
- **Systemd-Journal Fehler (Priorität 0-3, letzte 24h):** `45` Ereignisse

**Häufigste Fehlermuster im Journal:**
| Häufigkeit | Dienst / Fehlermeldung |
|---|---|
| `11x` | `kernel: audit: backlog limit exceeded` |
| `6x` | `sshd-session: error: kex_exchange_identification: read: Connection reset by peer [preauth` |
| `5x` | `sudo: andreas : a password is required ; TTY=pts/1 ; PWD=/srv/user/andreas/Cronjo` |
| `3x` | `openmediavault-webgui: Authorized login from 192.168.2.41 (username=admin, user-agent=Mozilla/5.0 ` |
| `2x` | `sshd-session: error: Protocol major versions differ: 2 vs. 1 [preauth]` |
| `2x` | `monit: 'server01' loadavg (5min) of 13.8 matches resource limit [loadavg (5min) > ` |
| `2x` | `postfix/sendmail: fatal: root(0): message file too big` |
| `1x` | `openmediavault-webgui: Authorized login from 192.168.2.23 (username=admin, user-agent=Mozilla/5.0 ` |

⚠️ **Kernel I/O-Wartezeiten / Hung-Tasks (letzte 24h):**
- `Nov 13 18:58:01 server01 kernel: audit: backlog limit exceeded`
- `Nov 13 19:11:34 server01 kernel: audit: backlog limit exceeded`
- `Nov 13 19:11:39 server01 kernel: audit: backlog limit exceeded`

---

## 💡 Empfohlene Maßnahmen
1. Keine Maßnahmen erforderlich. Das System, alle Dateisysteme, Daemons und Container sind stabil.

*Automatischer Prüfbericht generiert durch `system_check.py`.*
