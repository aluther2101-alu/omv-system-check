#!/usr/bin/env python3
"""
system_check.py - Tägliche Systemprüfung auf Aktualität und Sicherheit
Debian 12 Bookworm & Docker Umgebungs-Audit

Prüfumfang:
 1. Systemgesundheit (CPU-Last, Uptime, RAM/Swap, OOM-Killer, Reboot-Status)
 2. Updates & Paketaktualität (Debian OS, Sicherheitsupdates, Unattended-Upgrades)
 3. Dienste & Daemons (Kern-Dienste, SubStates, Restarts, Postfix IPC, Failed Units)
 4. Container & Docker (Zustand, Health-Checks, Registry-Image-Updates, Docker-Storage)
 5. Dateisystem & Speicher-Integrität (Speicherplatz, Inodes, Mount-Modus, Wurzel-Anomalien, Kernel-FS)
 6. Firewall & Netzwerksicherheit (nftables, iptables, ufw, exponierte & sensitive Ports)
 7. Sicherheitsvorfälle & Authentifizierung (SSH Brute-Force, Fail2Ban Bans, aktive Sitzungen, Sudo-Audit, Konten)
 8. Fehlermeldungen & Systemprotokolle (Systemd Journal Fehler p 0..3 der letzten 24h, Kernel-Fehler)
"""

import sys
import os
import json
import re
import datetime
import pathlib
import shutil
import subprocess
import hashlib
from collections import Counter

BASE_DIR = pathlib.Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def load_config() -> dict:
    default_config = {
        "system": {
            "hostname": "server01",
            "schedule": "06:30 täglich",
            "log_retention_days": 30,
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
            "journal_errors_warn": 100,
        },
        "critical_services": [
            "ssh",
            "docker",
            "fail2ban",
            "openmediavault-engined",
            "postfix",
            "cron",
        ],
        "checks": {
            "system_health": True,
            "os_updates": True,
            "unattended_upgrades": True,
            "reboot_required": True,
            "critical_services": True,
            "failed_services": True,
            "docker_status": True,
            "docker_image_updates": True,
            "docker_storage": True,
            "filesystem": True,
            "firewall": True,
            "listening_ports": True,
            "security_incidents": True,
            "ssh_logins": True,
            "fail2ban": True,
            "root_users": True,
            "system_errors": True,
        },
        "paths": {
            "log_dir": "logs",
            "latest_report": "latest_report.md",
        },
    }

    if CONFIG_PATH.is_file():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_conf = json.load(f)
                for k, v in user_conf.items():
                    if isinstance(v, dict) and k in default_config:
                        default_config[k].update(v)
                    else:
                        default_config[k] = v
        except Exception as e:
            print(f"[WARN] Konnte config.json nicht laden ({e}), nutze Standardwerte.", file=sys.stderr)

    return default_config


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return -1, "", str(e)


# ==========================================
# 1. Systemgesundheit
# ==========================================
def check_system_health(thresholds: dict) -> dict:
    result = {
        "uptime": "unbekannt",
        "load_1": 0.0,
        "load_5": 0.0,
        "load_15": 0.0,
        "cores": 1,
        "load_per_core": 0.0,
        "ram_used_mb": 0.0,
        "ram_total_mb": 0.0,
        "ram_percent": 0.0,
        "swap_used_mb": 0.0,
        "swap_total_mb": 0.0,
        "swap_percent": 0.0,
        "oom_events": [],
        "status": "OK",
        "warnings": [],
    }

    # 1. CPU Last & Kerne
    try:
        load1, load5, load15 = os.getloadavg()
        cores = os.cpu_count() or 1
        load_per_core = load1 / cores
        result["load_1"] = round(load1, 2)
        result["load_5"] = round(load5, 2)
        result["load_15"] = round(load15, 2)
        result["cores"] = cores
        result["load_per_core"] = round(load_per_core, 2)

        load_warn_th = thresholds.get("load_warn_per_core", 2.5)
        if load_per_core >= load_warn_th:
            result["warnings"].append(f"Hohe CPU-Last: {load1:.2f} ({load_per_core:.2f} pro Kern auf {cores} Kernen)")
            result["status"] = "WARNING"
    except Exception as e:
        result["warnings"].append(f"Fehler beim Lesen der CPU-Last: {e}")

    # 2. Uptime
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            up_secs = float(f.readline().split()[0])
        days = int(up_secs // 86400)
        hours = int((up_secs % 86400) // 3600)
        mins = int((up_secs % 3600) // 60)
        result["uptime"] = f"{days}d {hours}h {mins}m" if days > 0 else f"{hours}h {mins}m"
    except Exception:
        pass

    # 3. RAM & Swap aus /proc/meminfo
    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                p = line.split(":")
                if len(p) == 2:
                    meminfo[p[0].strip()] = int(p[1].split()[0])

        total_mb = meminfo.get("MemTotal", 0) / 1024
        avail_mb = meminfo.get("MemAvailable", 0) / 1024
        used_mb = total_mb - avail_mb
        ram_percent = (used_mb / total_mb * 100) if total_mb > 0 else 0

        swap_total_mb = meminfo.get("SwapTotal", 0) / 1024
        swap_free_mb = meminfo.get("SwapFree", 0) / 1024
        swap_used_mb = swap_total_mb - swap_free_mb
        swap_percent = (swap_used_mb / swap_total_mb * 100) if swap_total_mb > 0 else 0

        result["ram_total_mb"] = round(total_mb, 0)
        result["ram_used_mb"] = round(used_mb, 0)
        result["ram_percent"] = round(ram_percent, 1)
        result["swap_total_mb"] = round(swap_total_mb, 0)
        result["swap_used_mb"] = round(swap_used_mb, 0)
        result["swap_percent"] = round(swap_percent, 1)

        ram_th = thresholds.get("memory_warn_percent", 90)
        if ram_percent >= ram_th:
            result["warnings"].append(f"RAM-Auslastung hoch ({ram_percent:.1f}%)")
            result["status"] = "WARNING"

        swap_th = thresholds.get("swap_warn_percent", 80)
        if swap_total_mb > 0 and swap_percent >= swap_th:
            result["warnings"].append(f"Swap-Auslastung hoch ({swap_percent:.1f}%)")
            result["status"] = "WARNING"
    except Exception as e:
        result["warnings"].append(f"Fehler beim Lesen des Arbeitsspeichers: {e}")

    # 4. OOM-Killer & Kernel-Panics der letzten 24h
    code, stdout, _ = run_cmd(["journalctl", "-k", "--since", "24 hours ago", "--grep", "Out of memory|oom-killer|kernel panic", "--no-pager"], timeout=10)
    if code == 0 and stdout:
        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("--"):
                result["oom_events"].append(line_str)
        if result["oom_events"]:
            result["warnings"].append(f"Kritische Speicher-/Kernel-Ereignisse (OOM): {len(result['oom_events'])} Vorfall/Vorfälle in 24h")
            result["status"] = "CRITICAL"

    return result


# ==========================================
# 2. OS & Paket-Aktualität
# ==========================================
def check_os_updates() -> dict:
    result = {
        "total_upgrades": 0,
        "security_upgrades": 0,
        "packages": [],
        "error": None,
    }
    code, stdout, stderr = run_cmd(["apt", "list", "--upgradable"], timeout=30)
    if code != 0 and not stdout:
        result["error"] = stderr.strip() or "apt list fehlgeschlagen"
        return result

    lines = stdout.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Listing...") or line.startswith("N:"):
            continue

        is_security = "security" in line.lower() or "debian-security" in line.lower()
        if is_security:
            result["security_upgrades"] += 1
        result["total_upgrades"] += 1

        parts = line.split()
        pkg_name = parts[0].split("/")[0] if parts else line
        target_ver = parts[1] if len(parts) > 1 else "?"
        current_ver = "?"
        if "from:" in line:
            m = re.search(r"\[upgradable from:\s*([^\]]+)\]", line)
            if m:
                current_ver = m.group(1).strip()

        result["packages"].append({
            "name": pkg_name,
            "target_version": target_ver,
            "current_version": current_ver,
            "is_security": is_security,
            "raw": line,
        })

    return result


def check_unattended_upgrades() -> dict:
    log_file = pathlib.Path("/var/log/unattended-upgrades/unattended-upgrades.log")
    result = {
        "available": False,
        "last_run": None,
        "packages_upgraded": [],
        "errors": [],
    }
    if not log_file.is_file():
        return result

    result["available"] = True
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-60:]

        current_run_time = None
        for line in lines:
            if "Starting unattended upgrades script" in line:
                m = re.match(r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", line)
                if m:
                    current_run_time = m.group(1)
            elif "Packages that will be upgraded:" in line:
                pkgs = line.split("Packages that will be upgraded:")[-1].strip().split()
                result["packages_upgraded"].extend(pkgs)
            elif "ERROR" in line or "WARNING" in line:
                result["errors"].append(line.strip())

        result["last_run"] = current_run_time
    except Exception as e:
        result["errors"].append(f"Lesefehler: {e}")

    return result


def check_reboot_required() -> dict:
    flag_file = pathlib.Path("/run/reboot-required")
    pkgs_file = pathlib.Path("/run/reboot-required.pkgs")
    result = {
        "required": flag_file.exists(),
        "packages": [],
    }
    if result["required"] and pkgs_file.is_file():
        try:
            with open(pkgs_file, "r", encoding="utf-8", errors="replace") as f:
                result["packages"] = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
    return result


# ==========================================
# 3. Dienste & Daemons
# ==========================================
def check_critical_services(services_list: list[str]) -> dict:
    result = {
        "services": [],
        "failed_critical": [],
    }
    for s in services_list:
        code, stdout, _ = run_cmd(["systemctl", "is-active", s], timeout=5)
        is_active = (stdout.strip() == "active")

        # Details abfragen
        show_code, show_out, _ = run_cmd(["systemctl", "show", "-p", "SubState,NRestarts", s], timeout=5)
        details = {}
        if show_code == 0:
            for l in show_out.strip().splitlines():
                if "=" in l:
                    k, v = l.split("=", 1)
                    details[k] = v

        restarts = int(details.get("NRestarts", 0)) if details.get("NRestarts", "0").isdigit() else 0
        substate = details.get("SubState", stdout.strip())

        # Tiefenprüfung für Postfix: Kann die Warteschlange abgefragt werden?
        if s == "postfix" and is_active:
            pq_code, pq_stdout, pq_stderr = run_cmd(["postqueue", "-p"], timeout=5)
            if pq_code != 0 and ("mail system is down" in (pq_stdout + pq_stderr) or "Connection refused" in (pq_stdout + pq_stderr)):
                is_active = False
                substate = "down (IPC blockiert / Connection refused)"

        item = {
            "name": s,
            "active": is_active,
            "substate": substate,
            "restarts": restarts,
        }
        result["services"].append(item)

        if not is_active:
            result["failed_critical"].append(s)

    return result


def check_failed_services() -> list[str]:
    code, stdout, _ = run_cmd(["systemctl", "--failed", "--no-legend", "--plain"], timeout=10)
    failed = []
    if code == 0:
        for line in stdout.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            unit = parts[1] if parts[0] == "●" else parts[0]
            failed.append(unit)
    return failed


# ==========================================
# 4. Docker Container & Image-Aktualität
# ==========================================
def check_docker_containers() -> dict:
    result = {
        "available": False,
        "total": 0,
        "running": 0,
        "unhealthy": [],
        "exited": [],
        "restarting": [],
        "containers": [],
        "error": None,
    }
    code, stdout, stderr = run_cmd(["docker", "ps", "-a", "--format", "json"], timeout=15)
    if code != 0:
        result["error"] = stderr.strip() or "docker ps fehlgeschlagen"
        return result

    result["available"] = True
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]

    for line in lines:
        try:
            c = json.loads(line)
        except Exception:
            continue

        result["total"] += 1
        name = c.get("Names", "unknown")
        state = c.get("State", "").lower()
        status = c.get("Status", "")
        health = c.get("HealthStatus", "").lower()
        image = c.get("Image", "")
        ports = c.get("Ports", "")

        is_running = (state == "running")
        if is_running:
            result["running"] += 1

        c_info = {
            "name": name,
            "image": image,
            "state": state,
            "status": status,
            "health": health or "none",
            "ports": ports,
        }
        result["containers"].append(c_info)

        if health in ["unhealthy", "starting"]:
            result["unhealthy"].append(c_info)
        if "restarting" in status.lower() or state == "restarting":
            result["restarting"].append(c_info)
        if state == "exited" and not status.startswith("Exited (0)"):
            result["exited"].append(c_info)

    return result


def check_docker_image_updates(containers: list[dict]) -> list[dict]:
    results = []
    seen_images = set()

    for c in containers:
        image = c.get("image", "")
        if not image or image in seen_images:
            continue
        seen_images.add(image)

        if not ("/" in image or ":" in image) or re.match(r"^[0-9a-f]{12,}$", image):
            results.append({
                "image": image,
                "status": "LOCAL_ONLY",
                "details": "Lokales Image oder keine Remote-Registry",
            })
            continue

        if image.startswith("acd-voice-assistant") or "local" in image:
            results.append({
                "image": image,
                "status": "LOCAL_BUILD",
                "details": "Projektinternes/lokales Image",
            })
            continue

        code, insp_out, _ = run_cmd(["docker", "image", "inspect", image], timeout=10)
        local_digests = []
        if code == 0:
            try:
                insp_data = json.loads(insp_out)[0]
                local_digests = insp_data.get("RepoDigests", []) or []
            except Exception:
                pass

        matched = False

        # 1. Methode: buildx imagetools inspect --raw liefert den exakten Manifest-Index Hash
        # welcher von Docker in RepoDigests für Multi-Arch Images gespeichert wird
        code_raw, raw_out, err_raw = run_cmd(["docker", "buildx", "imagetools", "inspect", "--raw", image], timeout=12)
        if code_raw == 0 and raw_out:
            raw_hash = f"sha256:{hashlib.sha256(raw_out.encode('utf-8')).hexdigest()}"
            for ld in local_digests:
                if raw_hash in ld:
                    matched = True
                    break

        # 2. Methode: Fallback auf docker manifest inspect für Single-Arch oder Child-Manifests
        if not matched:
            code_m, m_out, m_err = run_cmd(["docker", "manifest", "inspect", "-v", image], timeout=12)
            if code_m == 0 and m_out:
                try:
                    m_json = json.loads(m_out)
                    manifest_items = m_json if isinstance(m_json, list) else [m_json]
                    for item in manifest_items:
                        desc_digest = item.get("Descriptor", {}).get("digest")
                        for ld in local_digests:
                            if desc_digest and desc_digest in ld:
                                matched = True
                                break
                        if matched:
                            break
                except Exception:
                    pass
            elif code_raw != 0:
                err_msg = (err_raw or m_err).strip()
                if "manifest unknown" in err_msg or "not found" in err_msg:
                    status_desc = "LOCAL_ONLY"
                    details = "Nicht auf Remote-Registry gefunden"
                elif "timed out" in err_msg:
                    status_desc = "TIMEOUT"
                    details = "Registry-Timeout bei der Prüfung"
                else:
                    status_desc = "SKIPPED"
                    details = f"Prüfung übersprungen ({err_msg[:60]})"
                results.append({
                    "image": image,
                    "status": status_desc,
                    "details": details,
                })
                continue

        results.append({
            "image": image,
            "status": "UP_TO_DATE" if matched else "UPDATE_AVAILABLE",
            "details": "Aktuell" if matched else "Neueres Image in Registry verfügbar",
        })

    return results


def check_docker_storage(thresholds: dict) -> dict:
    result = {
        "available": False,
        "build_cache_size": "0B",
        "build_cache_gb": 0.0,
        "images_size": "0B",
        "volumes_size": "0B",
        "containers_size": "0B",
        "warning": None,
    }
    code, stdout, _ = run_cmd(["docker", "system", "df", "--format", "json"], timeout=10)
    if code != 0 or not stdout:
        return result

    result["available"] = True
    for line in stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            t = item.get("Type", "")
            size_str = item.get("Size", "0B")

            size_gb = 0.0
            m = re.match(r"([\d\.]+)\s*([kKmMgGtT]?)B?", size_str)
            if m:
                val = float(m.group(1))
                unit = m.group(2).upper()
                if unit == "K":
                    size_gb = val / (1024**2)
                elif unit == "M":
                    size_gb = val / 1024
                elif unit == "G":
                    size_gb = val
                elif unit == "T":
                    size_gb = val * 1024

            if t == "Build Cache":
                result["build_cache_size"] = size_str
                result["build_cache_gb"] = round(size_gb, 1)
            elif t == "Images":
                result["images_size"] = size_str
            elif t == "Local Volumes":
                result["volumes_size"] = size_str
            elif t == "Containers":
                result["containers_size"] = size_str
        except Exception:
            pass

    cache_threshold = thresholds.get("docker_build_cache_warn_gb", 40)
    if result["build_cache_gb"] >= cache_threshold:
        result["warning"] = f"Docker Build-Cache belegt {result['build_cache_gb']} GB (Schwellenwert: {cache_threshold} GB)"

    return result


# ==========================================
# 5. Dateisystem & Speicher-Integrität
# ==========================================
def check_filesystem(thresholds: dict) -> dict:
    result = {
        "root_disk": {},
        "inodes": {},
        "mount_options": "",
        "is_read_only": False,
        "kernel_errors": [],
        "root_anomalies": [],
        "large_backups": [],
        "status": "OK",
        "warnings": [],
    }

    # 1. Speicherplatz Root
    try:
        du = shutil.disk_usage("/")
        total_gb = du.total / (1024**3)
        used_gb = du.used / (1024**3)
        free_gb = du.free / (1024**3)
        percent = (du.used / du.total) * 100

        result["root_disk"] = {
            "mount": "/",
            "total_gb": round(total_gb, 1),
            "used_gb": round(used_gb, 1),
            "free_gb": round(free_gb, 1),
            "percent": round(percent, 1),
        }

        if percent >= thresholds.get("disk_crit_percent", 95):
            result["warnings"].append(f"Festplatte / kritisch voll ({percent:.1f}%)")
            result["status"] = "CRITICAL"
        elif percent >= thresholds.get("disk_warn_percent", 85):
            result["warnings"].append(f"Festplatte / belegt ({percent:.1f}%)")
            if result["status"] == "OK":
                result["status"] = "WARNING"
    except Exception as e:
        result["root_disk"]["error"] = str(e)

    # 2. Inodes auf /
    code, stdout, _ = run_cmd(["df", "-i", "/"], timeout=5)
    if code == 0:
        lines = stdout.strip().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                try:
                    i_total = int(parts[1])
                    i_used = int(parts[2])
                    i_percent = float(parts[4].replace("%", ""))
                    result["inodes"] = {
                        "total": i_total,
                        "used": i_used,
                        "percent": i_percent,
                    }
                    if i_percent >= thresholds.get("inode_crit_percent", 95):
                        result["warnings"].append(f"Inodes auf / kritisch ({i_percent:.1f}%)")
                        result["status"] = "CRITICAL"
                    elif i_percent >= thresholds.get("inode_warn_percent", 85):
                        result["warnings"].append(f"Inodes auf / belegt ({i_percent:.1f}%)")
                        if result["status"] == "OK":
                            result["status"] = "WARNING"
                except Exception:
                    pass

    # 3. Mount-Status (Read-Only Check)
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1] == "/":
                    opts = parts[3].split(",")
                    result["mount_options"] = parts[3]
                    if "ro" in opts:
                        result["is_read_only"] = True
                        result["warnings"].append("Dateisystem / ist unerwartet READ-ONLY gemountet!")
                        result["status"] = "CRITICAL"
                    break
    except Exception:
        pass

    # 4. Wurzelverzeichnis-Anomalien
    std_dirs = {
        "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "libx32",
        "lost+found", "media", "mnt", "opt", "proc", "root", "run", "sbin",
        "srv", "sys", "tmp", "usr", "var", "sftp", "export",
        "Scripte", "scripte", "scripts", "Scripts"
    }
    try:
        for entry in os.listdir("/"):
            if os.path.isdir("/" + entry) and entry not in std_dirs:
                result["root_anomalies"].append(entry)
                result["warnings"].append(f"Unerwarteter Ordner im Wurzelverzeichnis entdeckt: '/{entry}'")
                if result["status"] == "OK":
                    result["status"] = "WARNING"
    except Exception:
        pass

    # 5. Suche nach versehentlichen Riesen-Backups auf /srv oder /var
    code, stdout, _ = run_cmd(["find", "/srv", "-maxdepth", "3", "-name", "*.fsa", "-size", "+50G"], timeout=5)
    if code == 0 and stdout:
        for line in stdout.splitlines():
            if line.strip():
                result["large_backups"].append(line.strip())
                result["warnings"].append(f"Große Backup-Datei gefunden: {line.strip()}")
                if result["status"] == "OK":
                    result["status"] = "WARNING"

    # 6. Kernel Dateisystem-/I/O-Fehler
    code, stdout, _ = run_cmd(["journalctl", "-k", "-p", "3", "--since", "24 hours ago", "--no-pager"], timeout=10)
    if code == 0:
        for line in stdout.splitlines():
            if any(term in line.lower() for term in ["ext4-fs error", "i/o error", "corruption", "remount-ro", "bad block"]):
                clean = line.strip()
                result["kernel_errors"].append(clean)
                result["warnings"].append(f"Dateisystemfehler im Kernel-Log: {clean[:80]}")
                result["status"] = "CRITICAL"

    return result


# ==========================================
# 6. Firewall & Netzwerksicherheit
# ==========================================
def check_listening_ports() -> dict:
    result = {
        "public_tcp": [],
        "public_udp": [],
        "localhost_tcp": [],
        "localhost_udp": [],
        "vpn_tcp": [],
        "error": None,
    }
    code, stdout, stderr = run_cmd(["ss", "-tuln"], timeout=10)
    if code != 0:
        result["error"] = stderr.strip() or "ss fehlgeschlagen"
        return result

    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ["Netid", "State"]:
            continue

        proto = parts[0].lower()
        local_addr = parts[4]

        port_m = re.search(r":(\d+)$", local_addr)
        if not port_m:
            continue
        port = int(port_m.group(1))

        is_localhost = local_addr.startswith("127.") or local_addr.startswith("[::1]")
        is_vpn = local_addr.startswith("10.") or local_addr.startswith("172.16.") or local_addr.startswith("192.168.")
        item = {"proto": proto, "port": port, "address": local_addr}

        if is_localhost:
            if proto == "tcp" and item not in result["localhost_tcp"]:
                result["localhost_tcp"].append(item)
            elif proto == "udp" and item not in result["localhost_udp"]:
                result["localhost_udp"].append(item)
        elif is_vpn:
            if proto == "tcp" and item not in result["vpn_tcp"]:
                result["vpn_tcp"].append(item)
        else:
            if proto == "tcp" and item not in result["public_tcp"]:
                result["public_tcp"].append(item)
            elif proto == "udp" and item not in result["public_udp"]:
                result["public_udp"].append(item)

    result["public_tcp"].sort(key=lambda x: x["port"])
    result["public_udp"].sort(key=lambda x: x["port"])
    result["vpn_tcp"].sort(key=lambda x: x["port"])
    return result


def check_firewall(ports: dict) -> dict:
    result = {
        "omv_firewall_active": False,
        "nftables_active": False,
        "ufw_active": False,
        "active_firewall": "Keine",
        "iptables_readable": False,
        "ipv4_default_policy": "unbekannt",
        "ipv4_rules_count": 0,
        "ipv4_has_catchall_drop": False,
        "ipv6_default_policy": "unbekannt",
        "ipv6_rules_count": 0,
        "ipv6_has_catchall_drop": False,
        "port_rules": {},
        "sensitive_exposed_ports": [],
        "warnings": [],
        "status": "OK",
    }

    # 1. Daemon-Status prüfen
    code_omv, out_omv, _ = run_cmd(["systemctl", "is-active", "openmediavault-firewall"], timeout=5)
    result["omv_firewall_active"] = (out_omv.strip() == "active")

    code_nft, out_nft, _ = run_cmd(["systemctl", "is-active", "nftables"], timeout=5)
    result["nftables_active"] = (out_nft.strip() == "active")

    code_ufw, out_ufw, _ = run_cmd(["systemctl", "is-active", "ufw"], timeout=5)
    result["ufw_active"] = (out_ufw.strip() == "active")

    active_daemons = []
    if result["omv_firewall_active"]:
        active_daemons.append("iptables (OMV-Firewall)")
    if result["nftables_active"]:
        active_daemons.append("nftables")
    if result["ufw_active"]:
        active_daemons.append("ufw")

    result["active_firewall"] = ", ".join(active_daemons) if active_daemons else "Keine"

    # 2. IPTables IPv4 Regeln prüfen (direkt oder via sudo -n)
    code_v4, stdout_v4, _ = run_cmd(["iptables", "-S"], timeout=5)
    if code_v4 != 0:
        code_v4, stdout_v4, _ = run_cmd(["sudo", "-n", "iptables", "-S"], timeout=5)

    if code_v4 == 0 and stdout_v4:
        result["iptables_readable"] = True
        for line in stdout_v4.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("-P INPUT"):
                result["ipv4_default_policy"] = line.split()[-1]
            elif line.startswith("-A INPUT"):
                result["ipv4_rules_count"] += 1

                # Catch-All DROP / REJECT prüfen
                if line in ["-A INPUT -j DROP", "-A INPUT -j REJECT"]:
                    result["ipv4_has_catchall_drop"] = True

                # Ports extrahieren (--dport oder multiport)
                dports = []
                m_single = re.search(r"--dport\s+(\d+)", line)
                if m_single:
                    dports.append(int(m_single.group(1)))
                m_multi = re.search(r"--dports\s+([0-9,]+)", line)
                if m_multi:
                    for p in m_multi.group(1).split(","):
                        if p.isdigit():
                            dports.append(int(p))

                # Quelle extrahieren
                src = "alle (0.0.0.0/0)"
                m_src = re.search(r"-s\s+(\S+)", line)
                if m_src:
                    src = m_src.group(1)
                elif "--src-range" in line:
                    m_range = re.search(r"--src-range\s+(\S+)", line)
                    if m_range:
                        src = m_range.group(1)

                m_iface = re.search(r"-i\s+(\S+)", line)
                if m_iface:
                    src += f" auf {m_iface.group(1)}"

                action = "ACCEPT" if "-j ACCEPT" in line else ("DROP" if "-j DROP" in line else ("REJECT" if "-j REJECT" in line else "OTHER"))

                for dp in dports:
                    if dp not in result["port_rules"]:
                        result["port_rules"][dp] = []
                    result["port_rules"][dp].append({
                        "action": action,
                        "source": src,
                        "raw": line
                    })

    # 3. IP6Tables IPv6 Regeln prüfen
    code_v6, stdout_v6, _ = run_cmd(["ip6tables", "-S"], timeout=5)
    if code_v6 != 0:
        code_v6, stdout_v6, _ = run_cmd(["sudo", "-n", "ip6tables", "-S"], timeout=5)

    if code_v6 == 0 and stdout_v6:
        for line in stdout_v6.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("-P INPUT"):
                result["ipv6_default_policy"] = line.split()[-1]
            elif line.startswith("-A INPUT"):
                result["ipv6_rules_count"] += 1
                if line in ["-A INPUT -j DROP", "-A INPUT -j REJECT"]:
                    result["ipv6_has_catchall_drop"] = True

    # 4. Sensitive Ports analysieren (0.0.0.0 / ::)
    sensitive_map = {
        22: ("SSH", "Brute-Force Angriffsziel (Empfehlung: Fail2Ban oder Portwechsel)"),
        139: ("Samba (NetBIOS)", "Unsicher im Internet! Dringend schließen."),
        445: ("Samba (SMB)", "Direkter Dateizugriff im Internet! Dringend schließen."),
        5432: ("PostgreSQL", "Datenbank öffentlich erreichbar"),
        3306: ("MySQL/MariaDB", "Datenbank öffentlich erreichbar"),
        8080: ("Web-UI / Proxy", "Verwaltungs-Oberfläche"),
        8081: ("Web-UI / Crafty", "Management-Interface"),
        11434: ("Ollama API", "KI-Schnittstelle ohne zwingende Auth"),
        25565: ("Minecraft Server", "Game-Server"),
    }

    public_tcp_ports = set(p["port"] for p in ports.get("public_tcp", []))
    for p, (srv, note) in sensitive_map.items():
        if p in public_tcp_ports:
            fw_protection = "Ungeprüft (erfordert root für Detail-Regeln)"
            is_protected = False

            if result["iptables_readable"]:
                rules_for_p = result["port_rules"].get(p, [])
                if rules_for_p:
                    allow_rules = [r for r in rules_for_p if r["action"] == "ACCEPT"]
                    drop_rules = [r for r in rules_for_p if r["action"] in ["DROP", "REJECT"]]
                    if drop_rules and not allow_rules:
                        fw_protection = "🟢 Blockiert durch IPTables"
                        is_protected = True
                    elif allow_rules:
                        sources = [r["source"] for r in allow_rules]
                        is_restricted = any(s != "alle (0.0.0.0/0)" for s in sources)
                        if is_restricted:
                            fw_protection = f"🟢 Geschützt (nur von {', '.join(sources)})"
                            is_protected = True
                        else:
                            fw_protection = "🟡 Erlaubt von überall (0.0.0.0/0)"
                elif result["ipv4_has_catchall_drop"] or result["ipv4_default_policy"] in ["DROP", "REJECT"]:
                    fw_protection = "🟢 Blockiert durch Default/Catchall DROP"
                    is_protected = True
                else:
                    fw_protection = "⚠️ Ungeschützt (keine Regel, Default ACCEPT)"
            elif result["omv_firewall_active"]:
                fw_protection = "🟢 IPTables OMV-Firewall aktiv"
                is_protected = True

            result["sensitive_exposed_ports"].append({
                "port": p,
                "service": srv,
                "protection": fw_protection,
                "note": note,
                "is_protected": is_protected,
            })

            # Nur alarmieren, wenn tatsächlich ungeschützt
            if not is_protected and not result["omv_firewall_active"]:
                if p in [139, 445, 5432, 3306]:
                    result["warnings"].append(f"Kritischer Port ungeschützt öffentlich geöffnet: {p} ({srv})")
                    result["status"] = "CRITICAL"
                elif p in [11434, 8080, 8081]:
                    if result["status"] == "OK":
                        result["status"] = "WARNING"

    if not result["omv_firewall_active"] and not result["nftables_active"] and not result["ufw_active"]:
        if result["sensitive_exposed_ports"]:
            result["warnings"].append(f"Keine Firewall aktiv mit {len(result['sensitive_exposed_ports'])} sensitiven Diensten.")
            if result["status"] == "OK":
                result["status"] = "WARNING"

    return result


# ==========================================
# 7. Sicherheitsvorfälle & Authentifizierung
# ==========================================
def check_ssh_security() -> dict:
    result = {
        "failed_attempts": 0,
        "successful_logins": 0,
        "top_attackers": [],
        "successful_users": [],
        "root_login_detected": False,
        "error": None,
    }
    code, stdout, stderr = run_cmd(["journalctl", "-u", "ssh", "--since", "24 hours ago", "--no-pager"], timeout=30)
    if code != 0:
        result["error"] = stderr.strip() or "journalctl ssh fehlgeschlagen"
        return result

    attacker_ips = Counter()
    users_success = Counter()

    for line in stdout.splitlines():
        if "Failed password" in line or "Failed none" in line or "authentication failure" in line:
            result["failed_attempts"] += 1
            m = re.search(r"from\s+([0-9a-fA-F\.:]+)", line)
            if m:
                attacker_ips[m.group(1)] += 1
        elif "Accepted publickey" in line or "Accepted password" in line:
            result["successful_logins"] += 1
            m = re.search(r"Accepted \S+ for (\S+) from ([0-9a-fA-F\.:]+)", line)
            if m:
                user = m.group(1)
                ip = m.group(2)
                users_success[f"{user}@{ip}"] += 1
                if user == "root":
                    result["root_login_detected"] = True

    result["top_attackers"] = attacker_ips.most_common(5)
    result["successful_users"] = users_success.most_common(10)
    return result


def check_fail2ban() -> dict:
    result = {
        "active": False,
        "recent_bans": 0,
        "banned_ips": [],
        "config_warnings": [],
    }
    code, stdout, _ = run_cmd(["systemctl", "is-active", "fail2ban"], timeout=5)
    result["active"] = (stdout.strip() == "active")

    f2b_log = pathlib.Path("/var/log/fail2ban.log")
    if f2b_log.is_file():
        try:
            with open(f2b_log, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-200:]
            for line in lines:
                if "Ban " in line:
                    result["recent_bans"] += 1
                    m = re.search(r"Ban\s+([0-9a-fA-F\.:]+)", line)
                    if m and m.group(1) not in result["banned_ips"]:
                        result["banned_ips"].append(m.group(1))
        except Exception:
            pass

    # Warnungen / Fehler in Fail2Ban Konfiguration
    code, ts_out, _ = run_cmd(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "fail2ban"], timeout=5)
    since_arg = ts_out.strip() if code == 0 and ts_out.strip() else "-1h"
    code, j_out, _ = run_cmd(["journalctl", "-u", "fail2ban", "--since", since_arg, "--no-pager"], timeout=10)
    if code == 0:
        for line in j_out.splitlines():
            if "ERROR" in line or "Unable to read" in line or "Skipping..." in line:
                clean_line = re.sub(r"^.*?server01 fail2ban-\S+\[\d+\]:\s*", "", line)
                if clean_line not in result["config_warnings"]:
                    result["config_warnings"].append(clean_line)

    return result


def check_active_sessions() -> list[dict]:
    sessions = []
    code, stdout, _ = run_cmd(["who"], timeout=5)
    if code == 0:
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            m = re.match(r"^(\S+)\s+(?:sshd\s+)?(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*(?:\(([^)]+)\))?", line_str)
            if m:
                sessions.append({
                    "user": m.group(1),
                    "terminal": m.group(2),
                    "time": m.group(3),
                    "host": m.group(4) or "lokal",
                })
            else:
                parts = line_str.split()
                if parts:
                    sessions.append({
                        "user": parts[0],
                        "terminal": parts[1] if len(parts) > 1 else "?",
                        "time": parts[2] if len(parts) > 2 else "?",
                        "host": parts[-1].strip("()") if len(parts) > 3 else "lokal",
                    })
    return sessions


def check_sudo_incidents(thresholds: dict) -> dict:
    result = {
        "failed_attempts": 0,
        "incidents": [],
        "warning": None,
    }
    code, stdout, _ = run_cmd(["journalctl", "--since", "24 hours ago", "--grep", "pam_unix.*sudo.*authentication failure|sudo:.*incorrect password", "--no-pager"], timeout=10)
    if code == 0 and stdout:
        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("--"):
                result["failed_attempts"] += 1
                result["incidents"].append(line_str)

    sudo_warn_th = thresholds.get("sudo_failed_warn", 5)
    if result["failed_attempts"] >= sudo_warn_th:
        result["warning"] = f"Auffällige Sudo-Fehlversuche: {result['failed_attempts']} fehlgeschlagene Versuche in 24h"

    return result


def check_root_users() -> dict:
    result = {
        "root_accounts": [],
        "sudo_users": [],
    }
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2] == "0":
                    result["root_accounts"].append(parts[0])
    except Exception:
        pass

    try:
        with open("/etc/group", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4 and parts[0] in ["sudo", "wheel", "admin"]:
                    members = [m.strip() for m in parts[3].split(",") if m.strip()]
                    result["sudo_users"].extend(members)
        result["sudo_users"] = sorted(list(set(result["sudo_users"])))
    except Exception:
        pass

    return result


def check_security_incidents(thresholds: dict) -> dict:
    ssh_data = check_ssh_security()
    f2b_data = check_fail2ban()
    sessions = check_active_sessions()
    sudo_data = check_sudo_incidents(thresholds)
    root_u = check_root_users()

    status = "OK"
    warnings = []

    if ssh_data.get("root_login_detected"):
        warnings.append("Direkter Root-Login über SSH festgestellt!")
        status = "CRITICAL"

    if ssh_data.get("failed_attempts", 0) >= thresholds.get("ssh_failed_warn", 100):
        warnings.append(f"{ssh_data['failed_attempts']} fehlgeschlagene SSH-Logins in 24h")
        if status == "OK":
            status = "WARNING"

    if not f2b_data.get("active"):
        warnings.append("Fail2Ban-Dienst ist inaktiv")
        if status == "OK":
            status = "WARNING"

    if f2b_data.get("config_warnings"):
        warnings.append(f"Fail2Ban Konfigurationsfehler ({len(f2b_data['config_warnings'])} Warnung(en))")
        if status == "OK":
            status = "WARNING"

    if sudo_data.get("warning"):
        warnings.append(sudo_data["warning"])
        if status == "OK":
            status = "WARNING"

    if len(root_u.get("root_accounts", [])) > 1:
        warnings.append(f"Mehrere UID 0 Accounts erkannt: {root_u['root_accounts']}")
        status = "CRITICAL"

    return {
        "ssh": ssh_data,
        "fail2ban": f2b_data,
        "sessions": sessions,
        "sudo": sudo_data,
        "root_users": root_u,
        "status": status,
        "warnings": warnings,
    }


# ==========================================
# 8. Fehlermeldungen & Systemprotokolle
# ==========================================
def check_system_errors(thresholds: dict) -> dict:
    result = {
        "total_errors": 0,
        "top_error_patterns": [],
        "kernel_errors": [],
        "warnings": [],
        "status": "OK",
    }

    # Bekannte harmlose / kosmetische Meldungen herausfiltern
    ignored_patterns = [
        r"systemd-ssh-generator",
        r"sd-exec-",
        r"filebrowser-proxy.*shutdown complete",
        r"filebrowser-proxy.*byeee",
        r"filebrowser-proxy.*shutting down apps",
    ]

    code, stdout, _ = run_cmd(["journalctl", "-p", "0..3", "--since", "24 hours ago", "--no-pager"], timeout=15)
    if code == 0 and stdout:
        err_counts = Counter()
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("--"):
                continue

            # Filter prüfen
            if any(re.search(pat, line_str) for pat in ignored_patterns):
                continue

            result["total_errors"] += 1

            # Normalisieren für Muster-Zählung
            m = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(.*?):\s*(.*)", line_str)
            if m:
                unit, msg = m.group(1), m.group(2)
                unit = re.sub(r"\[\d+\]", "", unit)
                short_msg = msg[:75]
                err_counts[f"{unit}: {short_msg}"] += 1
            else:
                err_counts[line_str[:80]] += 1

        result["top_error_patterns"] = err_counts.most_common(8)

    # Kernel-Fehlermeldungen
    code, k_out, _ = run_cmd(["journalctl", "-k", "-p", "0..3", "--since", "24 hours ago", "--no-pager"], timeout=10)
    if code == 0 and k_out:
        for line in k_out.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("--"):
                if not any(re.search(pat, line_str) for pat in ignored_patterns):
                    result["kernel_errors"].append(line_str)

    err_warn_th = thresholds.get("journal_errors_warn", 100)
    if result["total_errors"] >= err_warn_th:
        result["warnings"].append(f"Erhöhte Fehleranzahl im Systemd-Journal: {result['total_errors']} Fehlermeldungen (Priorität 0-3) in 24h")
        result["status"] = "WARNING"

    if result["kernel_errors"]:
        severe_kernel = [ke for ke in result["kernel_errors"] if any(t in ke.lower() for t in ["ext4", "corruption", "bad block", "i/o error", "hardware error", "segfault", "panic"])]
        if severe_kernel:
            result["warnings"].append(f"Kritische Kernel-Hardware-/Treiberfehler erkannt ({len(severe_kernel)} Vorfälle)")
            result["status"] = "CRITICAL"
        else:
            result["warnings"].append(f"Kernel I/O-Wartezeit-Meldungen (hung_task/io_wait) in 24h ({len(result['kernel_errors'])} Meldung(en))")
            if result["status"] == "OK":
                result["status"] = "WARNING"

    return result


# ==========================================
# 9. Gesamt-Bewertung (Severity)
# ==========================================
def evaluate_overall_severity(data: dict, thresholds: dict) -> tuple[str, list[str]]:
    reasons_crit = []
    reasons_warn = []

    # 1. Systemgesundheit
    health = data.get("system_health", {})
    if health.get("status") == "CRITICAL":
        reasons_crit.extend(health.get("warnings", []))
    elif health.get("status") == "WARNING":
        reasons_warn.extend(health.get("warnings", []))

    # 2. Updates
    os_up = data.get("os_updates", {})
    reboot = data.get("reboot", {})
    if os_up.get("security_upgrades", 0) > 0:
        reasons_crit.append(f"{os_up['security_upgrades']} Debian-Sicherheitsupdate(s) ausstehend")
    elif os_up.get("total_upgrades", 0) > 0:
        reasons_warn.append(f"{os_up['total_upgrades']} reguläre(s) Paketupdate(s) verfügbar")

    if reboot.get("required", False):
        reasons_crit.append("System-Neustart erforderlich (/run/reboot-required)")

    # 3. Dienste
    cs = data.get("critical_services", {})
    if cs.get("failed_critical"):
        reasons_crit.append(f"Kritischer Systemdienst inaktiv: {', '.join(cs['failed_critical'])}")

    failed_units = data.get("failed_services", [])
    if failed_units:
        reasons_crit.append(f"Abgestürzte Systemd-Dienste: {', '.join(failed_units)}")

    # 4. Container
    dock = data.get("docker", {})
    if len(dock.get("unhealthy", [])) > 0:
        names = [c["name"] for c in dock["unhealthy"]]
        reasons_crit.append(f"Docker Container 'unhealthy': {', '.join(names)}")
    if len(dock.get("exited", [])) > 0:
        names = [c["name"] for c in dock["exited"]]
        reasons_crit.append(f"Docker Container abgestürzt/beendet: {', '.join(names)}")

    image_updates = [img["image"] for img in data.get("docker_images", []) if img.get("status") == "UPDATE_AVAILABLE"]
    if image_updates:
        reasons_warn.append(f"{len(image_updates)} Docker-Image-Update(s) in Registry verfügbar")

    if data.get("docker_storage", {}).get("warning"):
        reasons_warn.append(data["docker_storage"]["warning"])

    # 5. Dateisystem
    fs = data.get("filesystem", {})
    if fs.get("status") == "CRITICAL":
        reasons_crit.extend(fs.get("warnings", []))
    elif fs.get("status") == "WARNING":
        reasons_warn.extend(fs.get("warnings", []))

    # 6. Firewall
    fw = data.get("firewall", {})
    if fw.get("status") == "CRITICAL":
        reasons_crit.extend(fw.get("warnings", []))
    elif fw.get("status") == "WARNING":
        reasons_warn.extend(fw.get("warnings", []))

    # 7. Sicherheitsvorfälle
    sec = data.get("security_incidents", {})
    if sec.get("status") == "CRITICAL":
        reasons_crit.extend(sec.get("warnings", []))
    elif sec.get("status") == "WARNING":
        reasons_warn.extend(sec.get("warnings", []))

    # 8. Fehlermeldungen
    errs = data.get("system_errors", {})
    if errs.get("status") == "CRITICAL":
        reasons_crit.extend(errs.get("warnings", []))
    elif errs.get("status") == "WARNING":
        reasons_warn.extend(errs.get("warnings", []))

    # Duplikate entfernen
    reasons_crit = list(dict.fromkeys(reasons_crit))
    reasons_warn = list(dict.fromkeys(reasons_warn))

    if reasons_crit:
        return "CRITICAL", reasons_crit + reasons_warn
    if reasons_warn:
        return "WARNING", reasons_warn
    return "OK", ["Alle Systeme, Dateisysteme, Daemons und Container laufen einwandfrei."]


# ==========================================
# 10. Berichterstattung (Markdown)
# ==========================================
def generate_markdown_report(data: dict, overall_status: str, reasons: list[str], timestamp: str) -> str:
    badge_map = {
        "OK": "🟢 **STATUS: OK** - Alle Systeme im grünen Bereich",
        "WARNING": "🟡 **STATUS: WARNUNG** - Aufmerksamkeit oder Wartung empfohlen",
        "CRITICAL": "🔴 **STATUS: KRITISCH** - Dringender Handlungsbedarf erforderlich",
    }

    md = []
    md.append(f"# 🛡️ Täglicher System- & Sicherheitsbericht: {data['hostname']}")
    md.append(f"**Prüfzeitpunkt:** `{timestamp}` | **Auslöser:** Täglicher Cronjob (06:30 Uhr)\n")
    md.append(f"### {badge_map.get(overall_status, overall_status)}\n")

    if reasons:
        md.append("#### 📌 Wichtigste Feststellungen:")
        for r in reasons:
            md.append(f"- {r}")
        md.append("")

    md.append("---\n")

    # 1. Systemgesundheit & Performance
    md.append("## 🩺 1. Systemgesundheit & Performance")
    sh = data.get("system_health", {})
    md.append(f"- **System-Uptime:** `{sh.get('uptime', 'unbekannt')}`")
    md.append(f"- **CPU-Auslastung:** `Load 1m: {sh.get('load_1', 0.0)}` | `5m: {sh.get('load_5', 0.0)}` | `15m: {sh.get('load_15', 0.0)}` ({sh.get('cores', 1)} CPU-Kerne, `{sh.get('load_per_core', 0.0)}` pro Kern)")
    md.append(f"- **Arbeitsspeicher (RAM):** `{sh.get('ram_used_mb', 0)} MB` von `{sh.get('ram_total_mb', 0)} MB` genutzt (**{sh.get('ram_percent', 0)}%**)")
    if sh.get("swap_total_mb", 0) > 0:
        md.append(f"- **Swap-Speicher:** `{sh.get('swap_used_mb', 0)} MB` von `{sh.get('swap_total_mb', 0)} MB` genutzt (**{sh.get('swap_percent', 0)}%**)")
    else:
        md.append("- **Swap-Speicher:** *Kein Swap konfiguriert*")

    if sh.get("oom_events"):
        md.append("\n🔴 **OOM-Killer Ereignisse (letzte 24h):**")
        for ev in sh["oom_events"][:3]:
            md.append(f"- `{ev}`")
    else:
        md.append("- **Kernel OOM-Killer:** 🟢 Keine OOM-Ereignisse festgestellt.")

    md.append("\n---\n")

    # 2. Betriebssystem & Updates
    md.append("## 📦 2. Betriebssystem & Paketaktualität (Debian 12)")
    os_up = data.get("os_updates", {})
    reboot = data.get("reboot", {})
    unatt = data.get("unattended", {})

    reboot_str = "🔴 **JA (Neustart erforderlich!)**" if reboot.get("required") else "🟢 Nein"
    md.append(f"- **Ausstehende Updates gesamt:** `{os_up.get('total_upgrades', 0)}`")
    md.append(f"- **Debian Sicherheitsupdates:** `{os_up.get('security_upgrades', 0)}`")
    md.append(f"- **System-Neustart erforderlich:** {reboot_str}")

    if reboot.get("packages"):
        md.append(f"  - Auslöser: `{', '.join(reboot['packages'])}`")

    if unatt.get("last_run"):
        pkgs_installed = f"({', '.join(unatt['packages_upgraded'])})" if unatt.get("packages_upgraded") else "(keine neuen Pakete)"
        md.append(f"- **Letzter Unattended-Upgrades Lauf:** `{unatt['last_run']}` {pkgs_installed}")

    if os_up.get("packages"):
        md.append("\n**Ausstehende Pakete:**")
        md.append("| Paket | Aktuell | Neu | Typ |")
        md.append("|---|---|---|---|")
        for p in os_up["packages"]:
            sec_tag = "🔴 **Sicherheit**" if p["is_security"] else "Regulär"
            md.append(f"| `{p['name']}` | `{p['current_version']}` | `{p['target_version']}` | {sec_tag} |")
    else:
        md.append("\n*Alle Betriebssystempakete sind aktuell.*")

    md.append("\n---\n")

    # 3. System-Dienste & Daemons
    md.append("## ⚙️ 3. System-Dienste & Daemons")
    cs = data.get("critical_services", {})
    failed_s = data.get("failed_services", [])

    if cs.get("services"):
        md.append("**Status der Kern-Dienste:**")
        md.append("| Dienst | Status | SubState | Restarts |")
        md.append("|---|---|---|---|")
        for s in cs["services"]:
            icon = "🟢 aktiv" if s["active"] else "🔴 INAKTIV"
            restart_str = f"⚠️ {s['restarts']}" if s["restarts"] > 0 else "0"
            md.append(f"| `{s['name']}` | {icon} | `{s['substate']}` | {restart_str} |")

    if failed_s:
        md.append(f"\n🔴 **Abgestürzte Systemd Units:** `{', '.join(failed_s)}`")
    else:
        md.append("\n- **Systemd Units:** 🟢 Alle Systemdienste laufen fehlerfrei (0 failed units).")

    md.append("\n---\n")

    # 4. Docker Container & Image-Aktualität
    md.append("## 🐳 4. Docker Container & Image-Aktualität")
    dock = data.get("docker", {})
    ds = data.get("docker_storage", {})
    md.append(f"- **Container Gesamt:** `{dock.get('total', 0)}` (Laufend: `{dock.get('running', 0)}`)")
    prob_count = len(dock.get("unhealthy", [])) + len(dock.get("exited", [])) + len(dock.get("restarting", []))
    md.append(f"- **Problematische Container:** `{prob_count}`")

    if dock.get("containers"):
        md.append("\n| Container | Status | Health | Image |")
        md.append("|---|---|---|---|")
        for c in dock["containers"]:
            h_icon = "🟢" if c["health"] == "healthy" else ("🟡" if c["health"] == "none" else "🔴")
            md.append(f"| `{c['name']}` | {c['status']} | {h_icon} {c['health']} | `{c['image']}` |")

    if data.get("docker_images"):
        md.append("\n**Registry-Aktualitätsprüfung der Images:**")
        md.append("| Image | Registry Status | Details |")
        md.append("|---|---|---|")
        for img in data["docker_images"]:
            st = img["status"]
            if st == "UPDATE_AVAILABLE":
                icon = "🟡 Update verfügbar"
            elif st == "UP_TO_DATE":
                icon = "🟢 Aktuell"
            else:
                icon = f"⚪ {st}"
            md.append(f"| `{img['image']}` | {icon} | {img['details']} |")

    if ds.get("available"):
        md.append("\n**Docker Storage Aufteilung:**")
        md.append(f"- **Build-Cache:** `{ds.get('build_cache_size', '0B')}`" + (" ⚠️ *(Prune empfohlen)*" if ds.get("warning") else ""))
        md.append(f"- **Images:** `{ds.get('images_size', '0B')}`")
        md.append(f"- **Volumes:** `{ds.get('volumes_size', '0B')}`")

    md.append("\n---\n")

    # 5. Dateisystem & Speicher-Integrität
    md.append("## 💾 5. Dateisystem & Speicher-Integrität")
    fs = data.get("filesystem", {})
    rd = fs.get("root_disk", {})
    inodes = fs.get("inodes", {})

    ro_badge = "🔴 **READ-ONLY (FEHLER!)**" if fs.get("is_read_only") else "🟢 Read-Write (Normal)"
    md.append(f"- **Festplatte `/`:** `{rd.get('used_gb', 0)} GB` von `{rd.get('total_gb', 0)} GB` belegt (**{rd.get('percent', 0)}%**)")
    md.append(f"- **Freier Speicherplatz:** `{rd.get('free_gb', 0)} GB`")
    if inodes:
        md.append(f"- **Inode-Belegung (`/`):** `{inodes.get('used', 0)}` von `{inodes.get('total', 0)}` (**{inodes.get('percent', 0)}%**)")
    md.append(f"- **Mount-Modus:** {ro_badge}")

    if fs.get("root_anomalies"):
        md.append("\n⚠️ **Unerwartete Ordner im Wurzelverzeichnis (`/`):**")
        for anom in fs["root_anomalies"]:
            md.append(f"- `/{anom}` *(Mögliches versehentliches Backup oder SCP-Fehler)*")
    else:
        md.append("- **Verzeichnis-Integrität:** 🟢 Keine unberechtigten oder verdächtigen Ordner auf `/`.")

    if fs.get("large_backups"):
        md.append("\n⚠️ **Große Backup-Dateien / Dumps gefunden:**")
        for lb in fs["large_backups"]:
            md.append(f"- `{lb}`")

    if fs.get("kernel_errors"):
        md.append("\n🔴 **Kernel Dateisystemfehler (letzte 24h):**")
        for ke in fs["kernel_errors"]:
            md.append(f"- `{ke}`")

    md.append("\n---\n")

    # 6. Firewall & Netzwerksicherheit
    md.append("## 🧱 6. Firewall & Netzwerksicherheit")
    fw = data.get("firewall", {})
    ports = data.get("ports", {})

    ipt_str = "🟢 Aktiv (openmediavault-firewall)" if fw.get("omv_firewall_active") else "⚪ Inaktiv"
    nft_str = "🟢 Aktiv" if fw.get("nftables_active") else "⚪ Inaktiv"
    ufw_str = "🟢 Aktiv" if fw.get("ufw_active") else "⚪ Inaktiv"
    md.append(f"- **Dienststatus:** `iptables`: {ipt_str} | `nftables`: {nft_str} | `ufw`: {ufw_str}")

    if fw.get("iptables_readable"):
        v4_drop = " (mit Catch-All DROP)" if fw.get("ipv4_has_catchall_drop") else ""
        md.append(f"- **IPv4 Regelwerk:** `{fw.get('ipv4_rules_count', 0)} Regeln aktiv` | Default-Policy: `{fw.get('ipv4_default_policy', 'unbekannt')}`{v4_drop}")
        v6_drop = " (mit Catch-All DROP)" if fw.get("ipv6_has_catchall_drop") else ""
        md.append(f"- **IPv6 Regelwerk:** `{fw.get('ipv6_rules_count', 0)} Regeln aktiv` | Default-Policy: `{fw.get('ipv6_default_policy', 'unbekannt')}`{v6_drop}")
    elif fw.get("omv_firewall_active"):
        md.append("- **Regelwerk:** 🟢 OpenMediaVault IPTables-Regelsatz aktiv geladen.")

    unique_pub_tcp = sorted(list(set(p["port"] for p in ports.get("public_tcp", []))))
    unique_pub_udp = sorted(list(set(p["port"] for p in ports.get("public_udp", []))))
    unique_loc_tcp = sorted(list(set(p["port"] for p in ports.get("localhost_tcp", []))))
    unique_vpn_tcp = sorted(list(set(p["port"] for p in ports.get("vpn_tcp", []))))

    md.append(f"- **Lauschende Ports auf Host (`0.0.0.0` / `::`):** `{len(unique_pub_tcp)}` TCP, `{len(unique_pub_udp)}` UDP")
    md.append(f"- **Nur lokal gebundene Ports (`127.0.0.1`):** `{len(unique_loc_tcp)}` TCP")
    if unique_vpn_tcp:
        md.append(f"- **Nur an VPN/LAN gebundene Ports:** `{len(unique_vpn_tcp)}` TCP (`{', '.join(str(p) for p in unique_vpn_tcp)}`)")

    if fw.get("sensitive_exposed_ports"):
        md.append("\n**Gefundene sensitive Ports & Firewall-Filterstatus:**")
        md.append("| Port | Dienst | Socket-Bindung | IPTables Schutzstatus | Bewertung / Empfehlung |")
        md.append("|---|---|---|---|---|")
        for sep in fw["sensitive_exposed_ports"]:
            md.append(f"| `{sep['port']}` | `{sep['service']}` | `0.0.0.0:{sep['port']}` | {sep.get('protection', 'Unbekannt')} | {sep['note']} |")

    md.append("\n---\n")

    # 7. Sicherheitsvorfälle & Authentifizierung
    md.append("## 🛡️ 7. Sicherheitsvorfälle & Authentifizierung")
    sec = data.get("security_incidents", {})
    ssh = sec.get("ssh", {})
    f2b = sec.get("fail2ban", {})
    sessions = sec.get("sessions", [])
    sudo_res = sec.get("sudo", {})
    root_u = sec.get("root_users", {})

    md.append("### SSH-Aktivität (letzte 24 Stunden)")
    md.append(f"- **Fehlgeschlagene Logins:** `{ssh.get('failed_attempts', 0)}`")
    md.append(f"- **Erfolgreiche Logins:** `{ssh.get('successful_logins', 0)}`")
    if ssh.get("root_login_detected"):
        md.append("- ⚠️ **Alarm:** Direkter Root-Login über SSH festgestellt!")

    if ssh.get("top_attackers"):
        md.append("\n**Top Angreifer-IPs:**")
        md.append("| IP-Adresse | Fehlversuche |")
        md.append("|---|---|")
        for ip, count in ssh["top_attackers"]:
            md.append(f"| `{ip}` | {count} |")

    md.append("\n### Fail2Ban & Abwehr")
    f2b_badge = "🟢 Aktiv" if f2b.get("active") else "🔴 Inaktiv"
    md.append(f"- **Dienststatus:** {f2b_badge}")
    md.append(f"- **Gesperrte IPs (Bans im Log):** `{f2b.get('recent_bans', 0)}`")
    if f2b.get("banned_ips"):
        md.append(f"  - Kürzlich gebannte IPs: `{', '.join(f2b['banned_ips'][:5])}`")

    md.append("\n### Sitzungen & Berechtigungen")
    if sessions:
        md.append(f"- **Aktive interaktive Benutzersitzungen ({len(sessions)}):**")
        for s in sessions:
            md.append(f"  - Benutzer `{s['user']}` an `{s['terminal']}` von `{s['host']}` (seit {s['time']})")
    else:
        md.append("- **Aktive interaktive Benutzersitzungen:** Keine aktiven Benutzer angemeldet.")

    md.append(f"- **Sudo-Fehlversuche (24h):** `{sudo_res.get('failed_attempts', 0)}`")
    md.append(f"- **Root-Konten (UID 0):** `{', '.join(root_u.get('root_accounts', []))}`")
    md.append(f"- **Sudo-Berechtigte Benutzer:** `{', '.join(root_u.get('sudo_users', []))}`")

    md.append("\n---\n")

    # 8. Fehlermeldungen & Systemprotokolle
    md.append("## ⚠️ 8. Fehlermeldungen & Systemprotokolle")
    errs = data.get("system_errors", {})
    md.append(f"- **Systemd-Journal Fehler (Priorität 0-3, letzte 24h):** `{errs.get('total_errors', 0)}` Ereignisse")

    if errs.get("top_error_patterns"):
        md.append("\n**Häufigste Fehlermuster im Journal:**")
        md.append("| Häufigkeit | Dienst / Fehlermeldung |")
        md.append("|---|---|")
        for pattern, count in errs["top_error_patterns"]:
            md.append(f"| `{count}x` | `{pattern}` |")
    else:
        md.append("\n🟢 *Keine kritischen Fehler im Systemd-Journal der letzten 24 Stunden verzeichnet.*")

    if errs.get("kernel_errors"):
        has_severe = any(any(t in ke.lower() for t in ["ext4", "corruption", "bad block", "i/o error", "hardware error", "segfault", "panic"]) for ke in errs["kernel_errors"])
        k_hdr = "🔴 **Kritische Kernel-Hardware- / Treiberfehler (letzte 24h):**" if has_severe else "⚠️ **Kernel I/O-Wartezeiten / Hung-Tasks (letzte 24h):**"
        md.append(f"\n{k_hdr}")
        for ke in errs["kernel_errors"][:3]:
            md.append(f"- `{ke}`")

    md.append("\n---\n")

    # 9. Empfohlene Maßnahmen
    md.append("## 💡 Empfohlene Maßnahmen")
    actions = []
    if os_up.get("security_upgrades", 0) > 0 or os_up.get("total_upgrades", 0) > 0:
        actions.append("Paketaktualisierungen einspielen: `sudo apt update && sudo apt upgrade`")
    if reboot.get("required"):
        actions.append("System neustarten, um Kernel-/System-Updates abzuschließen: `sudo reboot`")
    image_updates = [img["image"] for img in data.get("docker_images", []) if img.get("status") == "UPDATE_AVAILABLE"]
    if image_updates:
        actions.append("Docker Images aktualisieren: z.B. `docker pull <image>` oder `docker-compose pull && docker-compose up -d`")
    if cs.get("failed_critical"):
        for fcs in cs["failed_critical"]:
            actions.append(f"Kritischen Dienst neu starten: `sudo systemctl restart {fcs}`")
    if not f2b.get("active"):
        actions.append("Fail2Ban neu starten: `sudo systemctl restart fail2ban`")
    if ds.get("warning"):
        actions.append("Docker Build-Cache bereinigen: `docker builder prune -f`")
    if fs.get("root_anomalies"):
        actions.append(f"Unerwartete Ordner auf / prüfen & entfernen: {', '.join('/' + a for a in fs['root_anomalies'])}")
    if fs.get("large_backups"):
        actions.append(f"Alte/doppelte Backups prüfen & bereinigen: {', '.join(fs['large_backups'])}")
    if fw.get("sensitive_exposed_ports"):
        crit_ports = [str(sep["port"]) for sep in fw["sensitive_exposed_ports"] if sep["port"] in [139, 445, 5432, 3306]]
        if crit_ports:
            actions.append(f"Öffentliche Freigabe heikler Ports sperren: Ports {', '.join(crit_ports)}")

    if not actions:
        actions.append("Keine Maßnahmen erforderlich. Das System, alle Dateisysteme, Daemons und Container sind stabil.")

    for a in actions:
        md.append(f"1. {a}")

    md.append("\n*Automatischer Prüfbericht generiert durch `system_check.py`.*")
    return "\n".join(md) + "\n"


# ==========================================
# Main Execution
# ==========================================
def main():
    config = load_config()
    thresholds = config.get("thresholds", {})
    checks = config.get("checks", {})
    paths = config.get("paths", {})
    critical_services_list = config.get("critical_services", ["ssh", "docker", "fail2ban", "openmediavault-engined", "postfix", "cron"])

    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
    date_str = now.strftime("%Y-%m-%d_%H%M%S")

    log_dir = BASE_DIR / paths.get("log_dir", "logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    report_path = BASE_DIR / paths.get("latest_report", "latest_report.md")
    hist_log_path = log_dir / f"check_{date_str}.log"

    print(f"[{timestamp_str}] Starte erweiterte System-, Sicherheits- und Integritätsprüfung...")

    # Ports vorab ermitteln, da Firewall darauf zugreift
    ports_data = check_listening_ports() if checks.get("listening_ports", True) else {"public_tcp": [], "localhost_tcp": []}

    data = {
        "hostname": config.get("system", {}).get("hostname", "server01"),
        "system_health": check_system_health(thresholds) if checks.get("system_health", True) else {"status": "OK", "warnings": []},
        "os_updates": check_os_updates() if checks.get("os_updates", True) else {"total_upgrades": 0, "security_upgrades": 0, "packages": []},
        "unattended": check_unattended_upgrades() if checks.get("unattended_upgrades", True) else {"available": False},
        "reboot": check_reboot_required() if checks.get("reboot_required", True) else {"required": False, "packages": []},
        "critical_services": check_critical_services(critical_services_list) if checks.get("critical_services", True) else {"services": []},
        "failed_services": check_failed_services() if checks.get("failed_services", True) else [],
        "docker": check_docker_containers() if checks.get("docker_status", True) else {"available": False, "total": 0, "containers": []},
        "docker_images": [],
        "docker_storage": check_docker_storage(thresholds) if checks.get("docker_storage", True) else {"available": False},
        "filesystem": check_filesystem(thresholds) if checks.get("filesystem", True) else {"status": "OK", "warnings": []},
        "ports": ports_data,
        "firewall": check_firewall(ports_data) if checks.get("firewall", True) else {"status": "OK", "warnings": []},
        "security_incidents": check_security_incidents(thresholds) if checks.get("security_incidents", True) else {"status": "OK", "warnings": []},
        "system_errors": check_system_errors(thresholds) if checks.get("system_errors", True) else {"status": "OK", "warnings": []},
    }

    if checks.get("docker_image_updates", True) and data["docker"].get("containers"):
        print("Prüfe Docker Registry auf neuere Images...")
        data["docker_images"] = check_docker_image_updates(data["docker"]["containers"])

    overall_status, reasons = evaluate_overall_severity(data, thresholds)

    report_content = generate_markdown_report(data, overall_status, reasons, timestamp_str)

    # In latest_report.md schreiben
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    # In historisches Logfile schreiben
    with open(hist_log_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    # Log-Rotation (ältere Logs löschen)
    retention_days = config.get("system", {}).get("log_retention_days", 30)
    cutoff = now - datetime.timedelta(days=retention_days)
    for p in log_dir.glob("check_*.log"):
        try:
            mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime)
            if mtime < cutoff:
                p.unlink()
        except Exception:
            pass

    # Konsolenausgabe
    print(f"\n=======================================================")
    print(f" Prüfergebnis: [{overall_status}]")
    print(f"=======================================================")
    for r in reasons:
        print(f" - {r}")
    print(f"-------------------------------------------------------")
    print(f" Ausführlicher Bericht gespeichert in:")
    print(f" -> {report_path}")
    print(f" -> {hist_log_path}")
    print(f"=======================================================\n")

    if "--report" in sys.argv or "--mail" in sys.argv:
        print(report_content)

    return 0 if overall_status in ["OK", "WARNING"] else 1


if __name__ == "__main__":
    sys.exit(main())
