#!/usr/bin/env python3
"""
Server Manager — SSH-based server monitoring, vulnerability scanning, and management.
Reads credentials from config.json in the same directory.
"""

import json
import sys
import os
import re
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("paramiko not found. Install it with: pip install paramiko")
    sys.exit(1)


# ─────────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_server(config, name=None):
    servers = config["servers"]
    if not servers:
        raise ValueError("No servers defined in config.json")
    if name:
        for s in servers:
            if s["name"].lower() == name.lower():
                return s
        raise ValueError(f"Server '{name}' not found in config.json")
    return servers[0]


# ─────────────────────────────────────────────
# SSH connection
# ─────────────────────────────────────────────

def connect(server):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=server["host"],
        port=server.get("port", 22),
        username=server["username"],
        password=server.get("password"),
        key_filename=server.get("key_file"),
        timeout=10,
    )
    return client


def run(client, cmd, timeout=30):
    """Run a command and return (stdout, stderr, exit_code)."""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return out, err, code


def run_out(client, cmd, timeout=30):
    """Run a command and return stdout only."""
    out, _, _ = run(client, cmd, timeout=timeout)
    return out


# ─────────────────────────────────────────────
# OS detection
# ─────────────────────────────────────────────

def detect_os(client):
    out = run_out(client, "cat /etc/os-release 2>/dev/null || uname -a")
    if "ubuntu" in out.lower():
        return "ubuntu"
    if "debian" in out.lower():
        return "debian"
    if "centos" in out.lower() or "rhel" in out.lower() or "red hat" in out.lower():
        return "centos"
    if "rocky" in out.lower() or "alma" in out.lower():
        return "rocky"
    if "fedora" in out.lower():
        return "fedora"
    if "arch" in out.lower():
        return "arch"
    return "unknown"


def pkg_manager(os_type):
    if os_type in ("ubuntu", "debian"):
        return "apt"
    if os_type in ("centos", "rhel", "rocky", "fedora"):
        return "yum"
    return None


# ─────────────────────────────────────────────
# System overview
# ─────────────────────────────────────────────

def system_overview(client):
    print("\n" + "═" * 60)
    print("  SYSTEM OVERVIEW")
    print("═" * 60)

    hostname = run_out(client, "hostname -f 2>/dev/null || hostname")
    uptime = run_out(client, "uptime -p 2>/dev/null || uptime")
    kernel = run_out(client, "uname -r")
    os_info = run_out(client, "grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || uname -o")
    arch = run_out(client, "uname -m")

    print(f"  Hostname : {hostname}")
    print(f"  OS       : {os_info}")
    print(f"  Kernel   : {kernel} ({arch})")
    print(f"  Uptime   : {uptime}")

    # CPU
    cpu_model = run_out(client, "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'N/A'")
    cpu_cores = run_out(client, "nproc 2>/dev/null || grep -c processor /proc/cpuinfo")
    load = run_out(client, "cat /proc/loadavg | awk '{print $1, $2, $3}'")
    print(f"\n  CPU      : {cpu_model} ({cpu_cores} cores)")
    print(f"  Load avg : {load}")

    # Memory
    mem = run_out(client, "free -h | awk 'NR==2{printf \"Used: %s / Total: %s (Free: %s)\", $3, $2, $4}'")
    print(f"  Memory   : {mem}")

    # Disk
    print("\n  Disk Usage:")
    disk = run_out(client, "df -h --output=target,size,used,avail,pcent 2>/dev/null | grep -v tmpfs | grep -v udev | head -10")
    for line in disk.splitlines():
        print(f"    {line}")


# ─────────────────────────────────────────────
# Monitoring
# ─────────────────────────────────────────────

def monitor(client):
    print("\n" + "═" * 60)
    print("  REAL-TIME STATS")
    print("═" * 60)

    # Top processes by CPU
    print("\n  Top 10 processes by CPU:")
    procs = run_out(client, "ps aux --sort=-%cpu | head -11 | awk 'NR>1{printf \"  %-10s %-8s %-8s %s\\n\", $1, $3\"%\", $4\"%\", $11}'")
    print("  USER       CPU      MEM      CMD")
    print(procs)

    # Network connections
    print("\n  Active network connections (ESTABLISHED):")
    conns = run_out(client, "ss -tnp state established 2>/dev/null | head -20 || netstat -tnp 2>/dev/null | grep ESTABLISHED | head -20")
    print(conns if conns else "  (none or ss/netstat not available)")

    # Listening ports
    print("\n  Listening ports:")
    ports = run_out(client, "ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN")
    print(ports if ports else "  (none found)")


# ─────────────────────────────────────────────
# Vulnerability & Security Scan
# ─────────────────────────────────────────────

def vuln_scan(client, os_type=None):
    if not os_type:
        os_type = detect_os(client)
    pm = pkg_manager(os_type)

    print("\n" + "═" * 60)
    print("  VULNERABILITY & SECURITY SCAN")
    print("═" * 60)
    print(f"  OS: {os_type}  |  Package manager: {pm or 'unknown'}")
    print(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    issues = []

    # 1. Outdated packages
    print("  [1/8] Checking for outdated packages...")
    if pm == "apt":
        out = run_out(client, "apt list --upgradable 2>/dev/null | grep -v 'Listing' | wc -l")
        detail = run_out(client, "apt list --upgradable 2>/dev/null | grep -v 'Listing' | head -20")
    elif pm == "yum":
        out = run_out(client, "yum check-update 2>/dev/null | grep -v '^$' | grep -v '^Loaded' | grep -v '^Last' | wc -l")
        detail = run_out(client, "yum check-update 2>/dev/null | grep -v '^$' | grep -v '^Loaded' | grep -v '^Last' | head -20")
    else:
        out = "0"
        detail = ""
    count = out.strip()
    if count.isdigit() and int(count) > 0:
        issues.append(f"MEDIUM: {count} outdated packages")
        print(f"    ⚠  {count} packages can be upgraded")
        if detail:
            for line in detail.splitlines()[:5]:
                print(f"       {line}")
            if int(count) > 5:
                print(f"       ... and {int(count)-5} more")
    else:
        print("    ✓  All packages up to date")

    # 2. Open ports
    print("\n  [2/8] Scanning open ports...")
    ports_out = run_out(client, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    risky_ports = {"21": "FTP", "23": "Telnet", "25": "SMTP", "110": "POP3",
                   "143": "IMAP", "3306": "MySQL", "5432": "PostgreSQL",
                   "27017": "MongoDB", "6379": "Redis", "9200": "Elasticsearch"}
    found_risky = []
    for port, name in risky_ports.items():
        if f":{port}" in ports_out or f" {port} " in ports_out:
            found_risky.append(f"{port} ({name})")
    if found_risky:
        issues.append(f"HIGH: Exposed sensitive ports: {', '.join(found_risky)}")
        print(f"    ⚠  Sensitive ports exposed: {', '.join(found_risky)}")
    else:
        print("    ✓  No obviously risky ports detected")

    # 3. SSH root login
    print("\n  [3/8] Checking SSH root login...")
    ssh_cfg = run_out(client, "grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null")
    if "yes" in ssh_cfg.lower():
        issues.append("HIGH: SSH root login is permitted")
        print("    ⚠  PermitRootLogin is enabled — disable it in /etc/ssh/sshd_config")
    elif ssh_cfg:
        print(f"    ✓  {ssh_cfg.strip()}")
    else:
        print("    ?  Could not read sshd_config (may need root)")

    # 4. Password auth over SSH
    print("\n  [4/8] Checking SSH password authentication...")
    pw_auth = run_out(client, "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
    if "yes" in pw_auth.lower():
        issues.append("MEDIUM: SSH password authentication enabled (prefer key-based auth)")
        print("    ⚠  PasswordAuthentication yes — consider switching to key-based auth only")
    elif pw_auth:
        print(f"    ✓  {pw_auth.strip()}")
    else:
        print("    ?  Could not determine (may need root)")

    # 5. Users with empty passwords
    print("\n  [5/8] Checking for users with empty passwords...")
    empty_pw = run_out(client, "awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null")
    if empty_pw:
        issues.append(f"CRITICAL: Users with empty/locked passwords: {empty_pw}")
        print(f"    ⚠  Empty/locked passwords: {empty_pw}")
    else:
        print("    ✓  No users with empty passwords found")

    # 6. World-writable files (system dirs)
    print("\n  [6/8] Checking for world-writable files in /etc...")
    ww = run_out(client, "find /etc -type f -perm -o+w 2>/dev/null | head -10")
    if ww:
        issues.append(f"HIGH: World-writable files in /etc")
        print(f"    ⚠  World-writable /etc files:")
        for f in ww.splitlines():
            print(f"       {f}")
    else:
        print("    ✓  No world-writable files in /etc")

    # 7. Failed login attempts
    print("\n  [7/8] Checking recent failed login attempts...")
    failed = run_out(client, "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -5 || grep 'Failed password' /var/log/secure 2>/dev/null | tail -5")
    fail_count = run_out(client, "grep -c 'Failed password' /var/log/auth.log 2>/dev/null || grep -c 'Failed password' /var/log/secure 2>/dev/null || echo 0")
    if fail_count.strip().isdigit() and int(fail_count.strip()) > 0:
        n = int(fail_count.strip())
        severity = "HIGH" if n > 100 else "MEDIUM"
        issues.append(f"{severity}: {n} failed SSH login attempts in auth log")
        print(f"    ⚠  {n} failed login attempts found")
        if failed:
            for line in failed.splitlines()[-3:]:
                print(f"       {line}")
    else:
        print("    ✓  No failed login attempts found (or log not readable)")

    # 8. Sudo users
    print("\n  [8/8] Auditing sudo access...")
    sudo_users = run_out(client, "grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | head -20")
    sudo_group = run_out(client, "getent group sudo wheel 2>/dev/null")
    print("    Sudoers entries:")
    if sudo_users:
        for line in sudo_users.splitlines()[:10]:
            print(f"       {line}")
    if sudo_group:
        print(f"    Sudo/wheel group members: {sudo_group}")

    # Summary
    print("\n" + "─" * 60)
    print("  SCAN SUMMARY")
    print("─" * 60)
    if issues:
        for i, issue in enumerate(issues, 1):
            severity = issue.split(":")[0]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
            print(f"  {icon} {i}. {issue}")
    else:
        print("  ✅ No major issues detected!")
    print(f"\n  {len(issues)} issue(s) found.")


# ─────────────────────────────────────────────
# Service management
# ─────────────────────────────────────────────

def list_services(client):
    print("\n" + "═" * 60)
    print("  SERVICES")
    print("═" * 60)
    out = run_out(client, "systemctl list-units --type=service --state=running 2>/dev/null | head -30")
    if out:
        print(out)
    else:
        # Fallback for non-systemd
        out = run_out(client, "service --status-all 2>&1 | head -30")
        print(out)


def service_action(client, service, action):
    """Start, stop, restart, or status a service."""
    if action not in ("start", "stop", "restart", "status"):
        print(f"Unknown action: {action}. Use start, stop, restart, or status.")
        return
    out, err, code = run(client, f"systemctl {action} {service} 2>&1 || service {service} {action} 2>&1")
    print(out or err)
    return code == 0


def show_logs(client, service, lines=50):
    print(f"\n  Last {lines} log lines for {service}:")
    out = run_out(client, f"journalctl -u {service} -n {lines} --no-pager 2>/dev/null || tail -n {lines} /var/log/{service}/*.log 2>/dev/null || tail -n {lines} /var/log/syslog 2>/dev/null | grep {service}")
    print(out if out else "  (no logs found)")


# ─────────────────────────────────────────────
# User management
# ─────────────────────────────────────────────

def audit_users(client):
    print("\n" + "═" * 60)
    print("  USER AUDIT")
    print("═" * 60)

    # All login-capable users
    print("\n  Login-capable users (shell != nologin/false):")
    users = run_out(client, "grep -v '/nologin\\|/false' /etc/passwd | grep -v '^#' | cut -d: -f1,3,6,7")
    print(f"  {'Username':<20} {'UID':<8} {'Home':<25} {'Shell'}")
    print("  " + "-" * 65)
    for line in users.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            print(f"  {parts[0]:<20} {parts[1]:<8} {parts[2]:<25} {parts[3]}")

    # Last logins
    print("\n  Last logins:")
    lastlog = run_out(client, "last -n 10 2>/dev/null | head -12")
    print(lastlog if lastlog else "  (not available)")

    # Currently logged in
    print("\n  Currently logged in:")
    who = run_out(client, "who 2>/dev/null || w 2>/dev/null")
    print(who if who else "  (none)")

    # SSH authorized keys
    print("\n  SSH authorized keys:")
    keys = run_out(client, "find /home -name authorized_keys 2>/dev/null; cat /root/.ssh/authorized_keys 2>/dev/null | head -5")
    print(keys if keys else "  (none found or no permission)")


# ─────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────

HELP = """
Server Manager — available commands:

  overview                    System overview (hostname, CPU, memory, disk)
  monitor                     Real-time stats (top processes, ports, connections)
  scan                        Full vulnerability & security scan
  services                    List running services
  service <name> <action>     start | stop | restart | status a service
  logs <service> [lines]      Show service logs (default 50 lines)
  users                       Audit users, logins, and SSH keys
  help                        Show this message

Add --server <name> to target a specific server from config.json.

Examples:
  python server_manager.py overview
  python server_manager.py scan
  python server_manager.py service nginx restart
  python server_manager.py logs nginx 100
  python server_manager.py users
  python server_manager.py overview --server "My Server"
"""


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("help", "--help", "-h"):
        print(HELP)
        return

    # Parse --server flag
    server_name = None
    if "--server" in args:
        idx = args.index("--server")
        server_name = args[idx + 1]
        args = [a for i, a in enumerate(args) if i not in (idx, idx + 1)]

    cmd = args[0] if args else "overview"

    config = load_config()
    server = get_server(config, server_name)

    print(f"\n  Connecting to {server['name']} ({server['host']})...")
    try:
        client = connect(server)
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        sys.exit(1)
    print(f"  ✓ Connected\n")

    try:
        os_type = detect_os(client)

        if cmd == "overview":
            system_overview(client)

        elif cmd == "monitor":
            monitor(client)

        elif cmd == "scan":
            vuln_scan(client, os_type)

        elif cmd == "services":
            list_services(client)

        elif cmd == "service":
            if len(args) < 3:
                print("Usage: service <name> <start|stop|restart|status>")
            else:
                service_action(client, args[1], args[2])

        elif cmd == "logs":
            svc = args[1] if len(args) > 1 else "syslog"
            lines = int(args[2]) if len(args) > 2 else 50
            show_logs(client, svc, lines)

        elif cmd == "users":
            audit_users(client)

        else:
            print(f"Unknown command: {cmd}")
            print(HELP)

    finally:
        client.close()

    print()


if __name__ == "__main__":
    main()
