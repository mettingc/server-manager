# Server Manager Project

Claude uses this project to connect to, monitor, and scan remote servers over SSH.

## Files

- `config.json` — Server credentials and connection settings (fill this in before running)
- `server_manager.py` — Main script; all SSH operations live here
- `CLAUDE.md` — This file

## How to add a server

Edit `config.json` and add an entry to the `servers` array:

```json
{
  "name": "Descriptive Name",
  "host": "1.2.3.4",
  "port": 22,
  "username": "admin",
  "password": "yourpassword"
}
```

For key-based auth, omit `password` and add:
```json
"key_file": "/path/to/private.pem"
```

## Running commands

Install dependency first (one time):
```bash
pip install paramiko
```

Then run:
```bash
python server_manager.py overview          # System summary
python server_manager.py monitor           # Live stats + processes
python server_manager.py scan              # Full vulnerability scan
python server_manager.py services          # List running services
python server_manager.py service nginx restart
python server_manager.py logs nginx 100
python server_manager.py users             # User/login audit
```

Add `--server "Name"` to target a specific server when multiple are configured.

## What the scan covers

1. Outdated packages (apt/yum)
2. Risky open ports (FTP, Telnet, Redis, MongoDB, etc.)
3. SSH root login enabled
4. SSH password authentication
5. Users with empty/locked passwords
6. World-writable files in /etc
7. Failed SSH login attempts
8. Sudo access audit

## OS support

Auto-detected on connect. Supports Ubuntu, Debian, CentOS, RHEL, Rocky, Fedora.
Falls back gracefully on unknown systems.

## Notes for Claude

- Always read `config.json` to get the server list before attempting to connect
- Use `mcp__workspace__bash` to run `python server_manager.py <cmd>` in the shell
- The bash path for this folder is: `/sessions/.../mnt/Server Manager/`
- If the user says "check my server" or "run a scan", run `scan` then `overview`
- If the user asks about a specific service, use `service <name> status` or `logs <name>`
- Never hardcode credentials — always read from config.json
