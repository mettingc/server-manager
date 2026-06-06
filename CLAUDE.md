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

## GitHub Integration

Code is stored at https://github.com/mettingc/server-manager.

Claude pushes to this repo via the Nutrition OS Cloudflare Worker MCP at `https://nutrition.mettingc.workers.dev`.
The worker's `github_put_file`, `github_get_file`, `github_list_files`, and `github_delete_file` tools all accept an optional `repo` parameter — pass `"mettingc/server-manager"` to target this repo instead of the default nutrition-assistant repo.

The GitHub token is stored in `config.json` under `github.token` for reference, but Claude does NOT use it directly from the shell — all GitHub operations go through the Cloudflare Worker MCP.

`config.json` is gitignored and never committed to GitHub.

Example push:
```
github_put_file(path="server_manager.py", content="...", message="...", repo="mettingc/server-manager")
```

## Notes for Claude

- Always read `config.json` to get the server list before attempting to connect
- Use `mcp__workspace__bash` to run `python server_manager.py <cmd>` in the shell
- The bash path for this folder is: `/sessions/.../mnt/Server Manager/`
- If the user says "check my server" or "run a scan", run `scan` then `overview`
- If the user asks about a specific service, use `service <name> status` or `logs <name>`
- Never hardcode credentials — always read from config.json
- To push code changes to GitHub, use the Nutrition OS MCP tool `github_put_file` with `repo="mettingc/server-manager"` — do NOT attempt to use git or curl from the bash shell (the sandbox blocks outbound GitHub connections)
