# Headless / MDM Deployment

fumitm supports JAMF Pro, Ansible, Puppet, and similar headless orchestration tools. This document covers the CLI flags, exit codes, logging, user targeting, and ready-to-use wrapper scripts for each orchestrator.

## CLI Flags

| Flag | Behavior |
|------|----------|
| `--headless` | Non-interactive mode: disables color, skips update check. Does NOT imply `--yes` (consent is separate from environment). Also activated by `FUMITM_HEADLESS=1` env var. |
| `--yes` / `-y` | Answer yes to all prompts. Required for unattended runs. |
| `--no-color` | Disable ANSI color output. Also respects `NO_COLOR=1` env var ([no-color.org](https://no-color.org/)). |
| `--log-file PATH` | Write plain-text log to exact file (overwrites each run). |
| `--log-dir DIR` | Write per-run text logs to DIR with `fumitm-latest.log` symlink. Recommended for JAMF. |
| `--json-log-file PATH` | Write JSON-lines event log to exact file (overwrites each run). |
| `--json-log-dir DIR` | Write per-run JSON-lines logs to DIR with `fumitm-latest.jsonl` symlink. |
| `--run-as-user USERNAME` | Configure certs for USERNAME's home directory (requires root). Use `auto` to detect console user on macOS. |
| `--skip-update-check` | Skip the GitHub update check (implied by `--headless`). |
| `--provider warp\|netskope` | Explicit provider selection (default: auto-detect). |

## Exit Codes

| Code | Meaning | Orchestrator guidance |
|------|---------|----------------------|
| `0` | Success — all tools configured or already OK | JAMF: policy completed. Ansible: check `FUMITM_RESULT:` for `changed_when`. Puppet: resource converged. |
| `1` | Hard failure — cert download failed, invalid args, or all tools failed | Retry or investigate. |
| `2` | Non-interactive input required but unavailable — missing `--yes` or `--cert-file` | Caller/config bug. Fix the invocation. |
| `3` | Partial success — some tools configured, some failed | Investigate failures; successes are stable. |
| `130` | Interrupted (Ctrl+C) | Re-run. |

Exit codes 2 and 3 are deliberately separate: exit 2 is always a caller/config problem (fixable without changing the target system), exit 3 is an operational partial (some tools need attention on the target).

## Machine-Parseable Output

In install mode (`--fix`), fumitm prints a `FUMITM_RESULT:` line to stdout after the install loop:

```
FUMITM_RESULT: {"changes_made":true,"configured":2,"completed":5,"already_ok":0,"skipped":3,"failed":1,"exit_code":3}
```

Fields:
- `changes_made`: `true` if any tool returned `configured`; `false` if no changes were made (all `already_ok`, all `skipped`, or no results); `null` if legacy `completed` statuses make change state unknown.
- `configured` / `completed` / `already_ok` / `skipped` / `failed`: per-status counts.
- `exit_code`: the exit code that will be returned.

Ansible `changed_when` must use `!= false` to treat `null` (unknown) as changed (conservative):

```yaml
changed_when: >
  (fumitm_result.stdout_lines | select('match', '^FUMITM_RESULT:')
   | first | regex_replace('^FUMITM_RESULT: ', '') | from_json).changes_made != false
```

## User Targeting

### The problem

JAMF runs scripts as root via launchd with `$HOME=/var/root` and no `SUDO_UID`. Without `--run-as-user`, fumitm would configure certificates for root's home directory instead of the logged-in user.

### Resolution priority

1. `--run-as-user USERNAME` — explicit, JAMF/Ansible/Puppet use this
2. `--run-as-user auto` — detects console user on macOS via `/dev/console` ownership
3. `SUDO_USER` env var — traditional `sudo ./fumitm.py` flow
4. Root without any user context — warns, continues with system-scoped work only
5. Current user (non-root default)

### Tool scope

Each tool in the registry has a scope that determines whether it runs without user context:

| Scope | Tools | Why |
|-------|-------|-----|
| System | `brew-cacerts` | Reads/writes system paths, not `$HOME` |
| User | `node`, `python`, `gcloud`, `git`, `curl`, `java`, `jenv`, `gradle`, `dbeaver`, `wget`, `android` | Write to `$HOME` (shell configs, env vars, user bundles) |
| Hybrid | `podman`, `rancher`, `colima` | Write to `~/.docker/certs.d/` and interact with user VMs |

When running as root without `--run-as-user` and without `SUDO_USER`, user-scoped and hybrid-scoped tools are skipped with a warning. System-scoped tools (cert download, detection, brew-cacerts) still run.

### Canonical identity mechanism per orchestrator

- **JAMF**: `--run-as-user "$3"` (JAMF provides console user as `$3`)
- **Ansible**: prefer `become_user` directive (Ansible handles user switching natively); `--run-as-user` as fallback
- **Puppet**: `user =>` parameter on `exec` resource; `--run-as-user` as fallback

## Logging

### Text logs

`--log-file PATH` writes to the exact file (overwrite mode). `--log-dir DIR` generates timestamped filenames (`fumitm-20260303-143000-12345.log`) and maintains a `fumitm-latest.log` symlink. Text logs are always ANSI-stripped with timestamps:

```
2026-03-03T14:30:00 [INFO] Configuring Node.js certificate...
2026-03-03T14:30:01 [ERROR] Failed to write to /usr/local/etc/node-ca.pem
```

### JSON-lines logs

`--json-log-file PATH` and `--json-log-dir DIR` work the same way as their text counterparts. Each line is a JSON object:

```json
{
  "ts": "2026-03-03T14:30:00Z",
  "level": "info",
  "phase": "tool",
  "tool": "node",
  "action": "set_env",
  "result": "changed",
  "message": "Set NODE_EXTRA_CA_CERTS",
  "error_code": null
}
```

Fields:
- `ts`: ISO-8601 UTC timestamp
- `level`: `info`, `warn`, `error`, `debug`
- `phase`: `init`, `detect`, `cert`, `tool`, `verify`, `summary` (currently only populated by summary events)
- `tool`: tool key from the registry, or null for non-tool phases
- `action`: what was attempted, or null
- `result`: `ok`, `changed`, `skipped`, `failed`, `warn`, or null
- `message`: human-readable description (ANSI-stripped)
- `error_code`: optional error identifier, or null

### Log retention

Keep the last 30 log files or 50 MB per host, whichever is smaller.

## JAMF Pro

A complete, production-ready JAMF Self Service script is available at [`examples/jamf-self-service.sh`](examples/jamf-self-service.sh). It handles downloading, caching, integrity checking, and running fumitm — no pre-deployment of `fumitm.py` required.

### Wrapper script

```bash
#!/bin/bash
# JAMF policy script — $1=mount point, $2=computer name, $3=console username
# Guard: $3 may be empty or "loginwindow" at DEP/pre-login.
# Note: $3 can be stale in some enrollment flows; --run-as-user auto
# is a fallback if $3 proves unreliable in your environment.
args=(--fix --yes --headless --provider netskope
      --log-dir /var/log/fumitm --json-log-dir /var/log/fumitm)

if [ -n "$3" ] && [ "$3" != "loginwindow" ]; then
    args+=(--run-as-user "$3")
fi

/usr/bin/python3 /path/to/fumitm.py "${args[@]}"
# Without --run-as-user, fumitm runs system-scope only (cert download, detection)
```

### Exit code handling

- Exit 0 = policy success in JAMF dashboard.
- Exit 1/2/3 = policy failure. Admin checks `fumitm-latest.*` in `--log-dir` on the endpoint.
- Exit 2 almost always means the JAMF script is misconfigured (missing `--yes` or `--cert-file`).

### Cleanup policy

Add a separate JAMF policy to prune old log files. macOS lacks GNU sort/tail, so use a Python one-liner that handles any filenames safely:

```bash
#!/bin/bash
# JAMF cleanup script — keep last 30 fumitm log files of each type
/usr/bin/python3 -c "
import os, glob
log_dir = '/var/log/fumitm'
for ext in ('log', 'jsonl'):
    files = sorted(glob.glob(os.path.join(log_dir, f'fumitm-*.{ext}')), reverse=True)
    for f in files[30:]:
        os.remove(f)
"
```

## Ansible

### Preferred: `become_user`

```yaml
- name: Configure MITM proxy certificates
  command: >
    /usr/bin/python3 /path/to/fumitm.py
    --fix --yes --headless --provider netskope
  become: true
  become_user: "{{ primary_user }}"
  register: fumitm_result
  changed_when: >
    (fumitm_result.stdout_lines | select('match', '^FUMITM_RESULT:')
     | first | regex_replace('^FUMITM_RESULT: ', '') | from_json).changes_made != false
  failed_when: fumitm_result.rc in [1, 2]
```

### Alternative: `--run-as-user`

```yaml
- name: Configure MITM proxy certificates
  command: >
    /usr/bin/python3 /path/to/fumitm.py
    --fix --yes --headless
    --run-as-user {{ primary_user }}
    --provider netskope
  register: fumitm_result
  changed_when: >
    (fumitm_result.stdout_lines | select('match', '^FUMITM_RESULT:')
     | first | regex_replace('^FUMITM_RESULT: ', '') | from_json).changes_made != false
  failed_when: fumitm_result.rc in [1, 2]
```

### Notes

- `failed_when: rc in [1, 2]` treats both hard failure (1) and caller/config bugs (2) as task failures. Exit 3 (partial success) is not treated as failure by default — add `3` to the list for strict all-or-nothing semantics.
- `changed_when` uses `!= false`: treats `null` (legacy/unknown) as changed (conservative), only reports unchanged when explicitly `false`.

## Puppet

```puppet
exec { 'fumitm-fix':
  command   => '/usr/bin/python3 /path/to/fumitm.py --fix --yes --headless --run-as-user ${user} --provider netskope',
  unless    => '/usr/bin/python3 /path/to/fumitm.py --headless --run-as-user ${user} --provider netskope',
  logoutput => on_failure,
}
```

- `unless` runs status mode (exit 0 = compliant, skip exec).
- Puppet retries naturally on exit 1/3 (every 30min by default).
- Exit 2 should be investigated as a manifest issue.

## Log Rotation (Ansible/Puppet)

Standard logrotate config:

```
/var/log/fumitm/*.log /var/log/fumitm/*.jsonl {
    rotate 30
    maxsize 5M
    missingok
    notifempty
    compress
}
```

## Environment Variables

| Variable | Equivalent |
|----------|-----------|
| `NO_COLOR=1` | `--no-color` ([no-color.org](https://no-color.org/)) |
| `FUMITM_HEADLESS=1` | `--headless` |

## Quick Reference

```bash
# JAMF one-liner
/usr/bin/python3 /path/to/fumitm.py --fix --yes --headless --provider netskope --run-as-user "$3" --log-dir /var/log/fumitm

# Ansible one-liner (with become_user)
/usr/bin/python3 /path/to/fumitm.py --fix --yes --headless --provider netskope

# Manual testing of headless behavior
sudo ./fumitm.py --fix --yes --headless --run-as-user $USER --debug
```
