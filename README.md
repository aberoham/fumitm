# fumitm (MITM Certificate .. Fixer Upper)

Script to automatically verify and fix MITM TLS distrust issues commonly afflicting corporate device users who are subject to traffic inspection via agents such as Cloudflare WARP or Netskope. ZScaler is not yet supported.

## Usage

### Linux/macOS

```bash
# Fix everything in one shot (no prompts, no download needed)
python3 <(curl -LsSf https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py) --fix --yes
source ~/.zshrc  # or ~/.bashrc
```

For more control, download the script first:

```bash
curl -LsSf https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py -o fumitm.py
chmod +x ./fumitm.py

# Check status (no changes made)
./fumitm.py

# Apply fixes (prompts before each change)
./fumitm.py --fix

# Run with detailed debug output (useful for troubleshooting)
./fumitm.py --debug

# List supported tools + tags (for use with --tools)
./fumitm.py --list-tools

# Fix only selected tools (keys and tags are both supported)
./fumitm.py --fix --tools brew-cacerts,node
./fumitm.py --fix --tools gcp --tools db

# Explicit provider selection (default is auto-detect)
./fumitm.py --fix --provider warp
./fumitm.py --fix --provider netskope

# Running in a devcontainer/WSL?
# See the "VS Code Devcontainers / WSL" section below.
```

### Windows

```powershell
# Download the Windows-specific script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm_windows.py" -OutFile "fumitm_windows.py"

# Check status (no changes made)
python fumitm_windows.py

# Apply fixes to all supported tools
python fumitm_windows.py --fix
```

## FU MITM Rational

When your organization runs a man-in-the-middle (MITM) gateway with TLS inspection enabled, the gateway intercepts and records virtually all HTTPS traffic for policy enforcement and security auditing. MITM gateways achieves this introspection by presenting their own root certificate to your TLS clients -- essentially performing sanctioned wiretapping on your TLS (aka SSL) connections.

Typically, MacOS and Windows themselves will automatically trust your MITM's certificate through system keychains. Most third-party development tools completely ignore these system certificates. Each tool maintains its own certificate bundle or looks for specific environment variables. This fragmentation creates endless annoying "certificate verify failed" errors across your toolchain whenever your MITM gateway's inspection is turned on.

One particularly annoying detail is that simply pointing tools to your organization's MITM gateway certificate by itself rarely works. You often need to append the custom MITM CA to an existing bundle of public CAs, which quickly becomes a brittle process that needs repeating for each tool. 

FU MITM!

## Don't Disable Your MITM

Whilst the quick temporary workaround might be to toggle your MITM gateway OFF, this is incredibly distressing to any nearby Information Security professionals who will one day need to forensically examine dodgy dependencies or MCPs that have slipped onto your laptop.

The act of toggling your MITM off also seriously hints that you have no clue what you're doing, as understanding TLS certificate-based trust is a critical concept underpinning modern vibe'n.

## Requirements

### General
- Cloudflare WARP or Netskope Client should be installed and connected
- `warp-cli` is needed for WARP flows. Netskope auto-detection uses known certificate paths or a running STAgent process (`nsdiag` is optional)
- Python 3 (macOS/Linux, Windows/WSL)

### Windows-Specific
- `warp-cli.exe` command must be available 
- Administrator privileges may be required for some fixes

## Contribute

Something amiss or not quite right? Please post the full output of a run to an issue or simply submit a PR

## List of supported fixes

### Linux/macOS
`./fumitm.py --list-tools` currently reports these Linux/macOS tool keys:
`brew-cacerts`, `node`, `python`, `gcloud`, `java`, `jenv`, `gradle`, `dbeaver`, `wget`, `podman`, `rancher`, `android`, `colima`, `git`, `curl`.

- **Homebrew CA Certificates (`brew-cacerts`)**: configures Homebrew's CA bundle (covers Homebrew OpenSSL consumers)
- **Node.js/npm**: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm
- **Python**: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables
- **gcloud**: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI
- **Git**: configures Git to use the custom certificate bundle via `http.sslCAInfo`
- **curl**: configures `CURL_CA_BUNDLE` environment variable for curl
- **Java/JVM**: adds the provider certificate to any found Java keystore (cacerts)
- **jenv**: adds the provider certificate to all jenv-managed Java installations
- **DBeaver**: targets the bundled JRE and adds the certificate to its keystore
- **wget**: configures the `ca_certificate` in the `.wgetrc` file
- **Podman**: installs certificate in `~/.docker/certs.d/` (persistent) and Podman VM's trust store (if running)
- **Rancher Desktop**: installs certificate in `~/.docker/certs.d/` (persistent) and Rancher VM's trust store (if running)
- **Colima**: installs certificate in `~/.docker/certs.d/` (persistent, applied on start) and Colima VM's trust store (if running)
- **Android Emulator**: helps install certificate on running Android emulators
- **Gradle**: sets `systemProp` entries in `gradle.properties` (respecting `GRADLE_USER_HOME`) for the provider certificate.
 
### Windows
- **Node.js/npm**: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm
- **Python**: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables
- **Google Cloud SDK (gcloud)**: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI
- **Java/JVM**: adds the provider certificate to any found Java keystore (cacerts)
- **wget**: configures the `ca_certificate` in the `.wgetrc` file
- **Podman**: installs certificate in Podman container runtime
- **Rancher Desktop**: installs certificate in Rancher Desktop Kubernetes environment
- **Git**: configures Git to use the custom certificate bundle via `http.sslCAInfo`
- **Windows Certificate Store**: installs the certificate in the Windows system certificate store

#### Windows-Specific Notes

The Windows version (`fumitm_windows.py`) includes Windows-specific functionality:

- Uses Windows Registry to locate certificates and configuration
- Handles Windows paths and file permissions
- Works with Windows-specific certificate stores
- Supports PowerShell environment variable management

### VS Code Devcontainers / WSL

Fumitm should auto-detect VS Code devcontainers and WSL environments where the provider CLI is only available on the underlying host. Within these environments, fumitm will guide you where to obtain your MITM cert and will skip slow verification tests.

If the cert cannot be pulled automatically from inside the container, use one of these flows:

```bash
# Use an existing cert file from your host/dev environment
./fumitm.py --fix --cert-file ./company-ca.pem --skip-verify

# Paste cert content manually
./fumitm.py --fix --manual-cert --skip-verify
```

## Headless / MDM Deployment

fumitm supports JAMF Pro, Ansible, Puppet, and similar headless orchestration tools.

### New Flags

| Flag | Behavior |
|------|----------|
| `--headless` | Non-interactive mode: disables color, skips update check. Does NOT imply `--yes`. |
| `--no-color` | Disable ANSI color output. Also respects `NO_COLOR=1` env var. |
| `--log-file PATH` | Write plain-text log to exact file (overwrites each run) |
| `--log-dir DIR` | Write per-run text logs to DIR with `fumitm-latest.log` symlink |
| `--json-log-file PATH` | Write JSON-lines event log to exact file (overwrites each run) |
| `--json-log-dir DIR` | Write per-run JSON-lines logs to DIR with `fumitm-latest.jsonl` symlink |
| `--run-as-user USERNAME` | Configure certs for USERNAME's home directory (requires root). Use `auto` to detect console user on macOS. |
| `--skip-update-check` | Skip the GitHub update check |

Environment variables: `FUMITM_HEADLESS=1` is equivalent to `--headless`.

### Exit Codes

| Code | Meaning | Use |
|------|---------|-----|
| `0` | Success (all configured or already OK) | JAMF: completed. Ansible: check `FUMITM_RESULT:` for `changed_when`. Puppet: converged. |
| `1` | Hard failure (cert download failed, invalid args, all tools failed) | Retry or investigate. |
| `2` | Non-interactive input required but unavailable (missing `--yes` or `--cert-file`) | Fix the invocation. |
| `3` | Partial success (some tools configured, some failed) | Investigate failures; successes are stable. |
| `130` | Interrupted (Ctrl+C) | Re-run. |

### Machine-Parseable Output

In install mode, fumitm prints a `FUMITM_RESULT:` line with JSON containing `changes_made` (true/false/null), per-status counts, and the exit code. Use this for Ansible `changed_when`.

### JAMF Pro

```bash
#!/bin/bash
# JAMF policy script — $3 is the console username
args=(--fix --yes --headless --provider netskope
      --log-dir /var/log/fumitm --json-log-dir /var/log/fumitm)

if [ -n "$3" ] && [ "$3" != "loginwindow" ]; then
    args+=(--run-as-user "$3")
fi

/usr/bin/python3 /path/to/fumitm.py "${args[@]}"
```

Without `--run-as-user`, fumitm runs system-scope only (cert download, detection). User-scoped tool configs (Node.js, Python, etc.) are skipped.

Log retention: keep the last 30 log files per host. Add a cleanup policy:

```bash
#!/bin/bash
/usr/bin/python3 -c "
import os, glob
log_dir = '/var/log/fumitm'
for ext in ('log', 'jsonl'):
    files = sorted(glob.glob(os.path.join(log_dir, f'fumitm-*.{ext}')), reverse=True)
    for f in files[30:]:
        os.remove(f)
"
```

### Ansible

Preferred approach using `become_user`:

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

Alternative using `--run-as-user`:

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

`changed_when` uses `!= false` so that `null` (legacy/unknown change status) is treated as changed (conservative).

### Puppet

```puppet
exec { 'fumitm-fix':
  command   => '/usr/bin/python3 /path/to/fumitm.py --fix --yes --headless --run-as-user ${user} --provider netskope',
  unless    => '/usr/bin/python3 /path/to/fumitm.py --headless --run-as-user ${user} --provider netskope',
  logoutput => on_failure,
}
```

`unless` runs status mode — exit 0 means compliant, skip the exec. Puppet retries naturally on exit 1/3.

### Log Retention

For Ansible/Puppet, use standard logrotate:

```
/var/log/fumitm/*.log /var/log/fumitm/*.jsonl {
    rotate 30
    maxsize 5M
    missingok
    notifempty
    compress
}
```

## Troubleshooting

If you encounter issues:

1. Ensure your MITM is connected: `warp-cli status` (WARP) or confirm Netskope Client/STAgent is running (`nsdiag -f` is optional)
2. Run with debug output: `./fumitm.py --debug` (Linux/macOS) or `python fumitm_windows.py --debug` (Windows)
3. Check that Python 3 is properly installed and in your PATH
4. Verify you have appropriate permissions for the tools you're trying to fix
