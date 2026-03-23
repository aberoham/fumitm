# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

fumitm (Fix Up My Interception of TLS, Man) is a Python script that automatically fixes TLS certificate trust issues caused by MITM proxies. It supports multiple providers — currently Cloudflare WARP and Netskope — and configures various development tools to trust the proxy's CA certificate.

## Key Commands

### Running the Script

```bash
# Check current certificate status (no changes made, auto-detects provider)
./fumitm.py

# Actually install/update certificates (makes changes)
./fumitm.py --fix

# Explicitly select a provider instead of auto-detecting
./fumitm.py --provider netskope
./fumitm.py --provider warp --fix

# Run with detailed debug output for troubleshooting
./fumitm.py --debug
./fumitm.py --debug --fix  # Debug mode with fixes

# Show help
./fumitm.py --help

# List all available tools and their tags
./fumitm.py --list-tools

# Non-interactive mode (answer yes to all prompts, for curl-pipe one-liners)
./fumitm.py --fix --yes

# Check/fix specific tools only
./fumitm.py --tools node --tools python  # Check Node.js and Python only
./fumitm.py --fix --tools node-npm,gcloud  # Fix Node.js/npm and gcloud only
./fumitm.py --fix --tools java,db  # Fix Java and database tools using tags

# Headless/MDM mode (JAMF, Ansible, Puppet)
./fumitm.py --fix --yes --headless --provider netskope
./fumitm.py --fix --yes --headless --run-as-user $USER --log-dir /var/log/fumitm

# Disable colors (also respects NO_COLOR=1 env var)
./fumitm.py --no-color

# Log to file or directory
./fumitm.py --log-file /tmp/fumitm.log
./fumitm.py --log-dir /var/log/fumitm --json-log-dir /var/log/fumitm
```

### Testing

The project has a pytest-based test suite in `test_suite/`:

```bash
# Run all tests
cd test_suite
uvx pytest test_fumitm_integration.py test_netskope_provider.py test_suspicious_bundles.py test_headless_mdm.py -v

# Run specific test files or classes
uvx pytest test_fumitm_integration.py::TestStatusFunctionContracts -v
uvx pytest test_fumitm_integration.py::TestCodeQuality -v
uvx pytest test_netskope_provider.py -v
```

Key test categories in `test_fumitm_integration.py`:
- **TestCertificateManagement**: Certificate download and validation
- **TestBrewCacerts**: Homebrew ca-certificates setup and status checking
- **TestToolSetup**: Tool-specific certificate setup workflows
- **TestStatusFunctionContracts**: Ensures all `check_*_status()` functions return booleans
- **TestCodeQuality**: Static analysis tests that enforce code standards:
  - No unsafe certificate appends (use `safe_append_certificate()`)
  - No unused global variables
  - Consistent messaging ("Configuring" not "Setting up")
  - No bare `except:` clauses (use `except Exception:`)
- **TestBundleCreation**: Tests for `create_bundle_with_system_certs()` helper
- **TestCertificateAppending**: Tests for safe PEM file handling (issue #13 fix)
- **TestPerformance**: Ensures subprocess call limits aren't exceeded
- **TestCertificateContentMatching**: Tests for pure-Python certificate matching
- **TestUpdateCheck**: Tests for the auto-update check functionality
- **TestGcloudVerification**: Tests for gcloud connectivity verification
- **TestOwnershipProtection**: Tests for sudo detection and file ownership correction

Key test categories in `test_netskope_provider.py`:
- **TestProviderDetection**: WARP and Netskope detection (cert files, encrypted certs, STAgent process)
- **TestProviderResolution**: Auto-detect priority, explicit override, invalid provider handling
- **TestNetskopeProviderConfig / TestNetskopeWarpProviderConfig**: Config propagation (cert_path, bundle_dir, keytool_alias, container_cert_name)
- **TestNetskopeGetCert**: Certificate retrieval (file read, keychain fallback with root + intermediate)
- **TestProviderCLI**: `--provider` argument parsing
- **TestCheckProviderConnection**: Provider-specific connection status checking

Key test categories in `test_headless_mdm.py`:
- **TestColorControl**: No color when `--no-color`, `NO_COLOR` env, `--headless`, non-TTY stdout
- **TestHeadlessFlag**: `--headless` disables color and update check, does NOT imply `--yes`
- **TestNonInteractiveError**: Non-TTY without `--yes` raises `NonInteractiveError`, exit code 2
- **TestLogFile**: `--log-file` and `--log-dir` text logging with timestamps and symlinks
- **TestJsonLogFile**: JSON-lines logging with schema validation
- **TestToolResultWrapper**: `_run_setup()` wraps legacy functions, error counting, exception handling
- **TestChangesmadeAccuracy**: `changes_made` is null/true/false based on ToolResult statuses
- **TestExitCodes**: 0 success, 1 hard failure, 2 non-interactive, 3 partial, 130 interrupted
- **TestRunAsUser**: `--run-as-user` user targeting, auto detection, root requirement
- **TestUserScopeGating**: User-scoped tools skipped without user context
- **TestSudoHelperUpdates**: Updated sudo helpers use `_target_uid`

## Architecture Overview

The script follows a modular architecture with these key components:

1. **Mode System**: Two modes - "status" (default, read-only) and "install" (with `--fix` flag)

2. **Provider System**: A config-dict abstraction (`PROVIDERS` dict in `fumitm.py`) that encapsulates per-provider differences (certificate paths, bundle directories, keytool aliases, container cert names, display names). The tool setup logic is identical across providers; only the data differs, so no class hierarchy is needed.
   - **Auto-detection**: checks WARP first (`warp-cli` on PATH), then Netskope (cert file at known path or STAgent process running). When both are detected, WARP is preferred.
   - **Explicit selection**: `--provider warp|netskope` overrides auto-detection.
   - Provider config flows through `self.provider` (the config dict), `self.cert_path`, and `self.bundle_dir` instance attributes.

3. **Certificate Management**:
   - **WARP**: Downloads certificate from `warp-cli certs`, stores at `~/.cloudflare-ca.pem`
   - **Netskope**: Reads from known file paths (`nscacert_combined.pem` preferred over `nscacert.pem`), with macOS keychain fallback extracting root (`-c "certadmin"`) and intermediate (`-c "goskope"`) CAs. Stores at `~/.netskope-ca.pem`. Detects encrypted `.enc` certs and directs users to `--cert-file`.
   - Checks for updates and certificate validity

4. **Tool-Specific Setup Functions**:
   - Each supported tool has its own `setup_*_cert()` function
   - Functions check current configuration before making changes
   - Handle permission issues by suggesting user-writable alternatives
   - Support for: Homebrew CA Certificates, Node.js/npm, Python, gcloud, Git, curl, Java/JVM, jenv, Gradle, DBeaver, wget, Docker (any backend), Podman, Rancher, Colima, Android Emulator
   - Tools can be selectively processed using `--tools` option with keys or tags
   - Container tools share a universal Docker VM cert installation method via nsenter (framework-agnostic)

5. **Certificate Helpers**:
   - `create_bundle_with_system_certs(path)`: Creates a CA bundle initialized with system certificates from `/etc/ssl/cert.pem` (macOS) or `/etc/ssl/certs/ca-certificates.crt` (Linux)
   - `safe_append_certificate(cert, target)`: Safely appends a certificate to a bundle file, ensuring proper PEM formatting
   - `certificate_exists_in_file()`: Checks if certificate already exists in bundle files (uses pure-Python string matching for O(1) performance)
   - `verify_connection()`: Tests if tools can connect through the proxy (supports node, python, curl, wget, gcloud)

6. **Docker VM Certificate Installation** (shared across all container tools):
   - `_install_cert_in_docker_vm()`: Installs the CA cert into the Docker VM's OS trust store via nsenter. Works with any Docker backend (OrbStack, Colima, Docker Desktop, Lima, etc.). Auto-detects Debian-style (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) vs Fedora-style (`/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`) cert paths inside the VM.
   - `_check_cert_in_docker_vm()`: Checks whether the cert exists in the VM (both Debian and Fedora paths).
   - `_restart_docker_in_vm()`: Restarts the Docker daemon, detecting the framework for the appropriate restart command (`orb restart docker`, `colima ssh -- sudo systemctl restart docker`, or generic nsenter fallback).
   - `_print_docker_build_hint()`: Prints Dockerfile guidance for build-time trust. Docker build containers use the base image's CA store (not the VM's), so users must inject the cert in their Dockerfile. Printed once after all container tools, not per-tool.
   - Podman keeps its own `podman machine ssh` fallback since Podman VMs don't always have Docker available.

7. **Ownership Protection and User Targeting** (sudo/JAMF/Ansible safety):
   - `_apply_target_user(username)`: Resolves username via `pwd.getpwnam()`, sets `_target_uid`/`_target_gid`, corrects `$HOME`. Supports `'auto'` for macOS console-user detection via `/dev/console` ownership.
   - `_detect_console_user()`: Static method that reads `/dev/console` ownership on macOS to find the GUI-session user.
   - `_is_running_as_sudo()` / `_get_real_user_ids()`: Detect sudo or `--run-as-user` context. Priority: `_target_uid` > `SUDO_UID` > current UID.
   - `_has_user_context()`: Returns True when a target user is resolved for user-scoped operations.
   - `_fix_ownership(path)`: Chowns home-directory files back to the real user; system paths are left untouched
   - `_safe_makedirs(path)`: Wraps `os.makedirs()` and chowns newly created directories; all setup functions use this instead of raw `os.makedirs()`
   - `check_ownership_sanity()`: Called early in `main()` — warns non-root users about root-owned files and proactively fixes ownership when running as sudo
   - User resolution priority: `--run-as-user` > `--run-as-user auto` > `SUDO_USER` > root-without-context (warn, system-only) > current user

8. **Status Checking**:
   - `check_all_status()`: Comprehensive status report of all configurations
   - Shows what needs fixing without making changes
   - Verifies actual connectivity before flagging issues (e.g., gcloud may work via system trust store without custom CA)

9. **Update Checking**:
   - `check_for_updates()`: Compares local file hash against GitHub main branch
   - Uses unverified SSL context (since WARP certificate trust might not be configured yet)
   - Warns users to update before running `--fix` if a newer version is available
   - Skipped when `--headless` or `--skip-update-check` is active

10. **Output Infrastructure** (headless/MDM support):
   - `_emit(message, level, ...)`: Central output method. All `print_*` methods route through it. Handles color stripping, text log writing, and JSON-lines event emission.
   - `_strip_ansi(text)`: Static method to remove ANSI escape codes.
   - `_open_log_files()` / `_close_log_files()`: Manage log file handles. File mode overwrites; directory mode generates timestamped filenames with `fumitm-latest.*` symlinks.
   - Color resolution: `--no-color` > `NO_COLOR` env > `--headless` > `sys.stdout.isatty()`
   - `NonInteractiveError`: Raised when `_prompt()` needs stdin but it's not a TTY. Caught in `main()` as exit code 2.
   - `--headless`: Composite flag that disables color and skips update check. Does NOT imply `--yes`.

11. **Idempotency and Exit Codes**:
    - `ToolResult`: Named tuple with `(tool, status, message)`. Statuses: `configured`, `already_ok`, `completed`, `skipped`, `failed`.
    - `_run_setup(tool_key, func)`: Wraps setup functions with error-counting side-channel via `print_error()`. Legacy functions that don't return `ToolResult` get `completed` or `failed` inferred.
    - `_print_summary(results)`: Prints human-readable summary and `FUMITM_RESULT:` JSON line for Ansible `changed_when`.
    - `_compute_changes_made(results)`: Returns `true` if any `configured`; `false` if no changes (all `already_ok`, all `skipped`, or empty); `null` if legacy `completed` makes state unknown.
    - Exit codes: 0 (success), 1 (hard failure), 2 (non-interactive input needed), 3 (partial success), 130 (interrupted).
    - Tool scope: each `tools_registry` entry has a `'scope'` key (`'system'`, `'user'`, `'hybrid'`). User-scoped tools are skipped when running as root without `--run-as-user`.

## Key Implementation Details

- Uses Python's exception handling for robust error management
- Preserves existing CA bundles by appending rather than replacing
- Handles multiple certificate formats and locations across different tools
- Provides user-friendly colored output with clear status indicators
- Supports both system-wide and user-specific certificate locations
- Detects and adapts to user's shell (bash, zsh, fish)
- Cross-platform Python implementation with proper type handling
- The global `CERT_PATH` constant is kept for backward compatibility but is unused internally; all class methods use `self.cert_path`
- All file writes to `$HOME` go through ownership-correcting helpers (`_fix_ownership`, `_safe_makedirs`) so that `sudo ./fumitm.py --fix` does not leave root-owned files behind

## Adding a New Provider

To add a new MITM proxy provider, add an entry to the `PROVIDERS` dict with the required keys (`name`, `short_name`, `cert_path`, `bundle_dir`, `keytool_alias`, `container_cert_name`), then implement `_detect_<provider>()` and `_get_<provider>_cert()` methods on `FumitmPython`. Update `_resolve_provider()` to include the new provider in the auto-detection chain, and add the provider name to the `--provider` CLI argument choices. The tool setup functions (`setup_*_cert`) are provider-agnostic and require no changes.

## Test Infrastructure Notes

- `FumitmTestCase.create_fumitm_instance()` defaults to `provider='warp'` to skip auto-detection, which would otherwise trigger subprocess calls (e.g. `pgrep`) that consume mock responses meant for the test's actual assertions.
- When testing auto-detection or provider resolution, instantiate `FumitmPython` directly with `provider=None` and mock the detection methods.
- `CERT_PATH` is listed in the `known_unused` set in `test_no_unused_globals_in_fumitm` since it's kept for backward compatibility but no longer referenced internally.