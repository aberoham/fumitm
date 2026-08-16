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
uvx pytest test_fumitm_integration.py test_netskope_provider.py \
  test_suspicious_bundles.py test_headless_mdm.py test_curlrc.py \
  test_aikido_root.py -v

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

Key test categories in `test_aikido_root.py`:
- **TestAikidoDetection / TestAikidoCnFilter / TestAikidoRootExtraction**: Aikido discovery and root/intermediate selection
- **TestAikidoBundleAssembly / TestAikidoIdempotency / TestAikidoAbsentNoOp / TestVendorInjectedBundle**: additive bundle behavior and vendor-bundle boundaries
- **TestAikidoResolution / TestAikidoForcedSources / TestAikidoContainerStatus / TestAikidoBrewPostinstall**: source selection and tool-specific integration
- **TestAikidoPythonTrustVars / TestAikidoGcloudReauthTrust / TestAikidoWget / TestAikidoCertFileExpansion / TestMultiRootMatching**: downstream trust configuration and multi-root matching
- **TestAikidoDoctorPathSafety / TestCertFingerprints / TestAikidoAdoptionState**: trusted doctor resolution, and the two signals that establish adoption (record directory, or the root present in every built bundle)
- **TestAikidoAdoptRegistry / TestAikidoAdoptGating / TestAikidoAdoptIdempotency / TestAikidoAdoptDryRun / TestAikidoAdoptInvocation / TestAikidoAdoptNonInteractive / TestAikidoAdoptFailure / TestAikidoAdoptStatus**: adoption workflow, failure handling, and status contracts

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
   - **Aikido supplemental root** (`SUPPLEMENTAL_ROOTS` dict): auto-detected and added to every managed bundle alongside the primary provider root (`--with-aikido`/`--no-aikido`/`--aikido-cert`). Root retrieval prefers Aikido's dedicated `endpoint-protection-proxy-ca-crt.pem`, then uses the System Keychain and maintained combined bundle as fallbacks. The `aikido-adopt` registry tool is the forward path (macOS-only — Aikido's adoption record lives under `/Library/Application Support`, so elsewhere the step is skipped): on agents shipping the `aikido-doctor` CLI it runs `[sudo] aikido-doctor certconfig adopt <staged-root>`, with the doctor resolved to an absolute path through a root-ownership PATH check (sudo secure_path may not carry the user's PATH). `_trusted_system_executable` returns `(resolved, None)` or `(None, reason)`, and the reason is printed for a rejected candidate so that "absent" and "present but untrusted" stay distinguishable — conflating them once sent an investigation down the wrong path entirely. Every component must be root-owned and not world-writable. The **executable itself** is rejected if group-writable whatever the group, since anyone in that group could rewrite the bytes fumitm is about to run as root. Group-writability is tolerated only on **parent directories** whose group is in `PRIVILEGED_GROUPS` (wheel, admin): macOS ships `/Applications` as `root:admin drwxrwxr-x`, and rejecting that outright made every agent installed as an application bundle permanently undiscoverable, so the whole adoption step silently skipped on every stock Mac. That tolerance leaves a stated residual — directory write permission allows unlink-and-recreate, so an admin-group process can swap the validated binary between the check and the privileged execution; resolving the symlink narrows the window but does not close it, and the exposure is accepted because admin membership already confers sudo. `root:staff` (staff contains every local user) stays rejected.

     The provider root is staged into a private mkstemp copy (`_stage_adoption_cert`) so the user-writable cert file cannot be swapped between fumitm's checks and the privileged read. `_aikido_trusts_root` requires **both** signals:
     - **Every bundle Aikido builds carries the root** (`_aikido_bundles_missing`, which returns the laggards). The bundles are ground truth for whether trust exists right now, because they are what the tools Aikido configures actually read, and they must be checked as a set because they disagree — on an observed host the pip and node bundles carried the Netskope chain (130 certs, seeded from the System keychain) while the openssl and ruby bundles did not (128, seeded from Apple's static `/etc/ssl/cert.pem`), so the original single-bundle check reported success and skipped the adoption that would have fixed the other two. No adoption record excuses a lagging bundle: a root adopted once still vanishes from any bundle Aikido later rebuilds from a source lacking it.
     - **Aikido recorded it** (`adopted-cas/<sha256>.pem`, `_aikido_has_adopted`). Required because bundles alone cannot distinguish trust Aikido was told to keep from trust it happened to inherit — the keychain-seeded bundles hold the provider root already, and the next rebuild from any other source drops it. **One** recorded fingerprint suffices rather than all: a provider chain can carry an intermediate alongside its root (Netskope's does) and an intermediate that never earns its own record would otherwise deny adoption forever. Completeness is the bundles' question. The record is unanswerable (`None`) only when the certificates cannot be fingerprinted, and the bundles then decide alone.

     Both callers establish that the agent ships `aikido-doctor` **and that its CLI has the `adopt` subcommand** (`_aikido_doctor_supports_adopt`, cached per run) before consulting either signal, which is what makes "no record directory means nothing adopted" a safe reading. The capability is asked of `certconfig --help` — unprivileged, a few milliseconds, and it names its subcommands — rather than inferred, because the CLI answers an unknown subcommand with "Unknown command" on stdout and **exits zero**: an agent predating `certconfig` would sail past the return-code check and be caught only by the post-adopt verification, turning a host that previously reported `already_ok` into a hard failure on every scheduled run with no path back to green. The match is anchored to a listing line (`^\s+adopt\b`), since the help text also describes adoption in prose.

     `bundle_globs` is `endpoint-protection-*-combined-ca.pem` and `endpoint-protection-*-cafile.pem`; the **tool segment is what selects a maintained bundle**. Two neighbours look like bundles and are not maintained by `certconfig adopt`: `endpoint-protection-proxy-ca-crt.pem`, which holds Aikido's own root alone, and the legacy `endpoint-protection-combined-ca.pem`, observed six weeks stale at three certificates while every per-tool bundle was rewritten in the same adoption pass. Requiring the provider root in a file nothing maintains would deny trust permanently and re-run adoption on every invocation. `_aikido_built_bundles` lists the directory rather than globbing it, and answers `None` when it cannot be read. That case **fails closed** rather than masquerading as an agent that builds no bundles: deferring to the adoption record there would let a filesystem fault read as a healthy adoption, the one answer that leaves Aikido-backed tools broken while reporting success. Status reports the directory, and `setup_aikido_adopt` returns `skipped` without invoking the doctor — adopting blind would give no way to tell afterwards whether it took, and `failed` would go red on every scheduled run with nothing able to clear it, since the escalation covers the doctor invocation alone and fumitm never gains the privilege that would make the directory readable. A directory that is merely *absent* (`FileNotFoundError`) is a different fact and answers the empty list, the legacy shape the record covers; treating it as a fault failed every host without Aikido installed, CI included.

     Re-adopting converges, verified against agent 1.7.28: one `certconfig adopt` reinstalls every rule, took the openssl and ruby bundles from 128 to 130 certificates, and created the record directory in the same pass (Aikido writes it lazily on first adoption; filenames are the full SHA-256 though the CLI displays a truncated form). Post-adopt, a zero exit that left **no record** is a `failed` result, but a record with a bundle still behind is `configured` plus a warning naming the laggards — bundles are rebuilt by the agent rather than by the CLI's return, and failing on that would turn every scheduled MDM run red for a condition the next agent pass clears. The env-var reclaim, curlrc-override fix, and stub-last shell machinery remain as defense-in-depth for hosts where adopt hasn't run.

4. **Tool-Specific Setup Functions**:
   - Each supported tool has its own `setup_*_cert()` function
   - Functions check current configuration before making changes
   - Handle permission issues by suggesting user-writable alternatives
   - Support for: Homebrew CA Certificates, Node.js/npm, Python, gcloud, Git, curl, Java/JVM, jenv, Gradle, DBeaver, wget, Docker (any backend), Podman, Rancher, Colima, Android Emulator
   - Tools can be selectively processed using `--tools` option with keys or tags
   - Java-family keystore setup compares SHA-256 certificate identities from `keytool -list -rfc`; an existing vendor alias therefore satisfies idempotency. Alias checks are used only when the RFC listing is unavailable. When one of **fumitm's own** aliases holds a different certificate — the shape a provider root rotation takes, since the alias is stable across rotations and the certificate under it is not — the alias is **deleted and re-imported**, because keytool refuses to import over an occupied alias (`Certificate not imported, alias <name> already exists`, exit 1) and would otherwise report the same failure on every scheduled run with nothing able to clear it. A root another product installed is matched by fingerprint and never reaches this branch, so the deletion only ever touches fumitm's own entries. A failed delete prints the manual `keytool -delete` remedy in the same shape as the import-failure branch. Any failed root fails the whole keystore rather than only a keystore where nothing imported: a collision means the store actively holds the wrong certificate, which a sibling root importing cleanly must not mask.
   - Docker resolves its effective endpoint with `DOCKER_HOST` taking precedence over the current context. A matching Colima socket uses bounded native `colima ssh`; unknown backends use the generic nsenter path. The explicit Colima tool uses that selected profile, or the sole running named profile when Docker does not select one.

5. **Certificate Helpers**:
   - `create_bundle_with_system_certs(path)`: Creates a CA bundle initialized with system certificates from `/etc/ssl/cert.pem` (macOS) or `/etc/ssl/certs/ca-certificates.crt` (Linux)
   - `safe_append_certificate(cert, target)`: Safely appends a certificate to a bundle file, ensuring proper PEM formatting
   - `certificate_exists_in_file()`: Checks if certificate already exists in bundle files (uses pure-Python string matching for O(1) performance)
   - `verify_connection()`: Tests if tools can connect through the proxy (supports node, python, curl, wget, gcloud)

6. **Docker VM Certificate Installation** (shared across all container tools):
   - `_install_cert_in_docker_vm()`: Installs the CA cert into the Docker VM's OS trust store via nsenter. Works with any Docker backend (OrbStack, Colima, Docker Desktop, Lima, etc.). Auto-detects Debian-style (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) vs Fedora-style (`/etc/pki/ca-trust/source/anchors/` + `update-ca-trust`) cert paths inside the VM.
   - `_check_cert_in_docker_vm()`: Checks whether the cert exists in the VM (both Debian and Fedora paths).
   - `_effective_docker_endpoint()` / `_active_colima_profile_for_docker()`: Resolve the daemon selected by the Docker CLI and identify default or named Colima profiles from their socket path.
   - `_restart_docker_in_vm()`: Restarts the Docker daemon for unknown backends, detecting the framework for the appropriate restart command (`orb restart docker`, `colima ssh -- sudo systemctl restart docker`, or generic nsenter fallback). Active Colima backends and the explicit Colima tool use `_restart_docker_in_colima()` so another installed runtime cannot be restarted by mistake. Native Colima installation does not fall back to nsenter: that could target a different runtime and could need the registry trust being repaired.
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

12. **Shell Environment Configuration** (`add_to_shell_config`):
    - Exports live in one sourced file, `~/.config/fumitm/env.sh`, and each shell startup file gets a marker-delimited **source stub** re-emitted at the end of the file on every write. Because the stub is last, the env file's exports win by last-export-wins over any earlier vendor block (e.g. Aikido), without fumitm ever editing that block.
    - `get_shell_configs(shell_type)`: returns **every** startup file the shell reads, not just one. A shell reads a different set per invocation mode, so writing to only one leaves the others exposed to whatever a vendor block set.
      - zsh reads `.zshenv` → `.zprofile` (login) → `.zshrc` (interactive) → `.zlogin` (login), all from `$ZDOTDIR` when set, else `$HOME` (`_zsh_dotdir()`). fumitm stubs `.zshenv`, `.zshrc` and `.zlogin`, which covers all four modes; `.zlogin` lands after `.zprofile` so a vendor block there loses. **`.zprofile` is deliberately never edited** — it is vendor territory.
      - bash gets `.bashrc` plus the first existing of `.bash_profile`/`.bash_login`/`.profile` (creating `.bash_profile` if none exist), plus `.profile` when present so `/bin/sh` login shells are covered. `$BASH_ENV` is **not** set: it would run for every script on the system.
    - The classic failure this prevents: a non-interactive login shell (`zsh -lc`, used by many tool launchers) reads `.zprofile` but never `.zshrc`, so exports placed only in `.zshrc` are silently absent and TLS fails with `CERTIFICATE_VERIFY_FAILED` while the interactive terminal works fine.
    - **Migration**: an inline export block written by an older fumitm is hoisted into the env file and replaced in place by the stub. The merged set is always written back — never short-circuited on "value already correct" — because replacing a legacy block removes its exports from the startup file, so anything hoisted out of it must reach the env file or the setting is silently lost.
    - fish (and csh derivatives) keep the historical inline block via `_write_inline_block()`, since they cannot source POSIX-sh syntax. `_uses_env_file(shell_type)` gates the two paths.
    - `_read_text_or_none()` guards every read: `os.path.exists()` succeeding does not guarantee the open will (dangling symlink, permissions, races).

## Key Implementation Details

- Uses Python's exception handling for robust error management
- Preserves existing CA bundles by appending rather than replacing
- Handles multiple certificate formats and locations across different tools
- Provides user-friendly colored output with clear status indicators
- Supports both system-wide and user-specific certificate locations
- Detects and adapts to user's shell (bash, zsh, fish), writing to every startup file that shell reads (see Shell Environment Configuration above)
- Cross-platform Python implementation with proper type handling
- The global `CERT_PATH` constant is kept for backward compatibility but is unused internally; all class methods use `self.cert_path`
- All file writes to `$HOME` go through ownership-correcting helpers (`_fix_ownership`, `_safe_makedirs`) so that `sudo ./fumitm.py --fix` does not leave root-owned files behind

## Adding a New Provider

To add a new MITM proxy provider, add an entry to the `PROVIDERS` dict with the required keys (`name`, `short_name`, `cert_path`, `bundle_dir`, `keytool_alias`, `container_cert_name`), then implement `_detect_<provider>()` and `_get_<provider>_cert()` methods on `FumitmPython`. Update `_resolve_provider()` to include the new provider in the auto-detection chain, and add the provider name to the `--provider` CLI argument choices. The tool setup functions (`setup_*_cert`) are provider-agnostic and require no changes.

## Test Infrastructure Notes

- `FumitmTestCase.create_fumitm_instance()` defaults to `provider='warp'` to skip auto-detection, which would otherwise trigger subprocess calls (e.g. `pgrep`) that consume mock responses meant for the test's actual assertions.
- When testing auto-detection or provider resolution, instantiate `FumitmPython` directly with `provider=None` and mock the detection methods.
- `CERT_PATH` is listed in the `known_unused` set in `test_no_unused_globals_in_fumitm` since it's kept for backward compatibility but no longer referenced internally.
- **`isolate_home` in `conftest.py` is autouse**: it points `$HOME` at a throwaway directory and clears `$ZDOTDIR` for every test. fumitm resolves shell startup files and `~/.config/fumitm/env.sh` from `~` (or `$ZDOTDIR` for zsh), so a test that only passes a `tmp_path` config would otherwise write to the developer's real dotfiles. Tests needing a specific HOME/ZDOTDIR override it with `monkeypatch.setenv` afterwards. Do not remove this fixture.
- Tests asserting on managed exports should read `Path(instance._env_file_path()).read_text()`, not the shell config — the startup file carries only the source stub.
