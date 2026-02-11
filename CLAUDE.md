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

# Check/fix specific tools only
./fumitm.py --tools node --tools python  # Check Node.js and Python only
./fumitm.py --fix --tools node-npm,gcloud  # Fix Node.js/npm and gcloud only
./fumitm.py --fix --tools java,db  # Fix Java and database tools using tags
```

### Testing

The project has a pytest-based test suite in `test_suite/`:

```bash
# Run all tests
cd test_suite
uvx pytest test_fumitm_integration.py test_netskope_provider.py test_suspicious_bundles.py -v

# Run specific test files or classes
uvx pytest test_fumitm_integration.py::TestStatusFunctionContracts -v
uvx pytest test_fumitm_integration.py::TestCodeQuality -v
uvx pytest test_netskope_provider.py -v
```

Key test categories in `test_fumitm_integration.py`:
- **TestCertificateManagement**: Certificate download and validation
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
   - Support for: Node.js/npm, Python, gcloud, Git, curl, Java/JVM, jenv, Gradle, DBeaver, wget, Podman, Rancher, Colima, Android Emulator
   - Tools can be selectively processed using `--tools` option with keys or tags

5. **Certificate Helpers**:
   - `create_bundle_with_system_certs(path)`: Creates a CA bundle initialized with system certificates from `/etc/ssl/cert.pem` (macOS) or `/etc/ssl/certs/ca-certificates.crt` (Linux)
   - `safe_append_certificate(cert, target)`: Safely appends a certificate to a bundle file, ensuring proper PEM formatting
   - `certificate_exists_in_file()`: Checks if certificate already exists in bundle files (uses pure-Python string matching for O(1) performance)
   - `verify_connection()`: Tests if tools can connect through the proxy (supports node, python, curl, wget, gcloud)

6. **Ownership Protection** (sudo safety):
   - `_is_running_as_sudo()` / `_get_real_user_ids()`: Detect sudo vs. real root login
   - `_fix_ownership(path)`: Chowns home-directory files back to the real user when running under sudo; system paths are left untouched
   - `_safe_makedirs(path)`: Wraps `os.makedirs()` and chowns newly created directories; all setup functions use this instead of raw `os.makedirs()`
   - `check_ownership_sanity()`: Called early in `main()` — warns non-root users about root-owned files and proactively fixes ownership when running as sudo
   - `$HOME` correction in `__init__`: On Linux, sudo may set `$HOME` to `/root`; the constructor detects this and repoints to the real user's home before any `expanduser` calls

7. **Status Checking**:
   - `check_all_status()`: Comprehensive status report of all configurations
   - Shows what needs fixing without making changes
   - Verifies actual connectivity before flagging issues (e.g., gcloud may work via system trust store without custom CA)

8. **Update Checking**:
   - `check_for_updates()`: Compares local file hash against GitHub main branch
   - Uses unverified SSL context (since WARP certificate trust might not be configured yet)
   - Warns users to update before running `--fix` if a newer version is available

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