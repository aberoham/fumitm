# Windows Refactoring Notes

This document tracks refactoring patterns applied to fumitm.py that should
also be applied to fumitm_windows.py for consistency.

## Known Unused Globals (Pending Cleanup)

The test suite has identified these unused global variables in fumitm_windows.py:

- `ALT_CERT_NAMES` - defined but never used
- `SHELL_MODIFIED` - defined but never used (class uses `self.shell_modified`)
- `CERT_FINGERPRINT` - defined but never used (class uses `self.cert_fingerprint`)

These are tracked in the test file with a `known_unused` set to avoid test failures
until the Windows refactoring is complete.

## Patterns to Apply

### 1. Dead Code Removal
- Delete unused globals listed above
- Check for dead functions not in registry (similar to `setup_curl_cert` in fumitm.py)

### 2. Helper Function Extraction (PR #29)
The `create_bundle_with_system_certs()` helper was implemented in fumitm.py:
- Centralizes system CA bundle detection logic
- Returns bool to indicate if system certs were found
- Windows equivalent needed with different system paths:
  - Windows doesn't have `/etc/ssl/cert.pem` or `/etc/ssl/certs/ca-certificates.crt`
  - May need to use Windows Certificate Store APIs or certifi package
  - Consider using `certifi.where()` if available

### 3. Message Standardization (PR #29)
- Changed 16 occurrences of "Setting up X certificate" to "Configuring X certificate"
- Apply same pattern to fumitm_windows.py for consistency
- Check with: `grep -n "Setting up" fumitm_windows.py`

### 4. Exception Handling (PR #29)
- Replaced 28 bare `except:` with `except Exception:` in fumitm.py
- Rationale: `except Exception:` catches all "normal" exceptions but allows:
  - `KeyboardInterrupt` (Ctrl+C) to propagate
  - `SystemExit` to propagate
- Apply same pattern to fumitm_windows.py
- Check with: `grep -n "except:" fumitm_windows.py | grep -v "Exception"`

### 5. Performance: Pure Python Certificate Matching (PR #30) — APPLIED
`certificate_exists_in_file()` now delegates to `certificate_likely_exists_in_file()`,
which compares whitespace-free base64 bodies with no subprocess calls. The old
install-mode fingerprint loop unlinked a `NamedTemporaryFile` while it was still
open, which Windows refuses (WinError 32), so it reported "missing" on every run
and appended another copy of the certificate each time (observed: three copies of
the Netskope root in one `python\ca-bundle.pem`). `append_certificate_if_missing()`
appends only the blocks the target lacks, so a root-only bundle gains the
intermediate without duplicating the root.

New regression tests added:
- `test_certificate_likely_exists_uses_no_subprocess`
- `test_no_subprocess_explosion_for_large_bundles`
- `test_safe_append_uses_fast_check`

### 6. Update Check Functionality (PR #31)
Added `check_for_updates()` method to compare local file hash against GitHub:
- Uses `ssl._create_unverified_context()` since WARP certificate might not be configured yet
- Fetches from `https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py`
- Compares SHA256 hashes and warns user if update is available
- Apply same pattern to fumitm_windows.py with appropriate URL

### 7. Connectivity-First Status Checks (PR #31)
The `check_gcloud_status()` function was improved to verify actual connectivity:
- **Before**: Flagged as issue if `core/custom_ca_certs_file` not configured
- **After**: First calls `verify_connection("gcloud")` to test actual connectivity
- If gcloud works (e.g., via system trust store), no issue is flagged
- Apply same pattern to fumitm_windows.py

Added `verify_connection("gcloud")` handler:
- Runs `gcloud config list --format=value(core.account)` to test connectivity
- Distinguishes SSL errors from other errors (non-SSL errors = connectivity OK)
- Handles timeout gracefully

## Windows-Specific Considerations

- Windows uses different system certificate paths
- Registry-based configuration differs from file-based
- Some tools have different installation patterns on Windows
- `winreg` module is Windows-only (tests skip on other platforms)

## Related Issues

- See #27 for curl handling discussion (applies to both platforms)
