#!/bin/bash
###############################################################################
# fumitm Self Service — Jamf Pro Script
#
# A self-contained script for Jamf Pro Self Service that downloads, caches,
# and runs fumitm.py to fix MITM certificate trust issues across developer
# tools (Node, Python, Git, curl, Java, etc.).
#
# This script does NOT require fumitm.py to already be on the Mac.
# It handles everything: download, integrity check, caching, execution,
# and log management.
#
# Jamf Parameters (auto-populated by Jamf):
#   $1 = Mount point of the policy (unused)
#   $2 = Computer name (unused)
#   $3 = Console username (logged-in user who triggered Self Service)
#
# Exit Codes (wrapper):
#  10   = No logged-in user detected (loginwindow / DEP / no session)
#  20   = Python 3 not available
#  30   = Failed to download fumitm.py from GitHub
#  31   = Downloaded file failed integrity check
#
# Exit Codes (fumitm passthrough):
#   0   = All certificate configurations applied successfully
#   1   = Hard failure (cert download failed, all tools failed)
#   2   = Config/invocation error (shouldn't happen with this wrapper)
#   3   = Partial success — some tools configured, some failed
#
# Author: jay-kay23 (https://github.com/aberoham/fumitm/issues/66)
###############################################################################

set -euo pipefail

# =============================================================================
# Configuration — adjust these if your environment differs
# =============================================================================
FUMITM_INSTALL_DIR="/usr/local/bin"
FUMITM_PATH="${FUMITM_INSTALL_DIR}/fumitm.py"
FUMITM_REPO="aberoham/fumitm"
FUMITM_BRANCH="main"
FUMITM_URL="https://raw.githubusercontent.com/${FUMITM_REPO}/${FUMITM_BRANCH}/fumitm.py"
PYTHON="/usr/bin/python3"
LOG_DIR="/var/log/fumitm"

# Provider: set to your org's MITM proxy. Hardcoding avoids auto-detect
# picking up a personal WARP install alongside corporate Netskope.
PROVIDER="netskope"

# How old (in hours) the cached copy can be before we attempt a refresh.
# Set to 0 to download every run. Set to 9999 to effectively never refresh.
CACHE_MAX_AGE_HOURS=2

# =============================================================================
# Helper functions
# =============================================================================
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }
bail() { err "$1"; exit "${2:-1}"; }

# =============================================================================
# Pre-flight: Python 3
# =============================================================================
if [[ ! -x "${PYTHON}" ]]; then
    PYTHON=$(command -v python3 2>/dev/null || true)
    if [[ -z "${PYTHON}" ]]; then
        bail "Python 3 is not installed. Install Xcode Command Line Tools or Homebrew Python." 20
    fi
fi
log "Using Python: ${PYTHON} ($("${PYTHON}" --version 2>&1))"

# =============================================================================
# Pre-flight: Logged-in user
# =============================================================================
CONSOLE_USER="${3:-}"

# If Jamf didn't pass a valid user, detect from /dev/console ownership.
# Also fall back when $3 is a UPN (user@domain.com) — Entra ID joined Macs
# report the UPN instead of the macOS short name in some enrollment flows.
if [[ -z "${CONSOLE_USER}" ]] \
    || [[ "${CONSOLE_USER}" == "loginwindow" ]] \
    || [[ "${CONSOLE_USER}" == *"@"* ]]; then
    log "Jamf \$3 is '${CONSOLE_USER:-<empty>}', falling back to /dev/console detection"
    CONSOLE_USER=$(/usr/bin/stat -f "%Su" /dev/console 2>/dev/null || true)
fi

# Final validation — Self Service needs a real user session.
if [[ -z "${CONSOLE_USER}" ]] \
    || [[ "${CONSOLE_USER}" == "root" ]] \
    || [[ "${CONSOLE_USER}" == "loginwindow" ]] \
    || [[ "${CONSOLE_USER}" == "_mbsetupuser" ]]; then
    bail "No valid logged-in user detected (got '${CONSOLE_USER:-<empty>}'). Self Service requires a user session." 10
fi

CONSOLE_USER_HOME=$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "${CONSOLE_USER_HOME}" ]]; then
    CONSOLE_USER_HOME="/Users/${CONSOLE_USER}"
fi

log "Console user: ${CONSOLE_USER} (home: ${CONSOLE_USER_HOME})"

# =============================================================================
# Pre-flight: Log directory
# =============================================================================
/bin/mkdir -p "${LOG_DIR}" 2>/dev/null

# =============================================================================
# Download / cache fumitm.py
# =============================================================================
download_fumitm() {
    local dest="$1"
    local tmp_file
    tmp_file=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/fumitm-download.XXXXXX") || bail "Cannot create temp file" 30

    log "Downloading fumitm.py from ${FUMITM_URL} ..."

    local http_code
    http_code=$(/usr/bin/curl \
        --silent \
        --show-error \
        --location \
        --fail \
        --connect-timeout 15 \
        --max-time 60 \
        --retry 2 \
        --retry-delay 3 \
        --output "${tmp_file}" \
        --write-out "%{http_code}" \
        "${FUMITM_URL}" 2>&1) || true

    if [[ ! -s "${tmp_file}" ]]; then
        /bin/rm -f "${tmp_file}"
        bail "Download failed (HTTP ${http_code}). Check network connectivity and that ${FUMITM_URL} is reachable." 30
    fi

    # Verify Python can parse it (syntax check only, no execution)
    if ! "${PYTHON}" -c "import sys, py_compile; py_compile.compile(sys.argv[1], doraise=True)" "${tmp_file}" 2>/dev/null; then
        /bin/rm -f "${tmp_file}"
        bail "Downloaded file has Python syntax errors (integrity check failed)." 31
    fi

    local version
    version=$(grep -m1 '__version__' "${tmp_file}" | sed 's/.*"\(.*\)".*/\1/' 2>/dev/null)
    log "Downloaded fumitm version: ${version:-unknown}"

    /bin/mkdir -p "$(/usr/bin/dirname "${dest}")" 2>/dev/null
    /bin/mv -f "${tmp_file}" "${dest}"
    /bin/chmod 755 "${dest}"

    log "Installed fumitm.py -> ${dest}"
}

needs_refresh() {
    local file="$1"

    [[ ! -f "${file}" ]] && return 0

    if [[ "${CACHE_MAX_AGE_HOURS}" -eq 0 ]]; then
        return 0
    fi

    local now file_mod age_seconds max_age_seconds
    now=$(/bin/date +%s)
    file_mod=$(/usr/bin/stat -f "%m" "${file}" 2>/dev/null || echo 0)
    age_seconds=$(( now - file_mod ))
    max_age_seconds=$(( CACHE_MAX_AGE_HOURS * 3600 ))

    if [[ "${age_seconds}" -gt "${max_age_seconds}" ]]; then
        log "Cached copy is $(( age_seconds / 3600 ))h old (threshold: ${CACHE_MAX_AGE_HOURS}h). Refreshing."
        return 0
    fi

    return 1
}

if needs_refresh "${FUMITM_PATH}"; then
    download_fumitm "${FUMITM_PATH}"
else
    local_version=$(grep -m1 '__version__' "${FUMITM_PATH}" | sed 's/.*"\(.*\)".*/\1/' 2>/dev/null)
    log "Using cached fumitm.py (version: ${local_version:-unknown})"
fi

if [[ ! -f "${FUMITM_PATH}" ]]; then
    bail "fumitm.py not found at ${FUMITM_PATH} after download attempt." 30
fi

# =============================================================================
# Run fumitm
# =============================================================================
log "=============================="
log " fumitm Self Service"
log " User:     ${CONSOLE_USER}"
log " Host:     $(/bin/hostname -s)"
log " Provider: ${PROVIDER}"
log "=============================="

"${PYTHON}" "${FUMITM_PATH}" \
    --fix \
    --yes \
    --headless \
    --provider "${PROVIDER}" \
    --run-as-user "${CONSOLE_USER}" \
    --log-dir "${LOG_DIR}" \
    --json-log-dir "${LOG_DIR}"

EXIT_CODE=$?

# =============================================================================
# Log cleanup — keep the last 30 log files of each type
# =============================================================================
"${PYTHON}" -c "
import os, glob
log_dir = os.environ.get('LOG_DIR', '${LOG_DIR}')
for ext in ('log', 'jsonl'):
    files = sorted(glob.glob(os.path.join(log_dir, f'fumitm-*.{ext}')), reverse=True)
    for f in files[30:]:
        try:
            os.remove(f)
        except OSError:
            pass
" 2>/dev/null

# =============================================================================
# Report result
# =============================================================================
case ${EXIT_CODE} in
    0)
        log "SUCCESS: All certificate configurations applied for ${CONSOLE_USER}."
        ;;
    1)
        log "FAILURE: Hard failure. Check ${LOG_DIR}/fumitm-latest.log for details."
        ;;
    2)
        log "FAILURE: Invocation/config error (exit 2). This is a bug in this wrapper script."
        ;;
    3)
        log "PARTIAL SUCCESS: Some tools configured, some failed. Check ${LOG_DIR}/fumitm-latest.log"
        ;;
    *)
        log "UNEXPECTED: fumitm exited with code ${EXIT_CODE}."
        ;;
esac

exit ${EXIT_CODE}
