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
# Wrapper log
# =============================================================================
# Jamf does not always keep a script's output in the policy log, so a failure
# before fumitm starts would otherwise leave no record on the Mac. The script
# therefore runs itself a second time with all output piped through tee. A
# pipeline, unlike process substitution, waits for tee to finish, so the file
# is complete when Jamf sees the exit code. If the log directory cannot be
# created, the script runs unlogged rather than failing.
if [[ -z "${FUMITM_WRAPPER_LOGGED:-}" ]] && /bin/mkdir -p "${LOG_DIR}" 2>/dev/null; then
    WRAPPER_LOG="${LOG_DIR}/selfservice-$(date '+%Y%m%d-%H%M%S').log"
    # errexit is off for the pipeline so that a tee failure cannot replace
    # the inner script's exit status with its own.
    set +e
    FUMITM_WRAPPER_LOGGED=1 /bin/bash "$0" "$@" 2>&1 | /usr/bin/tee -a "${WRAPPER_LOG}"
    exit "${PIPESTATUS[0]}"
fi

# =============================================================================
# Pre-flight: Python 3
# =============================================================================
# /usr/bin/python3 is a stub that hands off to Xcode or the Command Line Tools.
# On a Mac with Xcode installed whose licence has not been accepted, it exists
# but refuses to run (exit 69), so each candidate is tried rather than assumed.
# The Command Line Tools' own interpreter does not pass through that check.
PYTHON_CANDIDATES=(
    "${PYTHON}"
    /Library/Developer/CommandLineTools/usr/bin/python3
    /opt/homebrew/bin/python3
    /usr/local/bin/python3
)
PYTHON=""
for candidate in "${PYTHON_CANDIDATES[@]}"; do
    if [[ ! -x "${candidate}" ]]; then
        continue
    fi
    if "${candidate}" -c "import sys" >/dev/null 2>&1; then
        PYTHON="${candidate}"
        break
    fi
    log "Skipping ${candidate}: $("${candidate}" -c "import sys" 2>&1 | head -1 || true)"
done
if [[ -z "${PYTHON}" ]]; then
    bail "No working Python 3 found. Install the Xcode Command Line Tools, or accept the Xcode licence with 'sudo xcodebuild -license accept'." 20
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
    if ! "${PYTHON}" -c "import sys; compile(open(sys.argv[1], 'rb').read(), sys.argv[1], 'exec')" "${tmp_file}"; then
        /bin/rm -f "${tmp_file}"
        bail "Downloaded file has Python syntax errors (integrity check failed)." 31
    fi

    local version
    version=$(grep -m1 '__version__' "${tmp_file}" | sed 's/.*"\(.*\)".*/\1/' || true)
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
    local_version=$(grep -m1 '__version__' "${FUMITM_PATH}" | sed 's/.*"\(.*\)".*/\1/' || true)
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

# Under set -e a non-zero exit here would end the script before the summary
# below is printed, so the exit code is captured instead.
EXIT_CODE=0
"${PYTHON}" "${FUMITM_PATH}" \
    --fix \
    --yes \
    --headless \
    --provider "${PROVIDER}" \
    --run-as-user "${CONSOLE_USER}" \
    --log-dir "${LOG_DIR}" \
    --json-log-dir "${LOG_DIR}" || EXIT_CODE=$?

# =============================================================================
# Log cleanup — keep the last 30 log files of each type
# =============================================================================
"${PYTHON}" -c "
import os, glob
log_dir = '${LOG_DIR}'
for pattern in ('fumitm-[0-9]*.log', 'fumitm-[0-9]*.jsonl', 'selfservice-*.log'):
    files = sorted(glob.glob(os.path.join(log_dir, pattern)), reverse=True)
    for f in files[30:]:
        try:
            os.remove(f)
        except OSError:
            pass
" || true

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
