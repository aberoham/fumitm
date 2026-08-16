#!/usr/bin/env python3

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

# Version and metadata
__description__ = "MITM Proxy Certificate Fixer Upper for macOS and Linux"
__author__ = "Ingersoll & Claude"
__version__ = "2026.8.16.2"  # CalVer: YYYY.MM.DD (auto-updated on release)


def parse_calver(version_str):
    """Make a comparable tuple from a CalVer version string.

    Args:
        version_str: A version such as "2025.12.18" or "2025.12.18.1".

    Returns:
        tuple: (year, month, day, patch). The patch is 0 for a base version.
    """
    parts = version_str.split('.')
    if len(parts) == 3:
        return (int(parts[0]), int(parts[1]), int(parts[2]), 0)
    elif len(parts) == 4:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    raise ValueError(f"Invalid CalVer format: {version_str}")


def get_version_info():
    """Get version information from Git."""
    version_info = {
        'version': 'unknown',
        'commit': 'unknown',
        'date': 'unknown',
        'branch': 'unknown',
        'dirty': False
    }
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=script_dir,
            capture_output=True,
            text=True, check=False
        )
        
        if result.returncode == 0:
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True, check=False
            )
            if result.returncode == 0:
                version_info['commit'] = result.stdout.strip()
            
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%cd', '--date=short'],
                cwd=script_dir,
                capture_output=True,
                text=True, check=False
            )
            if result.returncode == 0:
                version_info['date'] = result.stdout.strip()
            
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True, check=False
            )
            if result.returncode == 0:
                version_info['branch'] = result.stdout.strip()
            
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=script_dir,
                capture_output=True,
                text=True, check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['dirty'] = True
            
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                cwd=script_dir,
                capture_output=True,
                text=True,
                stderr=subprocess.DEVNULL, check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['version'] = result.stdout.strip()
            else:
                # There is no tag. Use the number of commits as the version.
                result = subprocess.run(
                    ['git', 'rev-list', '--count', 'HEAD'],
                    cwd=script_dir,
                    capture_output=True,
                    text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    count = result.stdout.strip()
                    version_info['version'] = f"0.{count}.0"
            
            if version_info['dirty'] and version_info['version'] != 'unknown':
                version_info['version'] += '-dirty'
    
    except Exception:
        # git is absent, or this is not a git repository.
        pass
    
    return version_info


# Get version info once at module load
VERSION_INFO = get_version_info()

# Colors for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

# Certificate details
CERT_PATH = os.path.expanduser("~/.cloudflare-ca.pem")
# Heuristics for detecting misconfigured bundles that replace trust stores
SMALL_BUNDLE_MAX_CERTS = 2
SMALL_BUNDLE_MAX_SIZE_BYTES = 50 * 1024  # 50KB

# The MITM proxies that fumitm supports. Only the certificate sources, the
# paths, and the display names change between providers.
PROVIDERS = {
    'warp': {
        'name': 'Cloudflare WARP',
        'short_name': 'WARP',
        'cert_path': '~/.cloudflare-ca.pem',
        'bundle_dir': '~/.cloudflare-warp',
        'keytool_alias': 'cloudflare-zerotrust',
        'container_cert_name': 'cloudflare-warp',
    },
    'netskope': {
        'name': 'Netskope',
        'short_name': 'Netskope',
        'cert_path': '~/.netskope-ca.pem',
        'bundle_dir': '~/.netskope',
        'keytool_alias': 'netskope-zerotrust',
        'container_cert_name': 'netskope',
        'cert_sources': {
            'Darwin': [
                '/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem',
                '/Library/Application Support/Netskope/STAgent/data/nscacert.pem',
            ],
            'Linux': ['/opt/netskope/stagent/data/nscacert.pem'],
        },
    },
}

# Groups whose write access to a root-owned directory gives no new privilege.
# macOS gives /Applications the mode root:admin drwxrwxr-x, and vendor agents
# install there. Members of admin can already use sudo. Members of staff are
# all local users, thus staff is not in this set. This applies to directories
# only. A group-writable executable is always rejected.
PRIVILEGED_GROUPS = frozenset({0, 80})  # wheel, admin

# Vendors that intercept some TLS connections above a primary provider. fumitm
# adds these roots to each managed bundle with the primary root. It does not
# replace the primary root. They stay out of PROVIDERS, thus _resolve_provider
# cannot return one.
SUPPLEMENTAL_ROOTS = {
    'aikido': {
        'name': 'Aikido Endpoint Protection',
        'short_name': 'Aikido',
        # The keychain label and the subject CN start with this text. The
        # suffix "- org-NNNNNN" changes, thus fumitm matches the prefix.
        'keychain_label_prefix': 'Aikido Endpoint Protection Root CA',
        'support_dir': '/Library/Application Support/AikidoSecurity/',
        'run_dir': (
            '/Library/Application Support/AikidoSecurity/EndpointProtection/run'
        ),
        # The agent writes its root alone here. Prefer this direct source over a
        # keychain search or extraction from a large per-tool bundle.
        'root_pem': (
            '/Library/Application Support/AikidoSecurity/EndpointProtection/'
            'run/endpoint-protection-proxy-ca-crt.pem'
        ),
        'combined_pem': (
            '/Library/Application Support/AikidoSecurity/'
            'EndpointProtection/run/endpoint-protection-pip-combined-ca.pem'
        ),
        # Aikido makes one bundle for each tool group, and the bundles are not
        # the same. Check all of them.
        #
        # The tool segment in the pattern selects the maintained bundles. Two
        # other files look like bundles, but `certconfig adopt` does not write
        # them: the proxy CA, and the legacy
        # endpoint-protection-combined-ca.pem. A check against an unmaintained
        # file can never succeed.
        'bundle_globs': (
            'endpoint-protection-*-combined-ca.pem',
            'endpoint-protection-*-cafile.pem',
        ),
        # Aikido writes one <sha256>.pem here for each CA that it adopts. The
        # name is the fingerprint that `adopt --forget` takes. Aikido makes
        # this directory at the first adoption, thus an absent directory shows
        # that Aikido adopted no CA.
        'adopted_dir': (
            '/Library/Application Support/AikidoSecurity/'
            'EndpointProtection/run/adopted-cas'
        ),
        'cert_path': '~/.aikido-ca.pem',
        'keytool_alias': 'aikido-root',
        'container_cert_name': 'aikido',
    },
}

class NonInteractiveError(Exception):
    """Raised when interactive input is needed but stdin is not a terminal."""


# Status values:
#   'configured'  - changed (explicit ToolResult return only)
#   'already_ok'  - no change needed (explicit ToolResult return only)
#   'completed'   - ran without errors, change status unknown (legacy wrapper)
#   'skipped'     - tool not installed or no user context
#   'failed'      - errors occurred
# Optional `changed` flag preserves explicit change state for partial failures.
ToolResult = namedtuple(
    'ToolResult', ['tool', 'status', 'message', 'changed'], defaults=[None]
)


class FumitmPython:
    # These markers enclose the block that fumitm manages in a shell startup
    # file. fumitm always writes the block at the end of the file. Thus its
    # settings replace the settings of an earlier vendor block.
    _FUMITM_BLOCK_BEGIN = "# >>> fumitm managed (keep last) >>>"
    _FUMITM_BLOCK_END = "# <<< fumitm managed <<<"

    # Shells that read POSIX sh syntax get one file with the exports. Each
    # startup file sources that file. The stub uses $HOME and not an expanded
    # path, thus it stays correct if the home directory moves.
    _FUMITM_ENV_FILE_REL = ".config/fumitm/env.sh"
    _FUMITM_ENV_FILE_SHELL = '"$HOME/.config/fumitm/env.sh"'

    def __init__(self, mode='status', debug=False, selected_tools=None,
                 cert_file=None, manual_cert=False, skip_verify=False,
                 provider=None, auto_yes=False, no_color=False,
                 headless=False, skip_update_check=False,
                 log_file=None, log_dir=None,
                 json_log_file=None, json_log_dir=None,
                 run_as_user=None, with_aikido=False, no_aikido=False,
                 aikido_cert_file=None):
        self.mode = mode
        self.debug = debug
        self.shell_modified = False
        # Shell config paths with a backup of the original file. A second
        # write in the same run must not replace that backup.
        self._backed_up_shell_configs = set()
        # Paths already reported in dry-run mode. A dry run writes nothing,
        # thus each variable finds the same pending changes. Report each file
        # one time.
        self._dry_run_reported = set()
        # The ZDOTDIR value that the zsh startup configuration sets. fumitm
        # reads an exported value at each call.
        self._queried_zsh_dotdir = None
        self.cert_fingerprint = ""
        self.selected_tools = selected_tools or []
        self.cert_file = cert_file
        # Kept raw and expanded at read time. --run-as-user and sudo change
        # HOME later in __init__. Thus a tilde path must not expand against
        # the home directory of root.
        self.aikido_cert_file = aikido_cert_file
        self.manual_cert = manual_cert
        self.skip_verify = skip_verify
        self.auto_yes = auto_yes
        self.headless = headless
        self.skip_update_check = skip_update_check

        # Color resolution: explicit flag > NO_COLOR env > headless > TTY
        if no_color or os.environ.get('NO_COLOR') is not None or headless:
            self._use_color = False
        else:
            self._use_color = sys.stdout.isatty()

        # Log file handles. _open_log_files opens them and _close_log_files
        # closes them. Directory mode makes a name with a timestamp and keeps
        # a "latest" symlink.
        self._log_file_handle = None
        self._json_log_file_handle = None
        self._log_file_path = log_file
        self._log_dir = log_dir
        self._json_log_file_path = json_log_file
        self._json_log_dir = json_log_dir

        # Error-counting side-channel for _run_setup()
        self._in_setup_context = False
        self._setup_error_count = 0
        self._current_tool_key = None
        # Cached. Status and install both ask, and the answer cannot change
        # during a run.
        self._aikido_adopt_supported = None

        # User targeting for JAMF, Ansible, and Puppet
        self._target_uid = None
        self._target_gid = None
        self._run_as_user = run_as_user

        # Apply user targeting before any expanduser calls
        if run_as_user:
            self._apply_target_user(run_as_user)
        elif os.getuid() == 0:
            # Under sudo on Linux, HOME can be /root and not the home
            # directory of the user. Correct it before any call to expanduser.
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                self._apply_target_user(sudo_user)
            else:
                # Root without any user context (e.g., JAMF launchd)
                self.print_warn(
                    "Running as root without --run-as-user. "
                    "User-scoped tool configs will be skipped."
                )

        # When provider is None, auto-detection examines WARP first, then
        # Netskope.
        self.provider = self._resolve_provider(provider)
        self.cert_path = os.path.expanduser(self.provider['cert_path'])
        self.bundle_dir = os.path.expanduser(self.provider['bundle_dir'])

        # Supplemental roots that go with the primary provider. Each entry is
        # a copy of a descriptor. _prepare_extra_roots adds a 'path' key when
        # it materializes the root certificate. The list is empty when fumitm
        # detects no supplemental root.
        self._extra_root_temp_files = []
        self._aikido_active = False
        self.extra_roots = self._resolve_extra_roots(with_aikido, no_aikido)

        # Scope controls what runs when root runs without --run-as-user.
        # A 'system' tool always runs. A 'user' tool needs HOME.
        self.tools_registry = {
            'aikido-adopt': {
                'name': 'Aikido CA Bundles',
                'tags': ['aikido', 'aikido-adopt', 'aikido-doctor', 'certconfig'],
                'setup_func': self.setup_aikido_adopt,
                'check_func': self.check_aikido_adopt_status,
                'description': "Aikido's own CA bundles (via aikido-doctor certconfig adopt)",
                'scope': 'system',
            },
            'brew-cacerts': {
                'name': 'Homebrew CA Certificates',
                'tags': ['brew', 'homebrew', 'ca-certificates', 'cacerts'],
                'setup_func': self.setup_brew_cacerts,
                'check_func': self.check_brew_cacerts_status,
                'description': 'Homebrew ca-certificates bundle (covers all Homebrew OpenSSL tools)',
                'scope': 'system',
            },
            'node': {
                'name': 'Node.js',
                'tags': ['node', 'nodejs', 'node-npm', 'javascript', 'js'],
                'setup_func': self.setup_node_cert,
                'check_func': self.check_node_status,
                'description': 'Node.js runtime and npm package manager',
                'scope': 'user',
            },
            'python': {
                'name': 'Python',
                'tags': ['python', 'python3', 'pip', 'requests'],
                'setup_func': self.setup_python_cert,
                'check_func': self.check_python_status,
                'description': 'Python runtime and pip package manager',
                'scope': 'user',
            },
            'gcloud': {
                'name': 'Google Cloud SDK',
                'tags': ['gcloud', 'google-cloud', 'gcp'],
                'setup_func': self.setup_gcloud_cert,
                'check_func': self.check_gcloud_status,
                'description': 'Google Cloud SDK (gcloud CLI)',
                'scope': 'user',
            },
            'java': {
                'name': 'Java/JVM',
                'tags': ['java', 'jvm', 'keytool', 'jdk'],
                'setup_func': self.setup_java_cert,
                'check_func': self.check_java_status,
                'description': 'Java runtime and development kit',
                'scope': 'user',
            },
            'jenv': {
                'name': 'jenv (Java Environment Manager)',
                'tags': ['jenv', 'java', 'jvm', 'jdk'],
                'setup_func': self.setup_jenv_cert,
                'check_func': self.check_jenv_status,
                'description': 'jenv-managed Java installations',
                'scope': 'user',
            },
            'gradle': {
                'name': 'Gradle',
                'tags': ['gradle'],
                'setup_func': self.setup_gradle_cert,
                'check_func': self.check_gradle_status,
                'description': 'Gradle build tool',
                'scope': 'user',
            },
            'dbeaver': {
                'name': 'DBeaver',
                'tags': ['dbeaver', 'database', 'db'],
                'setup_func': self.setup_dbeaver_cert,
                'check_func': self.check_dbeaver_status,
                'description': 'DBeaver database client',
                'scope': 'user',
            },
            'wget': {
                'name': 'wget',
                'tags': ['wget', 'download'],
                'setup_func': self.setup_wget_cert,
                'check_func': self.check_wget_status,
                'description': 'wget download utility',
                'scope': 'user',
            },
            'podman': {
                'name': 'Podman',
                'tags': ['podman', 'container', 'docker-alternative'],
                'setup_func': self.setup_podman_cert,
                'check_func': self.check_podman_status,
                'description': 'Podman container runtime',
                'scope': 'hybrid',
            },
            'rancher': {
                'name': 'Rancher Desktop',
                'tags': ['rancher', 'rancher-desktop', 'kubernetes', 'k8s', 'container'],
                'setup_func': self.setup_rancher_cert,
                'check_func': self.check_rancher_status,
                'description': 'Rancher Desktop Kubernetes',
                'scope': 'hybrid',
            },
            'android': {
                'name': 'Android Emulator',
                'tags': ['android', 'emulator', 'adb'],
                'setup_func': self.setup_android_emulator_cert,
                'check_func': self.check_android_status,
                'description': 'Android SDK emulator',
                'scope': 'user',
            },
            'colima': {
                'name': 'Colima',
                'tags': ['colima', 'container', 'vm'],
                'setup_func': self.setup_colima_cert,
                'check_func': self.check_colima_status,
                'description': 'Colima Docker runtime',
                'scope': 'hybrid',
            },
            'docker': {
                'name': 'Docker',
                'tags': ['docker', 'orbstack', 'docker-desktop', 'container', 'vm'],
                'setup_func': self.setup_docker_cert,
                'check_func': self.check_docker_status,
                'description': 'Docker VM trust (any backend: OrbStack, Colima, Docker Desktop, etc.)',
                'scope': 'hybrid',
            },
            'git': {
                'name': 'Git',
                'tags': ['git'],
                'setup_func': self.setup_git_cert,
                'check_func': self.check_git_status,
                'description': 'Git version control',
                'scope': 'user',
            },
            'curl': {
                'name': 'curl',
                'tags': ['curl', 'http'],
                'setup_func': self.setup_curl_cert,
                'check_func': self.check_curl_status,
                'description': 'curl HTTP client',
                'scope': 'user',
            },
            'aws': {
                'name': 'AWS CLI',
                'tags': ['aws', 'aws-cli', 'amazon', 'cloud'],
                'setup_func': self.setup_aws_cert,
                'check_func': self.check_aws_status,
                'description': 'AWS CLI (aws command)',
                'scope': 'user',
            },
        }
        
        if platform.system() != 'Darwin':
            self.print_warn("This script is designed for macOS. Most features will not work correctly.")

    def _resolve_provider(self, requested):
        """Select the MITM proxy provider.

        With no given provider, auto-detection examines WARP first, then Netskope.
        If both are present, fumitm uses WARP and reports that Netskope is also
        available.
        """
        if requested:
            if requested not in PROVIDERS:
                self.print_error(f"Unknown provider '{requested}'. Available: {', '.join(PROVIDERS)}")
                sys.exit(1)
            return PROVIDERS[requested]

        warp_detected = self._detect_warp()
        netskope_detected = self._detect_netskope()

        if warp_detected and netskope_detected:
            self.print_info("Both Cloudflare WARP and Netskope detected; defaulting to WARP")
            self.print_info("Use --provider netskope to use Netskope instead")
            return PROVIDERS['warp']
        if warp_detected:
            return PROVIDERS['warp']
        if netskope_detected:
            return PROVIDERS['netskope']

        # fumitm found no provider. Use WARP, thus the messages about a
        # missing warp-cli stay correct.
        return PROVIDERS['warp']

    def _path_belongs_to_other_provider(self, path):
        """Find if a path is in the bundle directory of a different provider.

        Returns the display name of the other provider, or None.
        """
        for config in PROVIDERS.values():
            other_dir = os.path.expanduser(config['bundle_dir'])
            if other_dir == self.bundle_dir:
                continue
            if path.startswith(other_dir + os.sep):
                return config['name']
        return None

    def _is_vendor_injected_bundle(self, path):
        """Return True if the path is in the directory of a supplemental-root vendor.

        The vendor keeps this bundle current and sets it in the environment. fumitm
        must not use, change, or move it. fumitm keeps its own bundle. To add a root
        to the bundle of the vendor, use the tooling of the vendor. See
        setup_aikido_adopt.
        """
        for descriptor in SUPPLEMENTAL_ROOTS.values():
            support_dir = descriptor.get('support_dir')
            if support_dir and path.startswith(support_dir):
                return True
        return False

    def _detect_warp(self):
        """Return True if Cloudflare WARP appears to be installed."""
        return shutil.which('warp-cli') is not None

    def _detect_netskope(self):
        """Return True if Netskope is installed.

        Examines the known certificate paths first, then looks for the process. The
        client is "Netskope Client" on macOS and STAgent on Linux.
        """
        plat = platform.system()
        cert_sources = PROVIDERS['netskope'].get('cert_sources', {}).get(plat, [])
        for path in cert_sources:
            if os.path.exists(path):
                return True

        for path in cert_sources:
            if os.path.exists(path + '.enc'):
                return True

        # Fall back to process check with platform-appropriate process name
        try:
            proc_pattern = 'Netskope Client' if plat == 'Darwin' else 'STAgent'
            result = subprocess.run(
                ['pgrep', '-f', proc_pattern],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return True
        except Exception:
            pass

        return False

    def _resolve_extra_roots(self, with_aikido, no_aikido):
        """Select the supplemental root CAs for this run.

        A supplemental root applies when the operator forces it on, or when fumitm
        detects it and the operator does not force it off. Returns a list of
        descriptor copies. Each copy has its registry key.
        """
        active = []
        # Aikido is the only supplemental root now. A given certificate file
        # makes Aikido active, as --with-aikido does.
        aikido_forced_off = no_aikido
        aikido_forced_on = with_aikido or bool(self.aikido_cert_file)
        aikido_active = aikido_forced_on or (not aikido_forced_off and self._detect_aikido())
        self._aikido_active = aikido_active
        if aikido_active:
            entry = dict(SUPPLEMENTAL_ROOTS['aikido'])
            entry['key'] = 'aikido'
            active.append(entry)
        return active

    def _detect_aikido(self):
        """Return True if Aikido Endpoint Protection is present.

        One of these is sufficient: the AikidoSecurity directory is present, or the
        System Keychain holds a certificate with the Aikido root CA prefix in its
        label. fumitm ignores the suffix of the label. The root and combined PEMs
        are children of the support directory, so separate file checks are
        redundant.
        """
        descriptor = SUPPLEMENTAL_ROOTS['aikido']
        if os.path.isdir(descriptor['support_dir']):
            return True

        if platform.system() == 'Darwin':
            try:
                result = subprocess.run(
                    ['security', 'find-certificate', '-c',
                     descriptor['keychain_label_prefix'],
                     '/Library/Keychains/System.keychain'],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    return True
            except Exception as e:
                self.print_debug(f"Aikido keychain detection failed: {e}")

        return False

    def _get_aikido_root_cert(self):
        """Get the Aikido root CA certificates as PEM text.

        fumitm tries these sources in this sequence: a file that the operator gives
        with ``--aikido-cert``, the dedicated root PEM of the agent, the macOS
        System Keychain, a maintained combined PEM, and a root that an earlier run
        kept. The first source and the last source let ``--with-aikido`` succeed on
        a host with no Aikido agent, such as a CI image. fumitm keeps only the
        certificates whose subject CN starts with the Aikido root prefix. This
        removes the interception intermediate, which has a hexadecimal CN and a
        short life.

        Returns:
            str or None: PEM text with the Aikido roots, or None.
        """
        descriptor = SUPPLEMENTAL_ROOTS['aikido']
        prefix = descriptor['keychain_label_prefix']

        # Source 1: a file that the operator gives. Use this to force Aikido
        # on a host with no agent and no keychain entry. A failure here is
        # reported and does not fall through.
        if self.aikido_cert_file:
            cert_path = os.path.expanduser(self.aikido_cert_file)
            pem = self._read_aikido_root_from_file(cert_path, prefix)
            if pem:
                self.print_info(f"Using Aikido root CA from {cert_path}")
                return pem
            self.print_warn(f"No Aikido root CA found in {cert_path}")

        # Source 2: the dedicated single-certificate file of the live agent.
        pem = self._read_aikido_root_from_file(descriptor['root_pem'], prefix)
        if pem:
            self.print_info(f"Using Aikido root CA from {descriptor['root_pem']}")
            return pem

        # Source 3: macOS System Keychain, all matching certs by label prefix.
        if platform.system() == 'Darwin':
            try:
                result = subprocess.run(
                    ['security', 'find-certificate', '-a', '-c', prefix, '-p',
                     '/Library/Keychains/System.keychain'],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and '-----BEGIN CERTIFICATE-----' in result.stdout:
                    roots = self._filter_certs_by_cn_prefix(result.stdout, prefix)
                    if roots:
                        self.print_info("Using Aikido root CA from macOS System Keychain")
                        return '\n'.join(roots)
            except Exception as e:
                self.print_debug(f"Aikido keychain extraction failed: {e}")

        # Source 4: maintained combined PEM written by the live Aikido agent.
        pem = self._read_aikido_root_from_file(descriptor['combined_pem'], prefix)
        if pem:
            self.print_info(f"Using Aikido root CA from {descriptor['combined_pem']}")
            return pem

        # Source 5: a root that an earlier fumitm run kept. This keeps
        # --with-aikido usable after the agent is removed.
        persisted = os.path.expanduser(descriptor['cert_path'])
        pem = self._read_aikido_root_from_file(persisted, prefix)
        if pem:
            self.print_info(f"Using previously saved Aikido root CA from {persisted}")
            return pem

        self.print_warn("Could not extract Aikido root CA; skipping supplemental trust")
        return None

    def _read_aikido_root_from_file(self, path, cn_prefix):
        """Read Aikido root PEM text from a file, or return None.

        Keeps only the certificate blocks whose subject CN starts with ``cn_prefix``
        and returns them as PEM text. Returns None if the file is absent or
        unreadable, or if it has no matching root.
        """
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, 'r') as f:
                roots = self._filter_certs_by_cn_prefix(f.read(), cn_prefix)
            if roots:
                return '\n'.join(roots)
        except Exception as e:
            self.print_debug(f"Could not parse Aikido root from {path}: {e}")
        return None

    def _filter_certs_by_cn_prefix(self, pem_text, cn_prefix):
        """Return the PEM blocks whose subject CN starts with cn_prefix.

        openssl validates each certificate. This removes the Aikido interception
        intermediate, which has a hexadecimal CN, and keeps the root.
        """
        matching = []
        for block in self._pem_blocks(pem_text):
            subject = self._openssl_subject(block)
            if subject is None:
                continue
            cn = self._subject_common_name(subject)
            if cn and cn.startswith(cn_prefix):
                matching.append(block.strip())
        return matching

    @staticmethod
    def _pem_blocks(pem_text):
        """Split PEM text into individual certificate blocks."""
        marker = '-----END CERTIFICATE-----'
        begin = '-----BEGIN CERTIFICATE-----'
        blocks = []
        for chunk in pem_text.split(marker):
            if begin in chunk:
                blocks.append(chunk[chunk.index(begin):] + marker + '\n')
        return blocks

    def _cert_fingerprints(self, path):
        """Return the SHA-256 fingerprint of each certificate in a PEM file.

        This is the value that `openssl x509 -fingerprint -sha256` gives: a digest
        of the DER body. The form is lowercase with no separators, which is how
        Aikido names its adopted-CA files. fumitm computes it in-process to keep the
        number of subprocess calls low.
        """
        text = self._read_text_or_none(path)
        if text is None:
            return []
        return self._pem_fingerprints(text, path)

    def _pem_fingerprints(self, text, source):
        """Return SHA-256 fingerprints for the certificate blocks in PEM text."""
        fingerprints = []
        for block in self._pem_blocks(text or ''):
            body = ''.join(block.split('-----BEGIN CERTIFICATE-----')[1]
                                .split('-----END CERTIFICATE-----')[0].split())
            try:
                fingerprints.append(hashlib.sha256(base64.b64decode(body)).hexdigest())
            except Exception as e:
                self.print_debug(f"Could not fingerprint a block of {source}: {e}")
        return fingerprints

    def _aikido_has_adopted(self, cert_path):
        """Return True when the adopted-CA record of Aikido covers cert_path.

        Aikido makes the record directory at the first adoption, thus an absent
        directory shows that Aikido adopted no CA. Callers get here only after they
        find the `aikido-doctor` CLI, which makes that reading safe.

        One recorded fingerprint is sufficient. The record answers only this
        question: did the operator give this certificate file to Aikido? A provider
        chain can contain an intermediate with its root, as the Netskope chain does.
        An intermediate with no record of its own must not prevent adoption. The
        bundles answer the question about complete trust, and fumitm examines them
        for each certificate.

        Returns None when fumitm cannot make a fingerprint of the certificates.
        """
        adopted_dir = SUPPLEMENTAL_ROOTS['aikido']['adopted_dir']
        if not os.path.isdir(adopted_dir):
            return False
        fingerprints = self._cert_fingerprints(cert_path)
        if not fingerprints:
            return None
        return any(os.path.exists(os.path.join(adopted_dir, f'{fp}.pem'))
                   for fp in fingerprints)

    def _aikido_built_bundles(self):
        """Return each CA bundle that `certconfig adopt` builds and keeps current.

        fumitm lists the directory and does not use glob. A run_dir that is present
        but unreadable gives None and not an empty list. glob hides the error, and
        an empty list looks the same as an agent that builds no bundles. The caller
        would then use the adoption record, and a filesystem fault would look like a
        correct adoption.

        A run_dir that is absent is a different condition and gives the empty list.
        An agent with no bundle directory is the old shape that the record covers. A
        fault report would fail each host that has no Aikido agent.
        """
        descriptor = SUPPLEMENTAL_ROOTS['aikido']
        run_dir = descriptor['run_dir']
        try:
            entries = os.listdir(run_dir)
        except FileNotFoundError:
            return []
        except OSError as e:
            self.print_debug(f"Could not list Aikido's bundle directory {run_dir}: {e}")
            return None
        return sorted(
            os.path.join(run_dir, name)
            for name in entries
            if any(fnmatch.fnmatch(name, p) for p in descriptor['bundle_globs'])
        )

    def _aikido_bundles_missing(self, cert_path):
        """Return the bundles of Aikido that do not contain the roots of cert_path.

        Each bundle must contain them. The bundles of Aikido are not the same, thus
        a root in the pip bundle tells you nothing about the openssl bundle. Returns
        None when fumitm cannot read the bundle directory.
        """
        bundles = self._aikido_built_bundles()
        if bundles is None:
            return None
        return [bundle for bundle in bundles
                if not self.certificate_exists_in_file(cert_path, bundle)]

    def _aikido_trusts_root(self, cert_path):
        """Return True when Aikido contains the roots of cert_path and recorded them.

        The bundles show the trust that exists now, because the tools that Aikido
        configures read them. Thus one bundle that is behind denies trust, and no
        record can change that. A root that Aikido adopted one time is not in a
        bundle that Aikido rebuilds from a source without it.

        But the record is also necessary when fumitm can read it. The bundles alone
        cannot show the difference between trust that Aikido keeps and trust that
        Aikido received. Aikido builds some bundles from the macOS System keychain,
        which already contains the primary root. Those bundles can contain the root
        while Aikido knows nothing about it, and the next rebuild from a different
        source removes it. Adoption records it permanently.

        Adoption again converges and does not repeat. `certconfig adopt` installs
        each rule again. On agent 1.7.28 it moved the openssl bundle and the ruby
        bundle from 128 to 130 certificates and made the record in the same pass.
        When fumitm cannot make a fingerprint of the certificates, the record gives
        no answer and the bundles decide.

        A bundle directory that fumitm cannot read gives False. Use of the record
        here would let a filesystem fault look like a correct adoption. That answer
        reports success while the tools of Aikido stay broken.
        """
        missing = self._aikido_bundles_missing(cert_path)
        if missing is None:
            return False
        if missing:
            return False
        record = self._aikido_has_adopted(cert_path)
        if record is not None:
            return record
        return bool(self._aikido_built_bundles())

    def _openssl_subject(self, cert_pem):
        """Return the openssl subject line for a single PEM cert, or None if invalid."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                tf.write(cert_pem)
                tmp_path = tf.name
        except Exception:
            return None
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-subject', '-in', tmp_path],
                capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()
        except Exception:
            return None
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    @staticmethod
    def _subject_common_name(subject_line):
        """Return the CN value from an openssl subject line, or None.

        Accepts the RFC 2253 form ("subject=CN=foo,O=bar"), the OpenSSL 3 form with
        spaces ("subject=CN = foo, O = bar"), and the slash form
        ("subject= /CN=foo/O=bar") that LibreSSL and old builds give.
        """
        if not subject_line:
            return None
        body = subject_line.split('=', 1)[1] if subject_line.lower().startswith('subject') else subject_line
        # Normalize the slash-delimited legacy form into comma-delimited.
        for token in body.replace('/', ',').split(','):
            key, sep, value = token.partition('=')
            if sep and key.strip().upper() == 'CN':
                return value.strip()
        return None

    def is_install_mode(self):
        return self.mode == 'install'
    
    def is_debug_mode(self):
        return self.debug
    
    def should_process_tool(self, tool_key):
        """Check if a tool should be processed based on selected tools."""
        if not self.selected_tools:
            # No selection means process all tools
            return True
        
        tool_info = self.tools_registry.get(tool_key, {})
        if not tool_info:
            return False
        
        for selection in self.selected_tools:
            selection_lower = selection.lower()
            if selection_lower == tool_key:
                return True
            if selection_lower in [tag.lower() for tag in tool_info.get('tags', [])]:
                return True
        
        return False
    
    def _container_tool_keys(self):
        """Return the set of tool keys that have the 'container' tag."""
        return {
            key for key, info in self.tools_registry.items()
            if 'container' in info.get('tags', [])
        }

    def get_selected_tools_info(self):
        """Get information about selected tools."""
        if not self.selected_tools:
            return list(self.tools_registry.keys())
        
        selected = []
        for tool_key in self.tools_registry:
            if self.should_process_tool(tool_key):
                selected.append(tool_key)
        
        return selected
    
    def validate_selected_tools(self):
        """Validate that selected tools exist and return list of invalid ones."""
        if not self.selected_tools:
            return []
        
        invalid_tools = []
        for selection in self.selected_tools:
            selection_lower = selection.lower()
            found = False
            
            for tool_key, tool_info in self.tools_registry.items():
                if selection_lower == tool_key:
                    found = True
                    break
                if selection_lower in [tag.lower() for tag in tool_info.get('tags', [])]:
                    found = True
                    break
            
            if not found:
                invalid_tools.append(selection)
        
        return invalid_tools
    
    # Output infrastructure

    @staticmethod
    def _strip_ansi(text):
        """Remove ANSI escape sequences from text."""
        return re.sub(r'\033\[[0-9;]*m', '', text)

    def _open_log_files(self):
        """Open the file handles for text logging and JSON logging.

        File mode (--log-file, --json-log-file) writes to the given path and
        replaces the file at each run.

        Directory mode (--log-dir, --json-log-dir) makes a name with a timestamp and
        keeps a 'fumitm-latest' symlink to the most recent file.
        """
        ts = datetime.now(timezone.utc).astimezone().strftime('%Y%m%d-%H%M%S')
        pid = os.getpid()

        if self._log_dir:
            try:
                os.makedirs(self._log_dir, exist_ok=True)
                path = os.path.join(self._log_dir, f"fumitm-{ts}-{pid}.log")
                self._log_file_handle = open(path, 'w')  # noqa: SIM115 (closed in _close_log_files)
                symlink = os.path.join(self._log_dir, 'fumitm-latest.log')
                self._update_symlink(symlink, path)
            except OSError as e:
                print(
                    f"[WARN] Cannot open log file in {self._log_dir}: {e}",
                    file=sys.stderr,
                )
        elif self._log_file_path:
            try:
                parent = os.path.dirname(self._log_file_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                self._log_file_handle = open(self._log_file_path, 'w')  # noqa: SIM115 (closed in _close_log_files)
            except OSError as e:
                print(
                    f"[WARN] Cannot open log file {self._log_file_path}: {e}",
                    file=sys.stderr,
                )

        if self._json_log_dir:
            try:
                os.makedirs(self._json_log_dir, exist_ok=True)
                path = os.path.join(
                    self._json_log_dir, f"fumitm-{ts}-{pid}.jsonl",
                )
                self._json_log_file_handle = open(path, 'w')  # noqa: SIM115 (closed in _close_log_files)
                symlink = os.path.join(
                    self._json_log_dir, 'fumitm-latest.jsonl',
                )
                self._update_symlink(symlink, path)
            except OSError as e:
                print(
                    f"[WARN] Cannot open JSON log file in "
                    f"{self._json_log_dir}: {e}",
                    file=sys.stderr,
                )
        elif self._json_log_file_path:
            try:
                parent = os.path.dirname(self._json_log_file_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                self._json_log_file_handle = open(  # noqa: SIM115 (closed in _close_log_files)
                    self._json_log_file_path, 'w',
                )
            except OSError as e:
                print(
                    f"[WARN] Cannot open JSON log file "
                    f"{self._json_log_file_path}: {e}",
                    file=sys.stderr,
                )

    @staticmethod
    def _update_symlink(symlink_path, target_path):
        """Atomically update a symlink to point at target_path."""
        tmp = symlink_path + '.tmp'
        try:
            os.symlink(os.path.basename(target_path), tmp)
            os.replace(tmp, symlink_path)
        except OSError:
            # Best-effort: non-fatal if symlink creation fails
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _close_log_files(self):
        """Close any open log file handles."""
        for handle in (self._log_file_handle, self._json_log_file_handle):
            if handle:
                try:
                    handle.close()
                except OSError:
                    pass
        self._log_file_handle = None
        self._json_log_file_handle = None

    def _emit(self, message, level='info', file=None, phase=None,
              tool=None, action=None, result=None, error_code=None):
        """Write output. Each print_* method calls this method.

        Removes color for a non-TTY or for --no-color, writes the text log, and
        writes the JSON-lines events.

        Args:
            message: The formatted message. It can contain ANSI codes.
            level: The log level (info, warn, error, debug).
            file: The output file object. The default is stdout. Debug uses stderr.
            phase: The JSON log phase (init, detect, cert, tool, verify, summary).
            tool: The tool key from tools_registry, for the JSON log.
            action: The operation, for the JSON log.
            result: The result status for the JSON log (ok, changed, skipped, failed).
            error_code: An optional error identifier for the JSON log.
        """
        output_file = file or sys.stdout

        if self._use_color:
            print(message, file=output_file)
        else:
            print(self._strip_ansi(message), file=output_file)

        if self._log_file_handle:
            ts = datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%dT%H:%M:%S')
            plain = self._strip_ansi(message)
            self._log_file_handle.write(
                f"{ts} [{level.upper()}] {plain}\n"
            )
            self._log_file_handle.flush()

        if self._json_log_file_handle:
            event = {
                'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'level': level,
                'phase': phase,
                'tool': tool,
                'action': action,
                'result': result,
                'message': self._strip_ansi(message),
                'error_code': error_code,
            }
            self._json_log_file_handle.write(json.dumps(event) + '\n')
            self._json_log_file_handle.flush()

    def print_info(self, msg, **kwargs):
        self._emit(f"{GREEN}[INFO]{NC} {msg}", level='info', **kwargs)

    def print_warn(self, msg, **kwargs):
        self._emit(f"{YELLOW}[WARN]{NC} {msg}", level='warn', **kwargs)

    def print_error(self, msg, **kwargs):
        if self._in_setup_context:
            self._setup_error_count += 1
            if self._current_tool_key:
                kwargs.setdefault('phase', 'tool')
                kwargs.setdefault('tool', self._current_tool_key)
        self._emit(f"{RED}[ERROR]{NC} {msg}", level='error', **kwargs)

    def print_status(self, msg, **kwargs):
        self._emit(f"{BLUE}[STATUS]{NC} {msg}", level='info', **kwargs)

    def print_action(self, msg, **kwargs):
        self._emit(f"{YELLOW}[ACTION]{NC} {msg}", level='info', **kwargs)

    def print_debug(self, msg, **kwargs):
        if self.is_debug_mode():
            self._emit(
                f"{BLUE}[DEBUG]{NC} {msg}",
                level='debug', file=sys.stderr, **kwargs
            )

    def _prompt(self, message):
        """Ask the user for input, or return 'y' when --yes is active.

        Raises NonInteractiveError when stdin is not a terminal and the operator did
        not give --yes. This prevents a stop with no end under JAMF or Ansible.
        """
        if self.auto_yes:
            self._emit(f"{message}y (--yes)", level='info')
            return 'y'
        if not sys.stdin.isatty():
            raise NonInteractiveError(
                "Interactive input required but stdin is not a terminal. "
                "Use --yes for non-interactive runs, or --headless --yes "
                "for MDM deployments."
            )
        return input(message)

    def check_for_updates(self):
        """Find if a newer version of fumitm is available on GitHub.

        Compares CalVer versions and not file hashes. A hash gives a false result
        for a local change or a difference in format. fumitm does not give the
        warning for a local git working copy, because the user is a developer.

        The SSL context is unverified, because trust of the proxy certificate can be
        absent. That is why the user runs this script.

        Returns:
            bool: True if an update is available.
        """
        try:
            # The context is unverified. Trust of the proxy CA can be absent.
            context = ssl._create_unverified_context()
            url = "https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py"

            self.print_debug(f"Checking for updates from {url}")

            req = urllib.request.Request(url, headers={'User-Agent': 'fumitm-update-check'})
            with urllib.request.urlopen(req, context=context, timeout=10) as response:
                remote_content = response.read().decode('utf-8')

            version_match = re.search(r'^__version__\s*=\s*["\']([0-9.]+)["\']',
                                      remote_content, re.MULTILINE)

            if not version_match:
                self.print_debug("Could not extract version from remote file")
                return False

            remote_version = version_match.group(1)
            local_version = __version__

            self.print_debug(f"Local version:  {local_version}")
            self.print_debug(f"Remote version: {remote_version}")

            try:
                local_tuple = parse_calver(local_version)
                remote_tuple = parse_calver(remote_version)
            except ValueError as e:
                self.print_debug(f"Version parse error: {e}")
                return False

            if remote_tuple > local_tuple:
                # A git working copy on another branch, or with local
                # changes, gives a different version.
                is_dev = VERSION_INFO['branch'] not in ('main', 'master', 'unknown') or VERSION_INFO['dirty']
                if is_dev:
                    branch = VERSION_INFO['branch']
                    dirty = ' (modified)' if VERSION_INFO['dirty'] else ''
                    print()
                    self.print_info(f"Running from local working copy (branch: {branch}{dirty})")
                    self.print_info(f"  Local:  {local_version}  |  Remote: {remote_version}")
                    print()
                    return False

                print()
                self.print_warn("=" * 60)
                self.print_warn("A newer version of fumitm.py is available!")
                self.print_info(f"  Local:  {local_version}")
                self.print_info(f"  Remote: {remote_version}")
                self.print_warn("Update before running --fix to ensure best results:")
                # -k stops certificate verification. The curl of the user can
                # be broken, which is why the user runs this script.
                self.print_info("  curl -kLsSf https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py -o fumitm.py")
                self.print_warn("=" * 60)
                print()
                return True
            elif remote_tuple < local_tuple:
                self.print_debug(f"Running development version ({local_version} > {remote_version})")
            else:
                self.print_debug("fumitm.py is up to date")

        except Exception as e:
            self.print_debug(f"Update check failed (this is OK): {e}")

        return False

    def command_exists(self, cmd):
        """Check if a command exists."""
        return shutil.which(cmd) is not None

    def _is_apple_git(self):
        """True when the active git binary is Apple's SecureTransport build."""
        try:
            result = subprocess.run(
                ['git', 'version'],
                capture_output=True, text=True, timeout=5,
            check=False)
            return 'Apple Git' in result.stdout
        except Exception:
            return False

    def is_writable(self, path):
        """Check if a file/directory is writable."""
        if os.path.isfile(path):
            return os.access(path, os.W_OK)
        elif os.path.isdir(os.path.dirname(path)):
            return os.access(os.path.dirname(path), os.W_OK)
        else:
            # The path is absent. Examine the parent directories.
            parent = os.path.dirname(path)
            while not os.path.isdir(parent) and parent != '/':
                parent = os.path.dirname(parent)
            return os.access(parent, os.W_OK)
    
    def suggest_user_path(self, original_path, purpose):
        """Suggest alternative path."""
        filename = os.path.basename(original_path)
        return os.path.join(self.bundle_dir, purpose, filename)

    def _apply_target_user(self, username):
        """Resolve a user name and set HOME, thus each expanduser call uses it.

        Sets _target_uid and _target_gid for the correction of ownership. When the
        name is 'auto', fumitm tries to find the console user on macOS.

        Args:
            username: A system user name, or 'auto' to find the console user.
        """
        if username == 'auto':
            detected = self._detect_console_user()
            if not detected:
                self.print_error(
                    "Cannot detect console user. "
                    "Specify --run-as-user USERNAME."
                )
                sys.exit(1)
            username = detected

        try:
            pw = pwd.getpwnam(username)
        except KeyError:
            # On a Mac joined to Entra ID, JAMF can give the UPN (for example
            # "user@domain.com") and not the macOS short name.
            if '@' in username:
                short_name = username.split('@')[0]
                try:
                    pw = pwd.getpwnam(short_name)
                    self.print_warn(
                        f"User '{username}' not found, "
                        f"using short name '{short_name}'"
                    )
                except KeyError:
                    self.print_error(
                        f"User '{username}' not found "
                        f"(also tried '{short_name}')."
                    )
                    sys.exit(1)
            else:
                self.print_error(f"User '{username}' not found.")
                sys.exit(1)

        self._target_uid = pw.pw_uid
        self._target_gid = pw.pw_gid
        os.environ['HOME'] = pw.pw_dir

        # Add directories to PATH, thus command_exists() finds the tools of
        # the user. The PATH of root usually has no Homebrew directory.
        brew_prefix = (
            '/opt/homebrew/bin'
            if platform.machine() == 'arm64'
            else '/usr/local/bin'
        )
        user_paths = [
            brew_prefix,
            os.path.join(pw.pw_dir, '.local/bin'),
        ]
        current = os.environ.get('PATH', '')
        current_entries = current.split(os.pathsep)
        for p in reversed(user_paths):
            try:
                exists = os.path.isdir(p)
            except (OSError, TypeError):
                exists = False
            if exists and p not in current_entries:
                current = p + os.pathsep + current
        os.environ['PATH'] = current
        self.print_debug("Augmented PATH with user tool directories")

    @staticmethod
    def _detect_console_user():
        """Find the GUI-session user on macOS from the ownership of /dev/console.

        Returns the user name, or None. The result is None on Linux, when no user is
        logged in, and when /dev/console is not accessible.
        """
        if platform.system() != 'Darwin':
            return None
        try:
            st = os.stat('/dev/console')
            pw = pwd.getpwuid(st.st_uid)
            if pw.pw_name in ('root', '_windowserver'):
                return None
            return pw.pw_name
        except (OSError, KeyError):
            return None

    def _is_running_as_sudo(self):
        """Return True when root operates for a user who is not root.

        This includes sudo, which sets SUDO_UID, and --run-as-user, which sets
        _target_uid.
        """
        if self._target_uid is not None and self._target_uid != 0:
            return True
        return os.getuid() == 0 and 'SUDO_UID' in os.environ

    def _get_real_user_ids(self):
        """Return the (uid, gid) of the real user, also under sudo.

        The sequence is _target_uid, then SUDO_UID, then the UID of the process.
        """
        if self._target_uid is not None:
            return (self._target_uid, self._target_gid)
        if os.getuid() == 0 and 'SUDO_UID' in os.environ:
            return (int(os.environ['SUDO_UID']),
                    int(os.environ['SUDO_GID']))
        return (os.getuid(), os.getgid())

    def _fix_ownership(self, path):
        """Give a path in the home directory back to the real user under sudo.

        fumitm does not change a system path such as /etc/ssl. A file that belongs
        to root stays with root.
        """
        if not self._is_running_as_sudo():
            return
        if not os.path.exists(path):
            return
        home = os.path.expanduser('~')
        if not os.path.abspath(path).startswith(home):
            return
        uid, gid = self._get_real_user_ids()
        try:
            os.chown(path, uid, gid)
        except OSError as e:
            self.print_debug(f"Could not chown {path}: {e}")

    def _safe_makedirs(self, path, exist_ok=True):
        """Create directories and fix ownership of each newly created component."""
        if os.path.isdir(path):
            return
        # Walk up to find the first existing ancestor so we can chown only new dirs.
        to_create = []
        current = os.path.abspath(path)
        while not os.path.isdir(current):
            to_create.append(current)
            current = os.path.dirname(current)
        os.makedirs(path, exist_ok=exist_ok)
        for d in to_create:
            self._fix_ownership(d)

    def _has_user_context(self):
        """Return True when fumitm has a target user for user-scoped operations.

        The result is False only when fumitm runs as root with no --run-as-user and
        no SUDO_USER. There is then no home directory to write to.
        """
        if os.getuid() != 0:
            return True
        return self._target_uid is not None

    def detect_shell(self):
        """Detect the user's default shell with multiple fallbacks."""
        # Try environment variable first (current session)
        shell_path = os.environ.get('SHELL')

        # Use the pwd module. Under root, use the target user.
        if not shell_path:
            try:
                lookup_uid = self._target_uid if self._target_uid is not None else os.getuid()
                shell_path = pwd.getpwuid(lookup_uid).pw_shell
            except Exception:
                shell_path = None
        
        # Final fallback for modern macOS
        if not shell_path:
            shell_path = '/bin/zsh'
        
        shell_name = os.path.basename(shell_path)
        
        known_shells = {'bash', 'zsh', 'fish', 'sh', 'tcsh', 'csh', 'dash'}
        
        if shell_name in known_shells:
            return shell_name
        else:
            # Return actual name rather than 'unknown'
            return shell_name

    def _query_zsh_dotdir(self, home):
        """Ask zsh for a shell-local ZDOTDIR value from .zshenv.

        zsh does not export ZDOTDIR, thus a Python child cannot always find it in
        os.environ. A non-interactive zsh reads only .zshenv before the command
        below. This gives the directory without .zprofile, .zshrc, or .zlogin.

        When fumitm is root and operates for a target user, the child changes to the
        uid, the gid, and the groups of that user before it reads user-controlled
        startup code. The query has a time limit and returns HOME on a failure.
        """
        shell_path = os.environ.get('SHELL')
        if not shell_path or os.path.basename(shell_path) != 'zsh':
            if self._target_uid is not None:
                try:
                    candidate = pwd.getpwuid(self._target_uid).pw_shell
                    if os.path.basename(candidate) == 'zsh':
                        shell_path = candidate
                except (KeyError, OSError):
                    shell_path = None
            if not shell_path or os.path.basename(shell_path) != 'zsh':
                shell_path = shutil.which('zsh')

        if not shell_path:
            self.print_debug("Could not find zsh to resolve shell-local ZDOTDIR")
            return None

        child_identity = {}
        if os.getuid() == 0 and self._target_uid not in (None, 0):
            uid, gid = self._target_uid, self._target_gid
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                self.print_debug(
                    f"Could not resolve target UID {uid} for ZDOTDIR query"
                )
                return None
            child_identity = {
                'user': uid,
                'group': gid,
                'extra_groups': os.getgrouplist(username, gid),
            }

        marker = "__FUMITM_ZDOTDIR__="
        query_env = os.environ.copy()
        query_env['HOME'] = home
        query_env.pop('ZDOTDIR', None)
        try:
            process = subprocess.Popen(
                [
                    shell_path,
                    '-c',
                    f'print -r -- "{marker}${{ZDOTDIR:-$HOME}}"',
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                env=query_env,
                **child_identity,
            )
            stdout, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired as e:
            process.kill()
            process.communicate()
            self.print_debug(f"Could not query zsh for ZDOTDIR: {e}")
            return None
        except (OSError, subprocess.SubprocessError, TypeError) as e:
            self.print_debug(f"Could not query zsh for ZDOTDIR: {e}")
            return None

        if process.returncode != 0:
            self.print_debug(
                f"zsh ZDOTDIR query exited with status {process.returncode}"
            )
            return None

        for line in reversed(stdout.splitlines()):
            if line.startswith(marker):
                value = line[len(marker):]
                return value or home
        self.print_debug("zsh ZDOTDIR query returned no recognizable result")
        return None

    def _zsh_dotdir(self):
        """Return the directory that zsh reads its startup files from.

        zsh uses $ZDOTDIR if it is set, and HOME if it is not. An exported value is
        visible. When .zshenv sets a shell-local value, fumitm asks zsh one time.
        Thus a stub does not go into a HOME file that a later startup phase never
        reads.
        """
        home = os.path.expanduser("~")
        if 'ZDOTDIR' in os.environ:
            zdotdir = os.environ.get('ZDOTDIR')
            return os.path.expanduser(zdotdir) if zdotdir else home

        if self._queried_zsh_dotdir is None:
            queried = self._query_zsh_dotdir(home)
            resolved = os.path.expanduser(queried) if queried else home
            self._queried_zsh_dotdir = os.path.abspath(resolved)
        return self._queried_zsh_dotdir

    def get_shell_config(self, shell_type):
        """Return the primary shell config file.

        Callers that need one path use this method, for a message or a prompt. A
        write uses get_shell_configs(), which gives each startup file that the shell
        reads.
        """
        home = os.path.expanduser("~")
        if shell_type == 'bash':
            # For macOS, .bash_profile is the primary config file for login shells
            for config in ['.bash_profile', '.bashrc', '.profile']:
                if os.path.exists(os.path.join(home, config)):
                    return os.path.join(home, config)
            return os.path.join(home, '.profile')
        elif shell_type == 'zsh':
            return os.path.join(self._zsh_dotdir(), '.zshrc')
        elif shell_type == 'fish':
            return os.path.join(home, '.config/fish/config.fish')
        else:
            return os.path.join(home, '.profile')

    def get_shell_configs(self, shell_type):
        """Return each startup file that must contain the block, in read sequence.

        A shell reads a different set of startup files for each invocation mode. A
        write to only one file leaves the other files with the settings of a vendor
        block. The usual failure is a non-interactive login shell (`zsh -lc`, which
        many tool launchers use). It reads .zprofile and never .zshrc, thus an
        export only in .zshrc is absent.

        zsh reads .zshenv, then .zprofile for a login shell, then .zshrc for an
        interactive shell, then .zlogin for a login shell. A stub in .zshenv,
        .zshrc, and .zlogin covers all four modes. .zlogin comes after .zprofile,
        thus a vendor block in .zprofile does not win. fumitm never changes
        .zprofile, because that file belongs to the vendors.

        For a login shell, bash reads the first of .bash_profile, .bash_login, and
        .profile that is present. For an interactive non-login shell it reads
        .bashrc. A non-interactive non-login bash reads only $BASH_ENV. fumitm does
        not set $BASH_ENV, because that file would run for each script on the
        system.
        """
        home = os.path.expanduser("~")

        def in_home(*parts):
            return os.path.join(home, *parts)

        if shell_type == 'zsh':
            zdot = self._zsh_dotdir()
            return [os.path.join(zdot, name)
                    for name in ('.zshenv', '.zshrc', '.zlogin')]

        if shell_type == 'bash':
            targets = [in_home('.bashrc')]
            for name in ('.bash_profile', '.bash_login', '.profile'):
                if os.path.exists(in_home(name)):
                    targets.append(in_home(name))
                    break
            else:
                # None exist yet; .bash_profile is bash's first choice on macOS.
                targets.append(in_home('.bash_profile'))
            # A /bin/sh login shell reads .profile. Include it when the user
            # has one.
            if os.path.exists(in_home('.profile')) and in_home('.profile') not in targets:
                targets.append(in_home('.profile'))
            return targets

        return [self.get_shell_config(shell_type)]

    def _env_file_path(self):
        """Absolute path of the sourced env file holding fumitm's exports."""
        return os.path.join(os.path.expanduser("~"), self._FUMITM_ENV_FILE_REL)

    def _uses_env_file(self, shell_type):
        """Return True when the shell can source a POSIX sh env file.

        fish (`set -gx`) and the csh shells (`setenv`) cannot read POSIX sh syntax,
        thus they keep the inline block in their own config file.
        """
        return shell_type in ('zsh', 'bash', 'sh', 'dash', 'ksh')

    def check_environment_sanity(self):
        """Find CA environment variables that point to a file that is not present.

        A user can have an old variable from a previous WARP installation, or can
        remove a shell config export and keep the variable in the session.

        Returns:
            bool: True if fumitm found a broken variable.
        """
        ca_env_vars = [
            'CURL_CA_BUNDLE',
            'SSL_CERT_FILE',
            'REQUESTS_CA_BUNDLE',
            'NODE_EXTRA_CA_CERTS',
            'GIT_SSL_CAINFO',
            'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
        ]

        broken_vars = []

        for var_name in ca_env_vars:
            var_value = os.environ.get(var_name, '')
            if var_value and not os.path.exists(var_value):
                broken_vars.append((var_name, var_value))

        # Special handling for JAVA_OPTS which may contain -Djavax.net.ssl.trustStore=...
        java_opts = os.environ.get('JAVA_OPTS', '')
        if java_opts:
            match = re.search(r'-Djavax\.net\.ssl\.trustStore=([^\s]+)', java_opts)
            if match:
                truststore_path = match.group(1)
                if not os.path.exists(truststore_path):
                    broken_vars.append(('JAVA_OPTS (trustStore)', truststore_path))

        if not broken_vars:
            return False

        print()
        self.print_warn("=" * 60)
        self.print_warn("BROKEN ENVIRONMENT DETECTED")
        self.print_warn("=" * 60)
        print()
        self.print_warn("The following environment variables point to non-existent files:")
        print()

        for var_name, var_value in broken_vars:
            self.print_error(f"  {var_name}={var_value}")
            self.print_error("    FILE DOES NOT EXIST")
            print()

        self.print_info("To fix in your CURRENT shell session:")
        for var_name, _ in broken_vars:
            if var_name.startswith('JAVA_OPTS'):
                self.print_info("  unset JAVA_OPTS  # (or edit to remove trustStore)")
            else:
                self.print_info(f"  unset {var_name}")
        print()

        self.print_info("To fix PERMANENTLY, remove/comment the export lines from:")
        shell_type = self.detect_shell()
        home = os.path.expanduser("~")
        candidates = list(self.get_shell_configs(shell_type))
        if shell_type == 'zsh':
            # Login shells read .zprofile, and vendor installers write there.
            # fumitm does not change it.
            candidates.insert(1, os.path.join(self._zsh_dotdir(), '.zprofile'))
        for path in candidates:
            if os.path.exists(path):
                self.print_info(f"  {path.replace(home, '~', 1)}")
        if self._uses_env_file(shell_type) and os.path.exists(self._env_file_path()):
            self.print_info(f"  {self._env_file_path().replace(home, '~', 1)}  (managed by fumitm)")
        print()

        self.print_warn("IMPORTANT: After editing shell config files, you must either:")
        self.print_info("  1. Run: source ~/.zshrc  (or the appropriate config file)")
        self.print_info("  2. Or open a NEW terminal window")
        print()
        self.print_warn("Editing .zshrc does NOT affect your current shell session!")
        self.print_warn("=" * 60)
        print()

        return True

    def check_ownership_sanity(self):
        """Find and report files that belong to root in the home directory.

        ``sudo ./fumitm.py --fix`` makes files in HOME that belong to root. A later
        run that is not root then fails with PermissionError. This method finds that
        condition. It gives a warning when it is not root, and corrects the
        ownership when it runs under sudo.

        Returns:
            bool: True if fumitm found a problem or corrected one.
        """
        managed_paths = [self.cert_path, self.bundle_dir]
        home = os.path.expanduser('~')

        if self._is_running_as_sudo():
            # Under sudo, correct each managed file that belongs to root.
            uid, gid = self._get_real_user_ids()
            fixed = []
            for path in managed_paths:
                if not os.path.exists(path):
                    continue
                if os.path.isdir(path):
                    for dirpath, dirnames, filenames in os.walk(path):
                        for name in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
                            try:
                                st = os.stat(name)
                                if st.st_uid != uid:
                                    os.chown(name, uid, gid)
                                    fixed.append(name)
                            except OSError:
                                pass
                        for d in dirnames:
                            full = os.path.join(dirpath, d)
                            try:
                                st = os.stat(full)
                                if st.st_uid != uid:
                                    os.chown(full, uid, gid)
                                    fixed.append(full)
                            except OSError:
                                pass
                else:
                    try:
                        st = os.stat(path)
                        if st.st_uid != uid:
                            os.chown(path, uid, gid)
                            fixed.append(path)
                    except OSError:
                        pass
            if fixed:
                self.print_warn(f"Running as sudo. Corrected the ownership of {len(fixed)} file(s) in {home}")
                self.print_info("New files created during this run will also be owned by the real user")
            else:
                self.print_info("Running as sudo. fumitm corrects the ownership of each new file.")
            return bool(fixed)

        # Not root. Look for files that belong to root and give a warning.
        root_owned = []
        for path in managed_paths:
            if not os.path.exists(path):
                continue
            if os.path.isdir(path):
                for dirpath, _dirnames, filenames in os.walk(path):
                    for name in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
                        try:
                            if os.stat(name).st_uid == 0:
                                root_owned.append(name)
                        except OSError:
                            pass
            else:
                try:
                    if os.stat(path).st_uid == 0:
                        root_owned.append(path)
                except OSError:
                    pass

        if not root_owned:
            return False

        print()
        self.print_warn("Root-owned files detected in your home directory.")
        self.print_warn("This usually happens after running with sudo.")
        self.print_info("Affected paths:")
        for p in root_owned[:10]:
            self.print_error(f"  {p}")
        if len(root_owned) > 10:
            self.print_error(f"  ... and {len(root_owned) - 10} more")
        print()
        # Build a single chown command covering all managed paths
        dirs_to_fix = ' '.join(p for p in managed_paths if os.path.exists(p))
        self.print_info("To fix, run:")
        self.print_info(f"  sudo chown -R $(whoami) {dirs_to_fix}")
        print()
        return True

    def get_cert_fingerprint(self, cert_path=None):
        """Get certificate fingerprint (cached)."""
        if cert_path is None:
            cert_path = self.cert_path

        if self.cert_fingerprint and cert_path == self.cert_path:
            return self.cert_fingerprint

        if os.path.exists(cert_path):
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    fingerprint = result.stdout.strip().split('=')[1]
                    if cert_path == self.cert_path:
                        self.cert_fingerprint = fingerprint
                    self.print_debug(f"Cached certificate fingerprint: {fingerprint}")
                    return fingerprint
            except Exception as e:
                self.print_debug(f"Error getting fingerprint: {e}")
        return ""

    def find_java_home(self):
        """Locate JAVA_HOME using environment and command fallbacks."""
        java_home = os.environ.get('JAVA_HOME', '')
        if not java_home and self.command_exists('java'):
            try:
                if platform.system() == 'Darwin' and os.path.exists('/usr/libexec/java_home'):
                    result = subprocess.run(['/usr/libexec/java_home'], capture_output=True, text=True, check=False)
                    if result.returncode == 0:
                        java_home = result.stdout.strip()

                if not java_home:
                    result = subprocess.run(
                        ['java', '-XshowSettings:properties', '-version'],
                        capture_output=True, text=True, stderr=subprocess.STDOUT, check=False
                    )
                    for line in result.stdout.splitlines():
                        if 'java.home' in line:
                            java_home = line.split('=')[1].strip()
                            break
            except Exception as e:
                self.print_debug(f"Error finding JAVA_HOME: {e}")
        return java_home

    def find_java_cacerts(self, java_home=None):
        """Locate Java cacerts file."""
        if java_home is None:
            java_home = self.find_java_home()
        if not java_home:
            return ''
        cacerts = os.path.join(java_home, 'lib/security/cacerts')
        if not os.path.isfile(cacerts):
            cacerts = os.path.join(java_home, 'jre/lib/security/cacerts')
        return cacerts if os.path.isfile(cacerts) else ''

    def java_version_label(self, java_home):
        """Derive a human-readable label from a Java home path, e.g. 'temurin-21'."""
        if 'Contents/Home' in java_home:
            return os.path.basename(os.path.dirname(os.path.dirname(java_home))).replace('.jdk', '')
        return os.path.basename(java_home)

    def find_all_java_homes(self):
        """Find each Java installation on the system.

        Returns:
            list: The Java home paths that have a valid cacerts file.
        """
        java_homes = set()

        # Strategy 1: Get current/default Java
        current_java = self.find_java_home()
        if current_java:
            java_homes.add(current_java)

        # Strategy 2: Platform-specific multi-installation detection
        if platform.system() == 'Darwin':
            # macOS: Use /usr/libexec/java_home -V to list all installations
            if os.path.exists('/usr/libexec/java_home'):
                try:
                    result = subprocess.run(
                        ['/usr/libexec/java_home', '-V'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True, check=False
                    )
                    for line in result.stdout.splitlines():
                        if line and '/' in line and '/Contents/Home' in line:
                            parts = line.split()
                            for part in reversed(parts):
                                if '/Contents/Home' in part:
                                    java_homes.add(part)
                                    break
                except Exception as e:
                    self.print_debug(f"Error listing Java installations: {e}")

            # Also scan common macOS directories
            for base_dir in ['/Library/Java/JavaVirtualMachines',
                           os.path.expanduser('~/Library/Java/JavaVirtualMachines')]:
                if os.path.isdir(base_dir):
                    try:
                        for entry in os.listdir(base_dir):
                            if entry.endswith('.jdk'):
                                java_home = os.path.join(base_dir, entry, 'Contents/Home')
                                if os.path.isdir(java_home):
                                    java_homes.add(java_home)
                    except (OSError, PermissionError):
                        pass

        elif platform.system() == 'Linux':
            # Linux: Try update-alternatives
            try:
                result = subprocess.run(
                    ['update-alternatives', '--list', 'java'],
                    capture_output=True,
                    text=True, check=False
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line and '/bin/java' in line:
                            java_home = line.replace('/bin/java', '')
                            java_homes.add(java_home)
            except (FileNotFoundError, PermissionError):
                pass
            except Exception as e:
                self.print_debug(f"Error listing Java installations: {e}")

            # Scan common Linux directories, resolving symlinks to avoid duplicates
            if os.path.isdir('/usr/lib/jvm'):
                try:
                    for entry in os.listdir('/usr/lib/jvm'):
                        java_home = os.path.realpath(os.path.join('/usr/lib/jvm', entry))
                        if os.path.isdir(java_home):
                            java_homes.add(java_home)
                except (OSError, PermissionError):
                    pass

        # Strategy 3: installations that SDKMAN controls. 'current' is a
        # symlink to the active version, thus fumitm skips it. SDKMAN_DIR
        # gives a different location.
        sdkman_root = os.environ.get('SDKMAN_DIR') or os.path.expanduser('~/.sdkman')
        sdkman_java_dir = os.path.join(sdkman_root, 'candidates', 'java')
        if os.path.isdir(sdkman_java_dir):
            try:
                for entry in os.listdir(sdkman_java_dir):
                    if entry == 'current':
                        continue
                    version_dir = os.path.join(sdkman_java_dir, entry)
                    if not os.path.isdir(version_dir):
                        continue
                    # Some vendors put a .jdk application bundle in the
                    # version directory. Go into <vendor>.jdk/Contents/Home
                    # when it is present.
                    bundle_home = None
                    try:
                        for sub in os.listdir(version_dir):
                            if sub.endswith('.jdk'):
                                candidate = os.path.join(version_dir, sub, 'Contents', 'Home')
                                if os.path.isdir(candidate):
                                    bundle_home = candidate
                                    break
                    except (OSError, PermissionError):
                        pass
                    java_homes.add(bundle_home if bundle_home else version_dir)
            except (OSError, PermissionError):
                pass

        # Validate: only keep paths with valid cacerts
        valid_homes = []
        for home in java_homes:
            if self.find_java_cacerts(home):
                valid_homes.append(home)

        return sorted(valid_homes)

    def get_gradle_properties_path(self):
        """Get path to Gradle properties file respecting GRADLE_USER_HOME."""
        gradle_home = os.environ.get('GRADLE_USER_HOME', os.path.expanduser('~/.gradle'))
        return os.path.join(gradle_home, 'gradle.properties')

    def get_gradle_custom_cacerts_path(self):
        """Return the managed PKCS12 truststore path for Gradle."""
        gradle_home = os.environ.get('GRADLE_USER_HOME', os.path.expanduser('~/.gradle'))
        return os.path.join(gradle_home, 'custom-cacerts')

    def read_properties_file(self, path):
        """Read Java-style .properties file into a dict."""
        props = {}
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, val = line.split('=', 1)
                        props[key] = val
        return props

    def update_properties_file(self, path, props_to_set, desc="properties"):
        """Update key/value pairs in a .properties file."""
        existing_lines = []
        if os.path.exists(path):
            with open(path, 'r') as f:
                existing_lines = f.readlines()

        current_props = {}
        key_counts = {key: 0 for key in props_to_set}
        in_vendor_block = False
        for raw_line in existing_lines:
            line = raw_line.strip()
            if line.startswith('#') and line.endswith('-start'):
                in_vendor_block = True
                continue
            if line.startswith('#') and line.endswith('-end'):
                in_vendor_block = False
                continue
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                current_props[key] = val
                if key in key_counts and not in_vendor_block:
                    key_counts[key] += 1

        if (all(current_props.get(k) == v for k, v in props_to_set.items())
                and all(key_counts[key] == 1 for key in props_to_set)):
            return False

        self.print_info(f"Setting up {desc}...")

        updated_lines = []
        managed_keys = set(props_to_set)
        in_vendor_block = False
        for line in existing_lines:
            stripped = line.strip()
            if stripped.startswith('#') and stripped.endswith('-start'):
                in_vendor_block = True
                updated_lines.append(line)
                continue
            if stripped.startswith('#') and stripped.endswith('-end'):
                in_vendor_block = False
                updated_lines.append(line)
                continue
            if (not in_vendor_block
                    and any(stripped.startswith(key + '=') for key in managed_keys)):
                continue
            updated_lines.append(line)

        while updated_lines and updated_lines[-1].strip() == '':
            updated_lines.pop()
        if updated_lines:
            updated_lines.append('\n')

        for key, value in props_to_set.items():
            updated_lines.append(f"{key}={value}\n")

        if not self.is_install_mode():
            self.print_action(f"Would update {desc} at {path}")
        else:
            self._safe_makedirs(os.path.dirname(path))
            with open(path, 'w') as f:
                f.writelines(updated_lines)
            self._fix_ownership(path)
            self.print_info(f"Updated {desc} at {path}")
        return True

    def _property_lines_with_vendor_scope(self, path):
        """Return parsed property lines, [] when absent, or None when unreadable."""
        text = self._read_text_or_none(path)
        if text is None:
            try:
                os.lstat(path)
            except FileNotFoundError:
                return []
            except OSError as e:
                self.print_debug(f"Could not inspect {path}: {e}")
            return None
        raw_lines = text.splitlines(keepends=True)

        parsed = []
        in_vendor_block = False
        for raw_line in raw_lines:
            stripped = raw_line.strip()
            if stripped.startswith('#') and stripped.endswith('-start'):
                in_vendor_block = True
                parsed.append((raw_line, in_vendor_block, None, None))
                continue
            if stripped.startswith('#') and stripped.endswith('-end'):
                parsed.append((raw_line, in_vendor_block, None, None))
                in_vendor_block = False
                continue
            key = value = None
            if '=' in stripped and not stripped.startswith('#'):
                key, value = (part.strip() for part in stripped.split('=', 1))
            parsed.append((raw_line, in_vendor_block, key, value))
        return parsed

    @staticmethod
    def _properties_have_values_outside_vendor_blocks(parsed, expected):
        """Return True when a non-vendor property has one of the expected values."""
        return any(
            not in_vendor and key in expected and expected[key] == value
            for _, in_vendor, key, value in parsed
        )

    def _remove_property_values_outside_vendor_blocks(
            self, path, expected, desc, parsed):
        """Remove matching non-vendor properties and preserve vendor blocks."""
        kept = []
        changed = False
        for raw_line, in_vendor, key, value in parsed:
            if not in_vendor and key in expected and expected[key] == value:
                changed = True
                continue
            kept.append(raw_line)

        if not changed:
            return False
        if not self.is_install_mode():
            self.print_action(f"Would remove fumitm truststore overrides from {desc} at {path}")
            return True

        self._safe_makedirs(os.path.dirname(path))
        with open(path, 'w') as f:
            f.writelines(kept)
        self._fix_ownership(path)
        self.print_info(f"Removed fumitm truststore overrides from {desc} at {path}")
        return True

    def _gradle_fumitm_truststore_properties(self):
        """Return the Gradle truststore properties that fumitm owns."""
        return {
            'systemProp.javax.net.ssl.trustStore': self.get_gradle_custom_cacerts_path(),
            'systemProp.javax.net.ssl.trustStorePassword': 'changeit',
            'systemProp.javax.net.ssl.trustStoreType': 'PKCS12',
            'systemProp.https.protocols': 'TLSv1.2',
        }

    @staticmethod
    def _gradle_pinned_java_home(parsed):
        """Return the final org.gradle.java.home value, if one is present."""
        gradle_java_home = None
        for _, _, key, value in parsed or []:
            if key == 'org.gradle.java.home':
                gradle_java_home = value
        return os.path.expanduser(gradle_java_home) if gradle_java_home else None

    def _gradle_java_cacerts(self, gradle_props, parsed=None):
        """Return cacerts for Gradle's pinned JDK, or the active JDK."""
        if parsed is None:
            parsed = self._property_lines_with_vendor_scope(gradle_props)
        if parsed is None:
            return ''
        gradle_java_home = self._gradle_pinned_java_home(parsed)
        if gradle_java_home:
            self.print_debug(
                f"Gradle selects Java home from org.gradle.java.home: {gradle_java_home}"
            )
            return self.find_java_cacerts(gradle_java_home)
        return self.find_java_cacerts()
    
    def certificate_likely_exists_in_file(self, cert_file, target_file):
        """Look for certificates with pure-Python string matching.

        Confirms that each certificate in cert_file is in target_file. The
        identifier is the first 100 characters of the base64 body. cert_file can
        contain more than one certificate, for example several Aikido roots during a
        rotation of the root. A bundle without a later root must not look complete.
        This function makes no subprocess call.

        Args:
            cert_file: The path of the certificates to look for.
            target_file: The path of the bundle file to look in.

        Returns:
            bool: True if each certificate in cert_file is in target_file.
        """
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False

        try:
            unique_portions = self._cert_unique_portions(cert_file)
            if not unique_portions:
                return False

            # Normalize whitespace and require every certificate to be present.
            with open(target_file, 'r') as tf:
                target_normalized = ''.join(tf.read().split())

            for unique_portion in unique_portions:
                if unique_portion not in target_normalized:
                    return False
            self.print_debug(f"All certificates found in {target_file}")
            return True

        except Exception as e:
            self.print_debug(f"Error checking certificate content: {e}")

        return False

    def _cert_unique_portions(self, cert_file):
        """Return one base64 identifier for each certificate in cert_file.

        The identifier is the first 100 characters of the base64 body. This is
        sufficient and needs no subprocess call. The list keeps the sequence of the
        file and is empty when the file has no certificate.
        """
        unique_portions = []
        current = []
        in_cert = False
        with open(cert_file, 'r') as f:
            for line in f:
                if '-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    current = []
                elif '-----END CERTIFICATE-----' in line:
                    in_cert = False
                    body = ''.join(current)
                    if body:
                        unique_portions.append(body[:100])
                elif in_cert:
                    current.append(line.strip())
        return unique_portions

    def _any_cert_present_in_file(self, cert_file, target_file):
        """Return True if one or more certificates from cert_file are in target_file.

        This is the permissive form of certificate_likely_exists_in_file. It shows
        if brew took any part of a multi-certificate provider bundle from the
        keychain, for example the Netskope root with its intermediate. A bundle with
        the root but not the intermediate still counts. fumitm can then append the
        intermediate and does not report a keychain failure.
        """
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False
        try:
            unique_portions = self._cert_unique_portions(cert_file)
            if not unique_portions:
                return False
            with open(target_file, 'r') as tf:
                target_normalized = ''.join(tf.read().split())
            return any(portion in target_normalized for portion in unique_portions)
        except Exception as e:
            self.print_debug(f"Error checking certificate content: {e}")
            return False

    def certificate_exists_in_file(self, cert_file, target_file):
        """Find if a certificate is already in a file.

        Uses pure-Python string matching. The previous comparison used fingerprints
        and made one subprocess call for each certificate in the target file. String
        matching makes no subprocess call and is sufficient to find a duplicate.

        Args:
            cert_file: The path of the certificate to look for.
            target_file: The path of the bundle file to look in.

        Returns:
            bool: True if the certificate is in the target file.
        """
        # The pure-Python check is sufficient. A false negative appends a
        # duplicate, which does no damage. A false positive is very unlikely
        # with a match of 100 characters.
        return self.certificate_likely_exists_in_file(cert_file, target_file)

    def count_certificates_in_file(self, path):
        """Count the number of PEM certificates in a file."""
        try:
            if not os.path.exists(path):
                return 0
            count = 0
            with open(path, 'r') as f:
                for line in f:
                    if '-----BEGIN CERTIFICATE-----' in line:
                        count += 1
            return count
        except Exception as e:
            self.print_debug(f"Error counting certificates in {path}: {e}")
            return 0

    def files_are_identical(self, path_a, path_b):
        """Return True if two files have identical content."""
        try:
            if not (os.path.exists(path_a) and os.path.exists(path_b)):
                return False
            with open(path_a, 'r') as fa, open(path_b, 'r') as fb:
                return fa.read() == fb.read()
        except Exception as e:
            self.print_debug(f"Error comparing files {path_a} and {path_b}: {e}")
            return False

    def is_suspicious_full_bundle(self, bundle_path, warp_cert_path=None):
        """Find a bundle that contains only the WARP CA or is too small.

        Returns:
            tuple: (is_suspicious: bool, reason: str)
        """
        try:
            if not os.path.exists(bundle_path):
                return (False, "")
            size = 0
            try:
                size = os.path.getsize(bundle_path)
            except Exception:
                # Use the length of the content as an approximation.
                try:
                    with open(bundle_path, 'r') as f:
                        size = len(f.read().encode('utf-8'))
                except Exception:
                    size = 0

            cert_count = self.count_certificates_in_file(bundle_path)
            if self.is_debug_mode():
                self.print_debug(f"Bundle stats for {bundle_path}: {cert_count} cert(s), size={size}B")

            # One certificate only. This is an incorrect configuration.
            if cert_count <= 1:
                return (True, f"contains {cert_count} certificate(s), size={size}B")

            # Small count and small file size heuristics
            if cert_count <= SMALL_BUNDLE_MAX_CERTS and size <= SMALL_BUNDLE_MAX_SIZE_BYTES:
                return (True, f"contains {cert_count} certificates and is only {size}B")

            # A file that is equal to the WARP certificate is suspicious.
            if warp_cert_path and self.files_are_identical(bundle_path, warp_cert_path):
                return (True, "bundle is identical to the proxy certificate file")

            return (False, "")
        except Exception as e:
            self.print_debug(f"Error checking suspicious bundle {bundle_path}: {e}")
            return (False, "")

    def create_bundle_with_system_certs(self, bundle_path):
        """Make a CA bundle that starts with the system certificates.

        Tools that need a full CA chain use this bundle.

        Args:
            bundle_path: The path to make the bundle at.

        Returns:
            bool: True if fumitm copied the system certificates. False if it made an
            empty bundle.
        """
        if os.path.exists("/etc/ssl/cert.pem"):
            shutil.copy("/etc/ssl/cert.pem", bundle_path)
            self._fix_ownership(bundle_path)
            return True
        elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
            shutil.copy("/etc/ssl/certs/ca-certificates.crt", bundle_path)
            self._fix_ownership(bundle_path)
            return True
        else:
            Path(bundle_path).touch()
            self._fix_ownership(bundle_path)
            return False

    def safe_append_certificate(self, cert_file, target_file):
        """Append a certificate to a file and keep the PEM format correct.

        A target file that does not end with a newline would give a malformed PEM
        such as:
        -----END CERTIFICATE----------BEGIN CERTIFICATE-----

        Args:
            cert_file: The path of the certificate file to append.
            target_file: The path of the target bundle file.

        Returns:
            bool: True on success.
        """
        if not os.path.exists(cert_file):
            self.print_error(f"Certificate file not found: {cert_file}")
            return False

        if self.certificate_exists_in_file(cert_file, target_file):
            self.print_debug(f"Certificate already exists in {target_file}, skipping append")
            return True

        try:
            with open(cert_file, 'r') as cf:
                cert_content = cf.read()

            if not cert_content.endswith('\n'):
                cert_content = cert_content + '\n'

            needs_leading_newline = False
            if os.path.exists(target_file):
                with open(target_file, 'rb') as tf:
                    tf.seek(0, 2)  # Seek to end
                    if tf.tell() > 0:  # File is not empty
                        tf.seek(-1, 2)  # Seek to last byte
                        last_byte = tf.read(1)
                        # Look for LF, or CR for a CRLF file.
                        if last_byte not in (b'\n', b'\r'):
                            needs_leading_newline = True

            with open(target_file, 'a') as f:
                if needs_leading_newline:
                    f.write('\n')
                f.write(cert_content)

            self._fix_ownership(target_file)
            self.print_info(f"Appended certificate to {target_file}")
            return True

        except Exception as e:
            self.print_error(f"Failed to append certificate to {target_file}: {e}")
            return False

    def _parse_fumitm_block(self, content):
        """Divide shell config content into other lines and the managed block.

        Returns a tuple of (other_lines, managed). other_lines keeps each line
        outside the managed block without a change. This includes the lines of the
        user and a vendor block such as the Aikido block. managed is a dict of the
        variable and value pairs from inside the block, in sequence.

        fumitm pairs the last begin marker with the first end marker after it. Thus
        an old begin marker with no pair is other content, and the end marker of a
        new block does not close it. A begin marker with no end marker is malformed.
        fumitm then keeps all content without a change and reports an empty block,
        thus it appends a new block.
        """
        lines = content.splitlines()
        begin_idx = None
        for i, line in enumerate(lines):
            if line.strip() == self._FUMITM_BLOCK_BEGIN:
                begin_idx = i
        if begin_idx is None:
            return lines, {}

        end_idx = None
        for i in range(begin_idx + 1, len(lines)):
            if lines[i].strip() == self._FUMITM_BLOCK_END:
                end_idx = i
                break
        if end_idx is None:
            self.print_warn(
                "Found an unterminated fumitm block marker in the shell config; "
                "leaving existing content untouched and appending a fresh block"
            )
            return lines, {}

        managed = {}
        for line in lines[begin_idx + 1:end_idx]:
            stripped = line.strip()
            if not stripped.startswith('export '):
                continue
            try:
                name, rhs = stripped[len('export '):].split('=', 1)
            except ValueError:
                continue
            rhs = rhs.strip()
            if (rhs.startswith('"') and rhs.endswith('"')) or \
                    (rhs.startswith("'") and rhs.endswith("'")):
                rhs = rhs[1:-1]
            managed[name.strip()] = rhs

        other_lines = lines[:begin_idx] + lines[end_idx + 1:]
        return other_lines, managed

    def _render_fumitm_block(self, managed):
        """Render the managed export block as text (double-quoted values)."""
        body = [self._FUMITM_BLOCK_BEGIN]
        body.extend(f'export {name}="{value}"' for name, value in managed.items())
        body.append(self._FUMITM_BLOCK_END)
        return '\n'.join(body)

    def _render_stub(self):
        """Render the managed source-stub block placed in each startup file."""
        return '\n'.join([
            self._FUMITM_BLOCK_BEGIN,
            f'[ -r {self._FUMITM_ENV_FILE_SHELL} ] && . {self._FUMITM_ENV_FILE_SHELL}',
            self._FUMITM_BLOCK_END,
        ])

    def _read_text_or_none(self, path):
        """Read a file. Return None if it is absent or unreadable.

        A successful os.path.exists() does not show that the open will succeed. The
        path can be a dangling symlink, be unreadable, or be removed in the
        interval. Callers decide whether None is harmless absence or a fault that
        must fail closed.
        """
        try:
            with open(path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except OSError as e:
            self.print_debug(f"Could not read {path}: {e}")
            return None

    def _write_managed_file(self, path, new, label):
        """Write `new` to `path` and back up the original file one time each run.

        Returns True when the file changed, or would change in dry-run mode. The env
        file and each stub use this method, thus they get the same backup, ownership,
        and dry-run operation.
        """
        original = self._read_text_or_none(path)

        if original == new:
            return False

        if not self.is_install_mode():
            if path not in self._dry_run_reported:
                self.print_action(f"Would update {path} ({label})")
                self._dry_run_reported.add(path)
            return True

        if path not in self._backed_up_shell_configs:
            if original is not None:
                with open(path + '.bak', 'w') as f:
                    f.write(original)
                self._fix_ownership(path + '.bak')
            self._backed_up_shell_configs.add(path)

        self._safe_makedirs(os.path.dirname(path))
        with open(path, 'w') as f:
            f.write(new)
        self._fix_ownership(path)
        self.shell_modified = True
        return True

    def _read_env_file(self):
        """Parse the sourced env file into an insertion-ordered var->value dict."""
        content = self._read_text_or_none(self._env_file_path())
        if content is None:
            return {}

        managed = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.startswith('export '):
                continue
            try:
                name, rhs = stripped[len('export '):].split('=', 1)
            except ValueError:
                continue
            rhs = rhs.strip()
            if (rhs.startswith('"') and rhs.endswith('"')) or \
                    (rhs.startswith("'") and rhs.endswith("'")):
                rhs = rhs[1:-1]
            managed[name.strip()] = rhs
        return managed

    def _write_env_file(self, managed):
        """Write the sourced env file holding every fumitm-managed export."""
        body = [
            "# Managed by fumitm - do not edit; this file is regenerated.",
            "# Sourced from your shell startup files so TLS trust applies to",
            "# interactive, non-interactive and login shells alike.",
        ]
        body.extend(f'export {name}="{value}"' for name, value in managed.items())
        return self._write_managed_file(
            self._env_file_path(), '\n'.join(body) + '\n', 'fumitm exports'
        )

    def _ensure_stub(self, shell_config):
        """Make sure that `shell_config` ends with the managed source stub.

        fumitm removes a managed block that is already present. Thus the stub
        replaces an inline export block from an older fumitm.
        """
        other_lines, _ = self._parse_fumitm_block(
            self._read_text_or_none(shell_config) or ""
        )
        while other_lines and other_lines[-1].strip() == '':
            other_lines.pop()
        prefix = ('\n'.join(other_lines) + '\n\n') if other_lines else ''
        new = prefix + self._render_stub() + '\n'
        return self._write_managed_file(shell_config, new, 'source stub')

    def _legacy_block_vars(self, shell_config):
        """Exports found in an inline managed block written by an older fumitm."""
        content = self._read_text_or_none(shell_config)
        if content is None:
            return {}
        _, managed = self._parse_fumitm_block(content)
        return managed

    def add_to_shell_config(self, var_name, var_value, shell_config=None):
        """Write an export, thus it applies in each mode that the shell runs in.

        For a shell that reads POSIX sh syntax, fumitm writes the value to one env
        file. It then writes a stub with markers at the end of each startup file
        that the shell reads. See get_shell_configs. The stub is always last, thus
        it replaces the settings of an earlier vendor block. fumitm never changes
        that block.

        fish and the csh shells keep the inline block in their own config file,
        because they cannot read POSIX sh syntax.

        Args:
            shell_config: An optional startup file to add a stub to, with the
                standard set of the shell. Callers that resolved a path can
                continue to give it.

        Returns:
            bool: True when something changed, or would change in dry-run mode. The
            gcloud setup uses this result to report a pre-bootstrap write.
        """
        shell_type = self.detect_shell()

        if not self._uses_env_file(shell_type):
            return self._write_inline_block(
                var_name, var_value,
                shell_config or self.get_shell_config(shell_type),
            )

        targets = self.get_shell_configs(shell_type)
        if shell_config and shell_config not in targets:
            targets.append(shell_config)

        # Take the values from a legacy inline block first, thus an upgrade
        # keeps what an older fumitm configured. The env file wins when both
        # have the same variable.
        #
        # Always write the merged set. Do not stop when the value is already
        # correct. The stub replaces the legacy block and removes its exports,
        # thus each value from that block must reach the env file.
        existing = self._read_env_file()
        managed = {}
        for path in targets:
            managed.update(self._legacy_block_vars(path))
        managed.update(existing)
        managed[var_name] = var_value

        # _write_env_file compares content, so an unchanged set stays a no-op.
        changed = self._write_env_file(managed)
        if changed and existing.get(var_name) != var_value:
            if self.is_install_mode():
                self.print_info(f"Set {var_name} in {self._env_file_path()}")
            else:
                self.print_action(f'export {var_name}="{var_value}"')

        for path in targets:
            if self._ensure_stub(path):
                changed = True

        return changed

    def _write_inline_block(self, var_name, var_value, shell_config):
        """Write an export into the managed inline block, which is always last.

        This is the operation from before the env file. Shells that cannot source a
        POSIX sh file use it. fumitm keeps an earlier export of the user but
        replaces its value.
        """
        original = None
        if os.path.exists(shell_config):
            with open(shell_config, 'r') as f:
                original = f.read()

        other_lines, managed = self._parse_fumitm_block(original or "")
        managed[var_name] = var_value

        while other_lines and other_lines[-1].strip() == '':
            other_lines.pop()
        prefix = ('\n'.join(other_lines) + '\n\n') if other_lines else ''
        new = prefix + self._render_fumitm_block(managed) + '\n'

        changed = original is None or new != original

        if not self.is_install_mode():
            if changed:
                self.print_action(f"Would add to {shell_config}:")
                self.print_action(f'export {var_name}="{var_value}"')
            return changed

        if not changed:
            return False

        if shell_config not in self._backed_up_shell_configs:
            if original is not None:
                with open(shell_config + '.bak', 'w') as f:
                    f.write(original)
                self._fix_ownership(shell_config + '.bak')
            self._backed_up_shell_configs.add(shell_config)

        # fish keeps its config under ~/.config/fish, which may not exist yet.
        self._safe_makedirs(os.path.dirname(shell_config))
        with open(shell_config, 'w') as f:
            f.write(new)
        self._fix_ownership(shell_config)
        self.shell_modified = True
        self.print_info(f"Set {var_name} in {shell_config}")
        return True

    def is_devcontainer(self):
        """Check if running inside a VS Code devcontainer."""
        if os.environ.get('REMOTE_CONTAINERS') or os.environ.get('CODESPACES'):
            return True
        
        if os.path.exists('/.dockerenv'):
            return True
        
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup = f.read()
                if 'docker' in cgroup or 'containerd' in cgroup:
                    return True
        except Exception:
            pass
        
        try:
            with open('/proc/version', 'r') as f:
                version = f.read().lower()
                if 'microsoft' in version or 'wsl' in version:
                    # In WSL, check if warp-cli exists on Windows side
                    warp_cli_win = shutil.which('warp-cli.exe')
                    if not warp_cli_win and not self.command_exists('warp-cli'):
                        return True
        except Exception:
            pass
        
        return False
    
    def get_certificate_from_user(self):
        """Prompt user to manually provide the certificate."""
        print()
        self.print_info("=" * 70)
        self.print_info("Devcontainer Detected - Manual Certificate Setup")
        self.print_info("=" * 70)
        print()
        self.print_info("You're running fumitm inside a devcontainer where warp-cli isn't available.")
        self.print_info("The proxy certificate needs to be obtained from your Windows host machine.")
        print()
        self.print_info("QUICKEST METHOD:")
        self.print_info("1. On your Windows host, open PowerShell/Terminal and run:")
        self.print_info(f"   {BLUE}warp-cli certs --no-paginate{NC}")
        self.print_info("2. Copy the entire output (including BEGIN/END lines)")
        self.print_info("3. Come back here and paste it")
        print()
        self.print_info("ALTERNATIVE METHOD:")
        self.print_info("1. Save the certificate to a file accessible from this container")
        self.print_info("2. Run: ./fumitm.py --fix --cert-file /path/to/cert.pem")
        print()
        
        if self.auto_yes:
            self.print_error("Manual certificate input requires an interactive terminal. "
                             "Use --cert-file to provide the certificate non-interactively.")
            return None

        choice = input("Ready to paste? Press ENTER to continue, 'F' for file path, or 'Q' to quit: ").strip().upper()
        
        if choice == 'Q':
            return None
        elif choice == 'F':
            file_path = input("Enter the path to the certificate file: ").strip()
            if not file_path:
                self.print_error("No file path provided")
                return None
            
            file_path = os.path.expanduser(file_path)
            
            if not os.path.exists(file_path):
                self.print_error(f"File not found: {file_path}")
                return None
            
            try:
                with open(file_path, 'r') as f:
                    cert_content = f.read()
                self.print_info(f"Certificate loaded from {file_path}")
            except Exception as e:
                self.print_error(f"Error reading file: {e}")
                return None
        else:
            # Paste mode is the default, because it is easier.
            print()
            self.print_info("Paste the certificate now (Ctrl+V or right-click paste)")
            self.print_info("Then press Enter twice when done:")
            print()
            
            lines = []
            while True:
                try:
                    line = input()
                    if not line and lines and lines[-1] == "":
                        break
                    lines.append(line)
                except EOFError:
                    break
            
            cert_content = '\n'.join(lines[:-1] if lines and lines[-1] == "" else lines)
        
        if not cert_content.strip():
            self.print_error("No certificate provided")
            return None
        
        if "-----BEGIN CERTIFICATE-----" not in cert_content:
            self.print_error("Invalid certificate format: missing BEGIN CERTIFICATE marker")
            return None
        
        if "-----END CERTIFICATE-----" not in cert_content:
            self.print_error("Invalid certificate format: missing END CERTIFICATE marker")
            return None
        
        cert_lines = cert_content.strip().split('\n')
        formatted_cert = '\n'.join(cert_lines) + '\n'
        
        return formatted_cert
    
    def _get_warp_cert(self):
        """Get the CA certificate from warp-cli.

        Returns:
            str or None: The PEM certificate text, or None on a failure.
        """
        try:
            result = subprocess.run(
                ['warp-cli', 'certs', '--no-paginate'],
                capture_output=True, text=True, check=False
            )
            if result.returncode != 0 or not result.stdout.strip():
                self.print_error("Failed to get certificate from warp-cli")
                self.print_error("Make sure you are connected to Cloudflare WARP")
                return None
            return result.stdout.strip()
        except Exception as e:
            self.print_error(f"Error running warp-cli: {e}")
            return None

    def _get_netskope_cert(self):
        """Get the Netskope CA certificate.

        fumitm tries these sources in this sequence:
        1. The known file paths: nscacert_combined.pem, then nscacert.pem.
        2. The macOS Keychain, for the root and the intermediate.
        3. An encrypted .enc certificate. fumitm then tells the user to use
           --cert-file.

        Returns:
            str or None: The PEM certificate text, or None on a failure.
        """
        plat = platform.system()
        cert_sources = self.provider.get('cert_sources', {}).get(plat, [])

        for path in cert_sources:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read().strip()
                    if '-----BEGIN CERTIFICATE-----' in content:
                        self.print_info(f"Using Netskope certificate from {path}")
                        return content
                except Exception as e:
                    self.print_debug(f"Could not read {path}: {e}")

        # The encryptClientConfig flag encrypts the certificates on disk.
        # Record this and try the keychain.
        found_encrypted = False
        for path in cert_sources:
            enc_path = path + '.enc'
            if os.path.exists(enc_path):
                found_encrypted = True
                self.print_info(f"Found encrypted Netskope certificate at {enc_path}")
                self.print_info("  This usually means the encryptClientConfig hardening flag is enabled")
                break

        # macOS keychain fallback: extract root and intermediate CAs
        if plat == 'Darwin':
            if found_encrypted:
                self.print_info("  Attempting to extract certificate from macOS System Keychain instead...")
            result = self._get_netskope_cert_from_keychain()
            if result:
                return result

        if found_encrypted:
            self.print_error("Could not extract Netskope certificate from keychain")
            self.print_error("Use --cert-file to provide the certificate manually, or download it from")
            self.print_error("  your Netskope tenant at Settings > Manage > Certificates")
        else:
            self.print_error("Could not find Netskope certificate")
            self.print_error("Use --cert-file to provide the certificate manually")
        return None

    def _get_netskope_cert_from_keychain(self):
        """Get the Netskope root and intermediate CAs from the macOS System Keychain.

        The CN of the root usually contains "certadmin" and the CN of the
        intermediate contains "goskope". The -c flag of security find-certificate
        matches a substring, thus it accepts a variant such as ca.thg.goskope.com.

        Returns:
            str or None: The combined PEM text, or None on a failure.
        """
        certs = []

        # Root CA (CN contains "certadmin")
        try:
            result = subprocess.run(
                ['security', 'find-certificate', '-c', 'certadmin', '-p',
                 '/Library/Keychains/System.keychain'],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0 and '-----BEGIN CERTIFICATE-----' in result.stdout:
                certs.append(result.stdout.strip())
                self.print_debug("Found Netskope root CA in System Keychain")
        except Exception as e:
            self.print_debug(f"Keychain root CA search failed: {e}")

        if not certs:
            self.print_error("Could not find Netskope root CA in macOS System Keychain")
            self.print_error("Use --cert-file to provide the certificate manually")
            return None

        # Intermediate CA (CN contains "goskope")
        try:
            result = subprocess.run(
                ['security', 'find-certificate', '-c', 'goskope', '-p',
                 '/Library/Keychains/System.keychain'],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0 and '-----BEGIN CERTIFICATE-----' in result.stdout:
                certs.append(result.stdout.strip())
                self.print_debug("Found Netskope intermediate CA in System Keychain")
            else:
                self.print_warn("Netskope intermediate CA not found in keychain; proceeding with root CA only")
        except Exception as e:
            self.print_debug(f"Keychain intermediate CA search failed: {e}")
            self.print_warn("Could not search for Netskope intermediate CA; proceeding with root CA only")

        self.print_info("Using Netskope certificate(s) from macOS System Keychain")
        return '\n'.join(certs)

    def download_certificate(self):
        """Download and verify certificate."""
        provider_name = self.provider['name']
        self.print_info(f"Retrieving {provider_name} certificate...")
        
        warp_cert = None
        
        # Priority 1: Use certificate file if provided via command line
        if self.cert_file:
            cert_file_path = os.path.expanduser(self.cert_file)
            if not os.path.exists(cert_file_path):
                self.print_error(f"Certificate file not found: {cert_file_path}")
                return False
            
            try:
                with open(cert_file_path, 'r') as f:
                    warp_cert = f.read()
                self.print_info(f"Using certificate from file: {cert_file_path}")
            except Exception as e:
                self.print_error(f"Error reading certificate file: {e}")
                return False
        
        # Priority 2: Force manual input if requested
        elif self.manual_cert:
            self.print_info("Manual certificate mode enabled")
            warp_cert = self.get_certificate_from_user()
            if not warp_cert:
                return False
        
        # Priority 3: Auto-detect devcontainer/WSL without native CLI
        elif self.is_devcontainer() and not self.command_exists('warp-cli'):
            if os.path.exists(self.cert_path):
                self.print_info(f"Found existing certificate at {self.cert_path}")
                if self.is_install_mode():
                    response = self._prompt("Do you want to update it with a new certificate? (y/N) ")
                    if response.lower() == 'y':
                        warp_cert = self.get_certificate_from_user()
                        if not warp_cert:
                            return False
                    else:
                        with open(self.cert_path, 'r') as f:
                            warp_cert = f.read()
                        self.print_info("Using existing certificate")
                else:
                    with open(self.cert_path, 'r') as f:
                        warp_cert = f.read()
                    self.print_info("Using existing certificate for status check")
            else:
                warp_cert = self.get_certificate_from_user()
                if not warp_cert:
                    self.print_error("Cannot proceed without a certificate in devcontainer environment")
                    self.print_info("Tip: Run './fumitm.py --fix' to set up the certificate")
                    return False

        # Priority 4: Provider-specific certificate retrieval
        elif self.provider is PROVIDERS['warp']:
            warp_cert = self._get_warp_cert()
            if not warp_cert:
                return False
        elif self.provider is PROVIDERS['netskope']:
            warp_cert = self._get_netskope_cert()
            if not warp_cert:
                return False
        else:
            self.print_error(f"{provider_name} provider has no certificate retrieval method.")
            return False
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
            temp_cert.write(warp_cert)
            temp_cert_path = temp_cert.name
        
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-in', temp_cert_path],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                self.print_error("Retrieved file is not a valid PEM certificate")
                os.unlink(temp_cert_path)
                return False
        except Exception as e:
            self.print_error(f"Error verifying certificate: {e}")
            os.unlink(temp_cert_path)
            return False
        
        self.print_info(f"{provider_name} certificate retrieved successfully")

        needs_save = False
        if os.path.exists(self.cert_path):
            with open(self.cert_path, 'r') as f:
                existing_cert = f.read()

            if existing_cert != warp_cert:
                self.print_info(f"Certificate at {self.cert_path} needs updating")
                needs_save = True
            else:
                self.print_info(f"Certificate at {self.cert_path} is up to date")
        else:
            self.print_info(f"Certificate will be saved to {self.cert_path}")
            needs_save = True

        if needs_save:
            if not self.is_install_mode():
                self.print_action(f"Would save certificate to {self.cert_path}")
            else:
                shutil.copy(temp_cert_path, self.cert_path)
                self._fix_ownership(self.cert_path)
                self.print_info(f"Certificate saved to {self.cert_path}")

        os.unlink(temp_cert_path)
        
        self.get_cert_fingerprint()

        return True

    def _prepare_extra_roots(self):
        """Write each supplemental root CA that fumitm detected to a file.

        In install mode fumitm writes the root to its permanent cert_path and
        corrects the ownership. In status mode it writes to a temporary file and
        removes that file later. Each entry that stays gets a 'path' key. fumitm
        removes an entry when it cannot get or validate the root, thus the assembly
        of the bundle ignores it.
        """
        if not self.extra_roots:
            return
        getters = {'aikido': self._get_aikido_root_cert}
        resolved = []
        for entry in self.extra_roots:
            if entry.get('path'):
                resolved.append(entry)
                continue
            getter = getters.get(entry['key'])
            pem = getter() if getter else None
            if not pem:
                continue
            if not self._is_valid_pem_cert(pem):
                self.print_warn(f"{entry['name']} root certificate is not valid PEM; skipping")
                continue
            path = self._write_extra_root(entry, pem)
            if path:
                entry['path'] = path
                resolved.append(entry)
        self.extra_roots = resolved

    def _is_valid_pem_cert(self, pem_text):
        """Return True if pem_text starts with a certificate openssl can parse."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                tf.write(pem_text)
                tmp = tf.name
        except Exception:
            return False
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-in', tmp], capture_output=True, check=False
            )
            return result.returncode == 0
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _write_extra_root(self, entry, pem_text):
        """Write a supplemental root's PEM to disk and return its path, or None."""
        if not pem_text.endswith('\n'):
            pem_text = pem_text + '\n'
        if self.is_install_mode():
            path = os.path.expanduser(entry['cert_path'])
            try:
                with open(path, 'w') as f:
                    f.write(pem_text)
                self._fix_ownership(path)
                self.print_info(f"Saved {entry['name']} root CA to {path}")
                return path
            except Exception as e:
                self.print_error(f"Could not save {entry['name']} root CA: {e}")
                return None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                tf.write(pem_text)
                path = tf.name
            self._extra_root_temp_files.append(path)
            return path
        except Exception as e:
            self.print_debug(f"Could not write temp {entry['name']} root: {e}")
            return None

    def _cleanup_extra_root_temp_files(self):
        """Remove any temp files created for supplemental roots in status mode."""
        for path in self._extra_root_temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._extra_root_temp_files = []

    def _announce_extra_roots(self):
        """Print a one-line notice for each active supplemental root CA."""
        for entry in self.extra_roots:
            if entry.get('path'):
                self.print_info(
                    f"{entry['name']} detected. fumitm adds its supplemental root CA "
                    f"to the managed bundles with the {self.provider['short_name']} root"
                )

    def _all_proxy_root_paths(self):
        """Return the path of each CA root that a bundle must contain.

        The list starts with the primary provider certificate. Each supplemental
        root that fumitm materialized comes after it. With no supplemental root the
        list is [self.cert_path].
        """
        paths = [self.cert_path]
        paths.extend(e['path'] for e in self.extra_roots if e.get('path'))
        return paths

    def _append_all_proxy_roots(self, target_file):
        """Append the primary root and each supplemental root to target_file.

        safe_append_certificate makes each append idempotent. Returns True only if
        fumitm appended each root, or each root was already present.
        """
        ok = True
        for path in self._all_proxy_root_paths():
            if not self.safe_append_certificate(path, target_file):
                ok = False
        return ok

    def _all_roots_present_in_file(self, target_file, likely=False):
        """Return True only if each proxy root is already in target_file.

        With likely=True this uses the faster pure-Python matcher. With no
        supplemental root this is one check of the primary certificate.
        """
        matcher = (self.certificate_likely_exists_in_file if likely
                   else self.certificate_exists_in_file)
        return all(
            matcher(path, target_file)
            for path in self._all_proxy_root_paths()
        )

    def _status_roots_present(self, primary_cert_path, target_file, likely=False):
        """Find if each root is present, in status mode.

        Uses the given primary certificate path with each supplemental root that
        fumitm materialized. The primary path is usually a temporary file, because a
        status check does not write cert_path. With no supplemental root this is one
        check of the primary certificate.
        """
        matcher = (self.certificate_likely_exists_in_file if likely
                   else self.certificate_exists_in_file)
        if not matcher(primary_cert_path, target_file):
            return False
        for entry in self.extra_roots:
            if entry.get('path') and not matcher(entry['path'], target_file):
                return False
        return True

    def _all_root_aliases(self):
        """Return (keytool_alias, cert_path) for the primary and each supplemental root."""
        pairs = [(self.provider['keytool_alias'], self.cert_path)]
        pairs.extend(
            (e['keytool_alias'], e['path']) for e in self.extra_roots if e.get('path')
        )
        return pairs

    def _split_pem_certificates(self, cert_path):
        """Return each PEM certificate in cert_path as a standalone string."""
        try:
            with open(cert_path, 'r') as f:
                content = f.read()
        except OSError:
            return []

        certs = []
        current = []
        in_cert = False
        for line in content.splitlines():
            if '-----BEGIN CERTIFICATE-----' in line:
                current = ['-----BEGIN CERTIFICATE-----']
                in_cert = True
                continue
            if not in_cert:
                continue
            current.append(line)
            if '-----END CERTIFICATE-----' in line:
                certs.append('\n'.join(current) + '\n')
                current = []
                in_cert = False
        return certs

    def _expanded_alias_names(self, alias_pairs):
        """Return the alias names that a split PEM chain would import under."""
        names = []
        for alias, cert_path in alias_pairs:
            certs = self._split_pem_certificates(cert_path)
            if len(certs) <= 1:
                names.append(alias)
                continue
            for idx, _ in enumerate(certs, start=1):
                names.append(alias if idx == 1 else f'{alias}-{idx}')
        return names

    def _materialize_alias_pairs(self, alias_pairs, split_chains=False):
        """Return importable (alias, path) pairs and temp files for PEM chains."""
        if not split_chains:
            return alias_pairs, []

        pairs = []
        temp_paths = []
        for alias, cert_path in alias_pairs:
            certs = self._split_pem_certificates(cert_path)
            if len(certs) <= 1:
                pairs.append((alias, cert_path))
                continue
            for idx, cert_text in enumerate(certs, start=1):
                with tempfile.NamedTemporaryFile(
                        mode='w', suffix='.pem', delete=False) as tf:
                    tf.write(cert_text)
                    temp_path = tf.name
                temp_paths.append(temp_path)
                expanded_alias = alias if idx == 1 else f'{alias}-{idx}'
                pairs.append((expanded_alias, temp_path))
        return pairs, temp_paths

    def _detect_keystore_type(self, keystore, storepass='changeit'):
        """Return the keystore type reported by keytool, or an empty string."""
        try:
            result = subprocess.run(
                ['keytool', '-list', '-keystore', keystore, '-storepass', storepass],
                capture_output=True, text=True, check=False
            )
        except Exception as e:
            self.print_debug(f"Could not detect keystore type for {keystore}: {e}")
            return ''

        if result.returncode != 0:
            return ''
        for line in result.stdout.splitlines():
            if line.lower().startswith('keystore type:'):
                return line.split(':', 1)[1].strip()
        return ''

    def _keytool_alias_present(self, keytool_bin, keystore, alias, storetype=None):
        """Return True if alias is already present in the Java keystore."""
        try:
            cmd = [keytool_bin, '-list', '-alias', alias,
                   '-keystore', keystore, '-storepass', 'changeit']
            if storetype:
                cmd.extend(['-storetype', storetype])
            result = subprocess.run(
                cmd,
                capture_output=True, check=False
            )
            stdout = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
            return result.returncode == 0 and alias in stdout
        except Exception:
            return False

    def _keytool_keystore_fingerprints(self, keytool_bin, keystore, storetype=None):
        """Return certificate fingerprints in a keystore, or None on uncertainty.

        ``keytool -list -rfc`` emits each trusted certificate as PEM. Certificate
        identity is independent of its alias, so this also finds roots installed
        by another product under a vendor-specific name.
        """
        try:
            cmd = [keytool_bin, '-list', '-rfc', '-keystore', keystore,
                   '-storepass', 'changeit']
            if storetype:
                cmd.extend(['-storetype', storetype])
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                return None
            stdout = result.stdout
            if not stdout or '-----BEGIN CERTIFICATE-----' not in stdout:
                return None
            return set(self._pem_fingerprints(stdout, keystore))
        except Exception as e:
            self.print_debug(f"Could not list certificate identities in {keystore}: {e}")
            return None

    def _keystore_has_cert_path(self, fingerprints, cert_path):
        """Return whether a keystore fingerprint set contains cert_path's entry.

        Java's historical non-split import uses the first certificate from a PEM
        chain for one trusted-certificate alias. Split-chain callers materialize
        one certificate per file, so the same rule applies to both forms.
        """
        desired = self._cert_fingerprints(cert_path)
        return bool(desired and desired[0] in fingerprints)

    def _keystore_has_expected_roots(
            self, keytool_bin, keystore, storetype=None,
            primary_cert_path=None):
        """Return True only when every available proxy root is in a keystore.

        This predicate deliberately has no alias fallback. Callers use it as a
        safety gate before removing another trust path, so an unparseable keytool
        listing is uncertainty rather than proof that the keystore is ready.
        """
        fingerprints = self._keytool_keystore_fingerprints(
            keytool_bin, keystore, storetype=storetype
        )
        if fingerprints is None:
            return False
        alias_pairs = self._all_root_aliases()
        if primary_cert_path:
            alias_pairs[0] = (alias_pairs[0][0], primary_cert_path)
        return all(
            self._keystore_has_cert_path(fingerprints, cert_path)
            for _, cert_path in alias_pairs
        )

    def _ensure_roots_in_keystore(self, keytool_bin, keystore, label, storetype=None,
                                  alias_pairs=None, split_chains=False):
        """Import the primary root and each supplemental root into a Java keystore.

        Each root gets its own alias. fumitm does not import a root that is already
        present. Returns 'already_ok', 'configured', or 'failed' for the full
        keystore.
        """
        imported = False
        failed = False
        alias_pairs = alias_pairs if alias_pairs is not None else self._all_root_aliases()
        alias_pairs, temp_paths = self._materialize_alias_pairs(
            alias_pairs, split_chains=split_chains
        )
        keystore_fingerprints = self._keytool_keystore_fingerprints(
            keytool_bin, keystore, storetype=storetype
        )
        try:
            for alias, cert_path in alias_pairs:
                desired_fingerprint = None
                if keystore_fingerprints is not None:
                    if self._keystore_has_cert_path(
                        keystore_fingerprints, cert_path
                    ):
                        continue
                    desired = self._cert_fingerprints(cert_path)
                    if not desired:
                        self.print_warn(
                            f"    ✗ {label}: Could not identify {alias} certificate"
                        )
                        failed = True
                        continue
                    desired_fingerprint = desired[0]
                alias_present = self._keytool_alias_present(
                    keytool_bin, keystore, alias, storetype=storetype
                )
                if keystore_fingerprints is None and alias_present:
                    # Preserve the old idempotency check when keytool cannot give
                    # a parseable RFC listing. The result is uncertain, not absent.
                    continue
                if keystore_fingerprints is not None and alias_present:
                    self.print_warn(
                        f"    ✗ {label}: {alias} exists with a different certificate"
                    )
                    if not self.is_install_mode():
                        self.print_action(
                            f"    Would replace {alias} in: {keystore}"
                        )
                        imported = True
                        continue
                    delete_cmd = [
                        keytool_bin, '-delete', '-alias', alias,
                        '-keystore', keystore, '-storepass', 'changeit'
                    ]
                    if storetype:
                        delete_cmd.extend(['-storetype', storetype])
                    delete_result = subprocess.run(
                        delete_cmd, capture_output=True, text=True, check=False
                    )
                    if delete_result.returncode != 0:
                        self.print_warn(
                            f"    ✗ {label}: Failed to remove outdated {alias}"
                        )
                        self.print_info("      Fix with:")
                        command = (
                            f"        sudo {keytool_bin} -delete -alias {alias}"
                            f" -keystore {keystore} -storepass changeit"
                        )
                        if storetype:
                            command += f" -storetype {storetype}"
                        print(command)
                        if delete_result.stdout:
                            self.print_warn(
                                f"      Keytool response: {delete_result.stdout}"
                            )
                        failed = True
                        continue
                    self.print_info(
                        f"    ✓ {label}: outdated {alias} removed"
                    )
                if not self.is_install_mode():
                    self.print_action(f"    Would import {alias} certificate to: {keystore}")
                    imported = True
                    continue
                cmd = [keytool_bin, '-import', '-trustcacerts', '-alias', alias,
                       '-file', cert_path, '-keystore', keystore, '-storepass', 'changeit']
                if storetype:
                    cmd.extend(['-storetype', storetype])
                cmd.append('-noprompt')
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    self.print_info(f"    ✓ {label}: {alias} added successfully")
                    imported = True
                    if keystore_fingerprints is not None and desired_fingerprint:
                        keystore_fingerprints.add(desired_fingerprint)
                else:
                    self.print_warn(f"    ✗ {label}: Failed to add {alias} (may require sudo)")
                    self.print_info("      Fix with:")
                    print(f"        sudo {keytool_bin} -import -trustcacerts \\")
                    print(f"          -alias {alias} \\")
                    print(f"          -file {cert_path} \\")
                    print(f"          -keystore {keystore} \\")
                    if storetype:
                        print(f"          -storetype {storetype} \\")
                    print("          -storepass changeit -noprompt")
                    if result.stdout:
                        self.print_warn(f"      Keytool response: {result.stdout}")
                    failed = True
        finally:
            for path in temp_paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        if failed:
            return 'failed'
        if imported:
            return 'configured'
        return 'already_ok'

    def _gradle_custom_truststore_has_roots(self, gradle_cacerts):
        """Return True if the managed Gradle truststore contains every proxy CA."""
        if not os.path.exists(gradle_cacerts):
            return False
        alias_pairs, temp_paths = self._materialize_alias_pairs(
            self._all_root_aliases(), split_chains=True
        )
        try:
            fingerprints = self._keytool_keystore_fingerprints(
                'keytool', gradle_cacerts, storetype='PKCS12'
            )
            if fingerprints is not None:
                return all(
                    self._keystore_has_cert_path(fingerprints, cert_path)
                    for _, cert_path in alias_pairs
                )
            return all(
                self._keytool_alias_present(
                    'keytool', gradle_cacerts, alias, storetype='PKCS12'
                )
                for alias, _ in alias_pairs
            )
        finally:
            for path in temp_paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def ensure_gradle_custom_truststore(self, source_cacerts, gradle_cacerts):
        """Ensure Gradle's managed PKCS12 truststore exists and contains proxy roots."""
        if self._gradle_custom_truststore_has_roots(gradle_cacerts):
            return 'already_ok'

        if not self.is_install_mode():
            self.print_action(
                f"Would rebuild Gradle PKCS12 truststore at {gradle_cacerts} "
                f"from {source_cacerts}"
            )
            return 'skipped'

        source_type = self._detect_keystore_type(source_cacerts)
        if not source_type:
            self.print_error(f"Could not determine keystore type for {source_cacerts}")
            return 'failed'

        self._safe_makedirs(os.path.dirname(gradle_cacerts))
        fd, temp_keystore = tempfile.mkstemp(
            prefix='custom-cacerts-', suffix='.p12', dir=os.path.dirname(gradle_cacerts)
        )
        os.close(fd)
        try:
            os.unlink(temp_keystore)
        except OSError:
            pass

        try:
            result = subprocess.run(
                ['keytool', '-importkeystore', '-noprompt',
                 '-srckeystore', source_cacerts, '-srcstorepass', 'changeit',
                 '-srcstoretype', source_type,
                 '-destkeystore', temp_keystore, '-deststorepass', 'changeit',
                 '-deststoretype', 'PKCS12'],
                capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                self.print_error("Failed to seed Gradle custom truststore from Java cacerts")
                if result.stdout:
                    self.print_warn(result.stdout)
                if result.stderr:
                    self.print_warn(result.stderr)
                return 'failed'

            status = self._ensure_roots_in_keystore(
                'keytool', temp_keystore, 'Gradle custom truststore',
                storetype='PKCS12', split_chains=True
            )
            if status == 'failed':
                return 'failed'

            shutil.move(temp_keystore, gradle_cacerts)
            self._fix_ownership(gradle_cacerts)
            self.print_info(f"Rebuilt Gradle custom truststore at {gradle_cacerts}")
            return 'configured'
        finally:
            if os.path.exists(temp_keystore):
                try:
                    os.unlink(temp_keystore)
                except OSError:
                    pass

    def _all_container_certs(self):
        """Return (container_cert_name, cert_path) for the primary and each supplemental root."""
        pairs = [(self.provider['container_cert_name'], self.cert_path)]
        pairs.extend(
            (e['container_cert_name'], e['path']) for e in self.extra_roots if e.get('path')
        )
        return pairs

    def _container_certs_present(self, docker_certs_dir):
        """Return True if every proxy root is present in ~/.docker/certs.d."""
        for name, cert_path in self._all_container_certs():
            dest = os.path.join(docker_certs_dir, f"{name}.crt")
            if not (os.path.exists(dest)
                    and self.certificate_likely_exists_in_file(cert_path, dest)):
                return False
        return True

    def _status_container_certs_present(self, primary_cert_path, docker_certs_dir):
        """Find if each proxy root is in its own file, in status mode.

        Install writes the primary root and each supplemental root to a separate
        {container_cert_name}.crt file. Thus fumitm must examine each file. The
        primary root goes against the given temporary certificate, because status
        mode can leave cert_path unwritten.
        """
        primary_dest = os.path.join(
            docker_certs_dir, f"{self.provider['container_cert_name']}.crt"
        )
        if not (os.path.exists(primary_dest)
                and self.certificate_likely_exists_in_file(primary_cert_path, primary_dest)):
            return False
        for entry in self.extra_roots:
            if not entry.get('path'):
                continue
            dest = os.path.join(docker_certs_dir, f"{entry['container_cert_name']}.crt")
            if not (os.path.exists(dest)
                    and self.certificate_likely_exists_in_file(entry['path'], dest)):
                return False
        return True

    def _install_container_certs(self, docker_certs_dir):
        """Copy every proxy root into ~/.docker/certs.d as {name}.crt."""
        self._safe_makedirs(docker_certs_dir)
        for name, cert_path in self._all_container_certs():
            dest = os.path.join(docker_certs_dir, f"{name}.crt")
            shutil.copy(cert_path, dest)
            self._fix_ownership(dest)
            self.print_info(f"Certificate installed to {dest}")

    def _get_brew_prefix(self):
        """Return the Homebrew prefix directory.

        Runs `brew --prefix` and validates the output. If the command fails or gives
        no output, fumitm uses a default: /opt/homebrew on Apple Silicon and
        /usr/local on Intel macOS.
        """
        default = (
            '/opt/homebrew'
            if platform.machine() == 'arm64'
            else '/usr/local'
        )
        try:
            result = subprocess.run(
                ['brew', '--prefix'],
                capture_output=True, text=True, check=False
            )
            prefix = result.stdout.strip()
            if result.returncode == 0 and prefix:
                return prefix
            self.print_debug(
                f"brew --prefix failed (rc={result.returncode}), "
                f"using default {default}"
            )
        except Exception:
            self.print_debug(
                f"brew --prefix raised an exception, "
                f"using default {default}"
            )
        return default

    def _stage_adoption_cert(self):
        """Copy the primary root into a private temporary file for adoption.

        The materialized root is in a home directory that the target user can write.
        That user could replace the file between the checks of fumitm and the
        privileged read. mkstemp makes the staged copy with mode 0600, and the
        invoking user owns it. Each read in the adoption sequence gets the same
        bytes: the idempotency check, the doctor, and the verification after the
        run. Returns None when the root is absent or unreadable.
        """
        try:
            with open(self.cert_path, 'rb') as f:
                content = f.read()
        except OSError:
            return None
        fd, staged = tempfile.mkstemp(prefix='fumitm-aikido-adopt-', suffix='.pem')
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        return staged

    @staticmethod
    def _trusted_system_executable(path):
        """Examine an executable before fumitm runs it as root.

        Returns `(resolved_path, None)` when the path is trusted, or `(None,
        reason)` with the disqualification. fumitm reports the reason to the user. A
        message with the incorrect cause is worse than no message.

        The aikido-adopt tool can run this binary as root. Thus a path from the PATH
        of a target user is not trusted because it is present. Root must own the
        executable, and no other user can have write access to it. A group-writable
        executable is always rejected, because a member of that group could change
        the bytes of the binary without root.

        Root must also own each parent directory, and no other user can have write
        access. But a directory can be group-writable if the group is in
        PRIVILEGED_GROUPS.

        That exemption leaves one risk. Write access to a directory permits an
        unlink and a new file with the same name. Thus a process that is a member of
        admin can replace the executable between this check and the privileged run.
        The symlink resolution makes the interval short but does not remove it.
        fumitm accepts this risk for the same reason as PRIVILEGED_GROUPS: a member
        of admin can already use sudo and can run the doctor directly.
        """
        try:
            resolved = os.path.realpath(path)
            if not os.path.isabs(resolved) or not os.path.isfile(resolved):
                return None, 'not an absolute path to a regular file'
            if not os.access(resolved, os.X_OK):
                return None, 'not executable'

            current = resolved
            is_executable = True
            while True:
                info = os.stat(current)
                if info.st_uid != 0:
                    return None, f'{current} is not owned by root'
                if info.st_mode & stat.S_IWOTH:
                    return None, f'{current} is world-writable'
                if info.st_mode & stat.S_IWGRP and (
                        is_executable or info.st_gid not in PRIVILEGED_GROUPS):
                    return None, f'{current} is group-writable'
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
                is_executable = False
            return resolved, None
        except OSError as e:
            return None, f'could not be inspected: {e}'

    def _find_aikido_doctor(self):
        """Find aikido-doctor and do not select an untrusted executable.

        fumitm reports a rejected candidate at the debug level. A binary that is
        present but rejected and a binary that is absent need different corrections.
        """
        for directory in os.environ.get('PATH', '').split(os.pathsep):
            directory = directory or os.curdir
            candidate = os.path.join(directory, 'aikido-doctor')
            trusted, reason = self._trusted_system_executable(candidate)
            if trusted:
                return trusted
            # Use lexists and not exists. A dangling symlink is the usual
            # shape of a broken install, and exists() follows the link and
            # hides it.
            if os.path.lexists(candidate):
                self.print_debug(f"Ignoring {candidate}: {reason}")
        return None

    def _aikido_doctor_supports_adopt(self, doctor):
        """Return True when this aikido-doctor has the `certconfig adopt` subcommand.

        fumitm asks and does not assume. For an unknown subcommand the CLI writes
        "Unknown command" to stdout and exits zero. Thus an agent from before
        `certconfig` passes the return-code check. Only the verification after the
        adoption finds it, and that gives a failure. Such a host would stay red at
        each scheduled run.

        `certconfig --help` needs no privilege, takes a few milliseconds, and gives
        the names of the subcommands. Thus the answer comes from the CLI and not
        from a match against an error message.
        """
        if self._aikido_adopt_supported is None:
            try:
                result = subprocess.run([doctor, 'certconfig', '--help'],
                                        capture_output=True, text=True,
                                        check=False, timeout=30)
                listing = f'{result.stdout}\n{result.stderr}'
            except (subprocess.SubprocessError, OSError) as e:
                self.print_debug(f"Could not ask {doctor} for its certconfig commands: {e}")
                return False
            self._aikido_adopt_supported = bool(
                re.search(r'^\s+adopt\b', listing, re.MULTILINE))
        return self._aikido_adopt_supported

    def setup_aikido_adopt(self):
        """Adopt the primary provider root into the CA bundles of Aikido.

        A recent Aikido agent has `aikido-doctor certconfig adopt <pem>`. It records
        an external root and builds each bundle that it keeps current around that
        root: node, npm, pip, git, ruby, curl, nix, and bazel. Thus the bundles that
        Aikido sets in the environment also trust the primary provider. The other
        protections stay for a host with an older agent: the reclaim of the trust
        variables, the curlrc override, and the exports that stay last.
        """
        if not any(e['key'] == 'aikido' for e in self.extra_roots):
            return ToolResult('aikido-adopt', 'skipped', 'Aikido not active')
        if platform.system() != 'Darwin':
            # The adoption record of Aikido is under /Library/Application
            # Support. On another platform fumitm cannot read it, thus each
            # run would adopt again.
            return ToolResult('aikido-adopt', 'skipped', 'Aikido adoption is macOS-only')
        # This runs as root. Do not use a PATH entry that the user can write.
        # --run-as-user adds the Homebrew and ~/.local/bin directories of the
        # target user to PATH.
        doctor = self._find_aikido_doctor()
        if not doctor:
            return ToolResult(
                'aikido-adopt', 'skipped',
                'aikido-doctor not found in trusted system PATH'
            )
        if not self._aikido_doctor_supports_adopt(doctor):
            return ToolResult(
                'aikido-adopt', 'skipped',
                'aikido-doctor predates certconfig adopt'
            )
        staged = self._stage_adoption_cert()
        if staged is None:
            return ToolResult('aikido-adopt', 'skipped', 'Provider root certificate not materialized')

        try:
            if self._aikido_built_bundles() is None:
                # Adoption with no read access to the bundles is a privileged
                # command with no way to confirm the result. Report the
                # directory. This is 'skipped' and not 'failed'. fumitm never
                # gets the privilege that makes the directory readable, thus a
                # failure would stay red at each scheduled run.
                run_dir = SUPPLEMENTAL_ROOTS['aikido']['run_dir']
                message = f"Could not read Aikido's bundle directory {run_dir}"
                self.print_warn(message)
                return ToolResult('aikido-adopt', 'skipped', message)

            short = self.provider['short_name']
            if self._aikido_trusts_root(staged):
                self.print_info(f"  ✓ {short} root already adopted by Aikido")
                return ToolResult('aikido-adopt', 'already_ok',
                                  'Provider root already adopted by Aikido')

            as_root = os.getuid() == 0
            prefix = [] if as_root else ['sudo']
            argv = prefix + [doctor, 'certconfig', 'adopt', staged]
            # Messages show the durable certificate path and not the staged
            # copy. The staged copy is gone when a user runs the command. The
            # parts are shell-quoted because the path of the doctor contains
            # spaces.
            command_str = shlex.join(argv[:-1] + [self.cert_path])

            if not self.is_install_mode():
                self.print_action(f"Would run: {command_str}")
                return ToolResult('aikido-adopt', 'skipped', 'Dry run')

            if not as_root:
                # sudo reads its password from the TTY. With no TTY it stops,
                # also with --yes. Give the command to the user, thus _prompt
                # does not raise NonInteractiveError and end the run.
                if self.headless or not sys.stdin.isatty():
                    self.print_warn(f"Adopting the {short} root into Aikido's bundles requires sudo")
                    self.print_action(f"Run manually: {command_str}")
                    return ToolResult('aikido-adopt', 'skipped', 'Requires sudo; run manually')
                response = self._prompt(
                    f"Run 'sudo aikido-doctor certconfig adopt' to add the {short} "
                    "root to Aikido's CA bundles? (Y/n) ")
                if response.lower() == 'n':
                    return ToolResult('aikido-adopt', 'skipped', 'Declined by user')

            self.print_status(f"Running: {command_str}")
            try:
                result = subprocess.run(argv, capture_output=True, text=True,
                                        check=False, timeout=300)
            except (subprocess.TimeoutExpired, OSError) as e:
                self.print_error(f"aikido-doctor failed to run: {e}")
                return ToolResult('aikido-adopt', 'failed', f'aikido-doctor failed to run: {e}')

            if result.returncode != 0:
                detail = (result.stderr or result.stdout or '').strip()
                message = f'aikido-doctor exited {result.returncode}: {detail[:200]}'
                self.print_error(message)
                return ToolResult('aikido-adopt', 'failed', message)

            if not self._aikido_trusts_root(staged):
                # A doctor that exits 0 and writes no record adopted nothing.
                # But the agent rebuilds the bundles, and the CLI does not. A
                # bundle that is behind after a recorded adoption is not in
                # our control. A failure would make each scheduled run red
                # until the next agent pass. Give the names of those bundles.
                if self._aikido_has_adopted(staged) is not True:
                    message = f'aikido-doctor exited 0 but did not adopt the {short} root'
                    self.print_error(message)
                    return ToolResult('aikido-adopt', 'failed', message)
                missing = self._aikido_bundles_missing(staged)
                if missing is None:
                    self.print_warn(
                        f"Aikido recorded the {short} root, but its bundle directory "
                        "became unreadable before the result could be confirmed")
                else:
                    lagging = ', '.join(os.path.basename(b) for b in missing)
                    self.print_warn(
                        f"Aikido recorded the {short} root but has not yet rebuilt: {lagging}")
            self.print_info(f"  ✓ Adopted {short} root into Aikido's CA bundles")
            return ToolResult('aikido-adopt', 'configured',
                              'Adopted provider root into Aikido CA bundles')
        finally:
            try:
                os.unlink(staged)
            except OSError:
                pass

    def setup_brew_cacerts(self):
        """Build the ca-certificates bundle of Homebrew again with the proxy CA.

        The ca-certificates formula builds its bundle from the macOS system
        keychain, which contains the MITM proxy CA. `brew postinstall
        ca-certificates` builds the bundle at
        $(brew --prefix)/etc/ca-certificates/cert.pem again. This corrects each
        Homebrew tool that links against Homebrew OpenSSL.
        """
        if not self.command_exists('brew'):
            return ToolResult('brew-cacerts', 'skipped', 'Homebrew not installed')

        try:
            result = subprocess.run(
                ['brew', 'list', 'ca-certificates'],
                capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                self.print_debug("Homebrew ca-certificates formula not installed")
                return ToolResult('brew-cacerts', 'skipped', 'ca-certificates formula not installed')
        except Exception:
            return ToolResult('brew-cacerts', 'skipped', 'Failed to check brew')

        brew_prefix = self._get_brew_prefix()
        bundle_path = os.path.join(
            brew_prefix, 'etc', 'ca-certificates', 'cert.pem'
        )

        if not os.path.exists(bundle_path):
            self.print_debug(f"Homebrew CA bundle not found at {bundle_path}")
            self.print_info("Configuring Homebrew CA certificates...")
            if not self.is_install_mode():
                self.print_action(
                    "Would run: brew postinstall ca-certificates"
                )
                return ToolResult('brew-cacerts', 'skipped', 'Dry run')
            return self._run_brew_postinstall(bundle_path)

        if self._all_roots_present_in_file(bundle_path):
            self.print_debug(
                "Proxy certificate already in Homebrew CA bundle"
            )
            return ToolResult('brew-cacerts', 'already_ok', 'Proxy certificate already in Homebrew CA bundle')

        self.print_info("Configuring Homebrew CA certificates...")
        if not self.is_install_mode():
            self.print_action(
                "Would run: brew postinstall ca-certificates"
            )
            return ToolResult('brew-cacerts', 'skipped', 'Dry run')
        self.print_info(
            "Regenerating Homebrew CA bundle to include proxy certificate..."
        )
        return self._run_brew_postinstall(bundle_path)

    def _run_brew_postinstall(self, bundle_path):
        """Build the Homebrew CA bundle again and confirm that each root is in it.

        brew builds the bundle from the macOS system keychain. Thus it removes a
        certificate that is only in the combined PEM. This includes a provider
        intermediate that the keychain does not have, for example the Netskope
        intermediate, and each supplemental root such as the Aikido root. fumitm
        appends what is absent to the new bundle.

        fumitm reports a failure only when brew took no part of the primary proxy
        CA. That shows that the keychain does not have it. An append of the primary
        root there would be removed at the next ca-certificates upgrade, thus fumitm
        reports the keychain problem.
        """
        result = subprocess.run(
            ['brew', 'postinstall', 'ca-certificates'],
            capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            self.print_error("brew postinstall ca-certificates failed")
            if result.stderr:
                self.print_debug(result.stderr.strip())
            return ToolResult('brew-cacerts', 'failed', 'brew postinstall ca-certificates failed')

        if not self._any_cert_present_in_file(self.cert_path, bundle_path):
            self.print_warn(
                "brew postinstall succeeded but proxy certificate "
                "not found in bundle"
            )
            self.print_warn(
                "The proxy CA may not be in the macOS system keychain"
            )
            return ToolResult('brew-cacerts', 'failed', 'Proxy certificate not found in bundle after postinstall')

        if not self._all_roots_present_in_file(bundle_path):
            # brew took the primary root from the keychain. It dropped the
            # certificates that are only in the combined PEM. Append them.
            self._append_all_proxy_roots(bundle_path)
            if not self._all_roots_present_in_file(bundle_path):
                self.print_warn(
                    "Proxy certificate could not be added to the "
                    "Homebrew CA bundle"
                )
                return ToolResult('brew-cacerts', 'failed', 'Proxy certificate not found in bundle after postinstall')

        self.print_info("Homebrew CA bundle now includes proxy certificate")
        return ToolResult('brew-cacerts', 'configured', 'Bundle regenerated with proxy certificate')

    def setup_node_cert(self):
        """Setup Node.js certificate."""
        if not self.command_exists('node'):
            return ToolResult('node', 'skipped', 'node not found in PATH')
        
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        needs_setup = False
        
        node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
        
        if node_extra_ca_certs:
            other_provider = self._path_belongs_to_other_provider(node_extra_ca_certs)
            if other_provider:
                # The path belongs to a different provider. Move to the bundle
                # of the current provider.
                needs_setup = True
                node_bundle = os.path.join(self.bundle_dir, "node/ca-bundle.pem")
                self.print_info("Configuring Node.js certificate...")
                self.print_info(f"NODE_EXTRA_CA_CERTS points to previous provider ({other_provider}): {node_extra_ca_certs}")

                if not self.is_install_mode():
                    self.print_action(f"Would create Node.js CA bundle at {node_bundle}")
                    self.print_action(f"Would set NODE_EXTRA_CA_CERTS={node_bundle}")
                else:
                    self._safe_makedirs(os.path.dirname(node_bundle))
                    shutil.copy(self.cert_path, node_bundle)
                    self._fix_ownership(node_bundle)
                    self._append_all_proxy_roots(node_bundle)
                    self.add_to_shell_config("NODE_EXTRA_CA_CERTS", node_bundle, shell_config)
                    self.print_info(f"Migrated Node.js CA bundle to {node_bundle}")
            elif os.path.exists(node_extra_ca_certs):
                if self._all_roots_present_in_file(node_extra_ca_certs):
                    pass
                else:
                    needs_setup = True
                    self.print_info("Configuring Node.js certificate...")
                    self.print_info(f"NODE_EXTRA_CA_CERTS is already set to: {node_extra_ca_certs}")

                    if not self.is_writable(node_extra_ca_certs):
                        self.print_error(f"Cannot write to {node_extra_ca_certs} (permission denied)")
                        new_path = self.suggest_user_path(node_extra_ca_certs, "node")
                        self.print_warn(f"Suggesting alternative path: {new_path}")

                        if not self.is_install_mode():
                            self.print_action(f"Would create directory: {os.path.dirname(new_path)}")
                            self.print_action(f"Would copy {node_extra_ca_certs} to {new_path}")
                            self.print_action(f"Would append proxy certificate to {new_path}")
                            self.print_action(f"Would update NODE_EXTRA_CA_CERTS to point to {new_path}")
                        else:
                            response = self._prompt("Do you want to use this alternative path? (Y/n) ")
                            if response.lower() != 'n':
                                self._safe_makedirs(os.path.dirname(new_path))
                                if os.path.exists(node_extra_ca_certs):
                                    try:
                                        shutil.copy(node_extra_ca_certs, new_path)
                                        self._fix_ownership(new_path)
                                    except Exception:
                                        Path(new_path).touch()
                                        self._fix_ownership(new_path)

                                self._append_all_proxy_roots(new_path)

                                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", new_path, shell_config)
                                self.print_info(f"Created new certificate bundle at {new_path}")
                            else:
                                return ToolResult('node', 'skipped', 'User declined alternative path')
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would append proxy certificate to {node_extra_ca_certs}")
                        else:
                            self.print_info(f"Appending proxy certificate to {node_extra_ca_certs}")
                            self._append_all_proxy_roots(node_extra_ca_certs)
            else:
                self.print_info("Configuring Node.js certificate...")
                self.print_warn(f"NODE_EXTRA_CA_CERTS points to a non-existent file: {node_extra_ca_certs}")
                self.print_warn("Please fix this manually")
                return ToolResult('node', 'failed', f'NODE_EXTRA_CA_CERTS points to non-existent file: {node_extra_ca_certs}')
        else:
            needs_setup = True
            self.print_info("Configuring Node.js certificate...")
            node_bundle = os.path.join(self.bundle_dir, "node/ca-bundle.pem")
            
            if not self.is_install_mode():
                self.print_action(f"Would create Node.js CA bundle at {node_bundle}")
                self.print_action("Would include proxy certificate in the bundle")
                self.print_action(f"Would set NODE_EXTRA_CA_CERTS={node_bundle}")
            else:
                self.print_info(f"Creating Node.js CA bundle at {node_bundle}")
                self._safe_makedirs(os.path.dirname(node_bundle))
                
                # Start with the proxy certificates. NODE_EXTRA_CA_CERTS adds
                # to the system certificates and does not replace them.
                shutil.copy(self.cert_path, node_bundle)
                self._fix_ownership(node_bundle)
                self._append_all_proxy_roots(node_bundle)

                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", node_bundle, shell_config)
                self.print_info("Created Node.js CA bundle with proxy certificate")
        
        if self.command_exists('npm'):
            self.setup_npm_cafile()

        # Cleanup stale yarn/pnpm configs that might override NODE_EXTRA_CA_CERTS
        self.cleanup_yarn_cafile()
        self.cleanup_pnpm_cafile()

        if not needs_setup:
            return ToolResult('node', 'already_ok', 'Node.js certificate already configured')
        if self.is_install_mode():
            return ToolResult('node', 'configured', 'Configured Node.js certificate')
        return ToolResult('node', 'skipped', 'Dry run')

    def setup_npm_cafile(self):
        """Setup npm cafile."""
        try:
            result = subprocess.run(
                ['npm', 'config', 'get', 'cafile'],
                capture_output=True, text=True, check=False
            )
            current_cafile = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_cafile = ""
        
        # npm needs a full CA bundle, not just a single certificate
        npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")

        if current_cafile and current_cafile not in ["null", "undefined"]:
            # If the cafile belongs to a different provider, migrate unconditionally
            other_provider = self._path_belongs_to_other_provider(current_cafile)
            if other_provider:
                self.print_info("Configuring npm certificate...")
                self.print_info(f"npm cafile points to previous provider ({other_provider}): {current_cafile}")
                if not self.is_install_mode():
                    self.print_action(f"Would create full CA bundle at {npm_bundle}")
                    self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                else:
                    self._safe_makedirs(os.path.dirname(npm_bundle))
                    self.create_bundle_with_system_certs(npm_bundle)
                    self._append_all_proxy_roots(npm_bundle)
                    subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle], check=False)
                    self.print_info(f"Migrated npm cafile to: {npm_bundle}")
                return

            if os.path.exists(current_cafile):
                suspicious, reason = self.is_suspicious_full_bundle(current_cafile, self.cert_path)
                if suspicious:
                    self.print_info("Configuring npm certificate...")
                    self.print_warn(f"Existing npm cafile looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would create full CA bundle at {npm_bundle}")
                        self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                    else:
                        self._safe_makedirs(os.path.dirname(npm_bundle))
                        self.create_bundle_with_system_certs(npm_bundle)
                        self._append_all_proxy_roots(npm_bundle)
                        subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle], check=False)
                        self.print_info(f"Repointed npm cafile to managed bundle: {npm_bundle}")
                    return

                if not self._all_roots_present_in_file(current_cafile):
                    self.print_info("Configuring npm certificate...")
                    self.print_warn("Current npm cafile doesn't contain proxy certificate")
                    
                    if not self.is_writable(current_cafile):
                        self.print_error(f"Cannot write to npm cafile: {current_cafile} (permission denied)")
                        self.print_warn(f"Will use alternative path: {npm_bundle}")
                        
                        if not self.is_install_mode():
                            self.print_action(f"Would create directory: {os.path.dirname(npm_bundle)}")
                            self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and proxy certificate")
                            self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                        else:
                            self._safe_makedirs(os.path.dirname(npm_bundle))
                            if (not self.create_bundle_with_system_certs(npm_bundle)
                                    and os.path.exists(current_cafile)):
                                shutil.copy(current_cafile, npm_bundle)
                                self._fix_ownership(npm_bundle)

                            self._append_all_proxy_roots(npm_bundle)

                            subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle], check=False)
                            self.print_info(f"Created new npm cafile at {npm_bundle}")
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would ask to append proxy certificate to {current_cafile}")
                        else:
                            response = self._prompt("Do you want to append it to the existing cafile? (y/N) ")
                            if response.lower() == 'y':
                                self.print_info(f"Appending proxy certificate to {current_cafile}")
                                self._append_all_proxy_roots(current_cafile)
            else:
                self.print_info("Configuring npm certificate...")
                self.print_warn(f"npm cafile points to non-existent file: {current_cafile}")
                
                if not self.is_install_mode():
                    self.print_action(f"Would create full CA bundle at {npm_bundle}")
                    self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                else:
                    response = self._prompt("Do you want to create a new CA bundle for npm? (Y/n) ")
                    if response.lower() != 'n':
                        self._safe_makedirs(os.path.dirname(npm_bundle))
                        self.create_bundle_with_system_certs(npm_bundle)
                        self._append_all_proxy_roots(npm_bundle)
                        subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle], check=False)
                        self.print_info(f"Created and configured npm cafile at {npm_bundle}")
        else:
            self.print_info("Configuring npm certificate...")
            self.print_info("npm cafile is not configured")
            
            if not self.is_install_mode():
                self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and proxy certificate")
                self.print_action(f"Would run: npm config set cafile {npm_bundle}")
            else:
                response = self._prompt("Do you want to configure npm with a CA bundle including proxy certificate? (Y/n) ")
                if response.lower() != 'n':
                    self._safe_makedirs(os.path.dirname(npm_bundle))
                    if not self.create_bundle_with_system_certs(npm_bundle):
                        self.print_warn("Could not find system CA bundle, creating new bundle with only proxy certificate")
                    self._append_all_proxy_roots(npm_bundle)
                    subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle], check=False)
                    self.print_info(f"Configured npm cafile to: {npm_bundle}")
                    
                    try:
                        result = subprocess.run(
                            ['npm', 'config', 'get', 'cafile'],
                            capture_output=True, text=True, check=False
                        )
                        verify_cafile = result.stdout.strip()
                        if verify_cafile == npm_bundle:
                            self.print_info("npm cafile configured successfully")
                        else:
                            self.print_error("Failed to configure npm cafile")
                    except Exception:
                        pass

    def cleanup_yarn_cafile(self):
        """Examine and remove the cafile configuration of yarn.

        yarn reads NODE_EXTRA_CA_CERTS, thus a cafile setting is usually
        unnecessary. Such a setting often points at an old path from a previous
        script such as warp.sh.
        """
        if not self.command_exists('yarn'):
            return

        try:
            # Detect yarn version (v1 vs Berry/v2+)
            result = subprocess.run(['yarn', '--version'], capture_output=True, text=True, check=False)
            yarn_version = result.stdout.strip()
            if not yarn_version:
                return
            is_berry = yarn_version[0] in ('2', '3', '4')

            if is_berry:
                config_key = 'httpsCaFilePath'
                delete_cmd = ['yarn', 'config', 'unset', 'httpsCaFilePath']
            else:
                config_key = 'cafile'
                delete_cmd = ['yarn', 'config', 'delete', 'cafile']

            result = subprocess.run(['yarn', 'config', 'get', config_key],
                                   capture_output=True, text=True, check=False)
            current_cafile = result.stdout.strip()

            if not current_cafile or current_cafile in ['undefined', '']:
                return  # Not set, nothing to do

            # Check if it points to our managed npm bundle (that's fine)
            npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
            if current_cafile == npm_bundle:
                return  # Points to fumitm-managed bundle, that's OK

            if os.path.exists(current_cafile) and self._all_roots_present_in_file(current_cafile):
                return  # Working config, leave it

            self.print_info("Configuring yarn...")
            if not os.path.exists(current_cafile):
                self.print_warn(f"yarn {config_key} points to non-existent file: {current_cafile}")
            else:
                self.print_warn(f"yarn {config_key} doesn't contain proxy certificate: {current_cafile}")

            if not self.is_install_mode():
                self.print_action(f"Would remove yarn {config_key} config")
                self.print_action("NODE_EXTRA_CA_CERTS will handle certificate trust for yarn")
            else:
                subprocess.run(delete_cmd, capture_output=True, check=False)
                self.print_info(f"Removed yarn {config_key} config")
                self.print_info("yarn will now use NODE_EXTRA_CA_CERTS for certificate trust")
        except Exception as e:
            self.print_debug(f"Error checking yarn cafile: {e}")

    def cleanup_pnpm_cafile(self):
        """Examine and remove the cafile configuration of pnpm.

        pnpm reads NODE_EXTRA_CA_CERTS, thus a cafile setting is usually
        unnecessary and often points at an old path.
        """
        if not self.command_exists('pnpm'):
            return

        try:
            result = subprocess.run(['pnpm', 'config', 'get', 'cafile'],
                                   capture_output=True, text=True, check=False)
            current_cafile = result.stdout.strip()

            if not current_cafile or current_cafile in ['undefined', '']:
                return  # Not set, nothing to do

            # Check if it points to our managed npm bundle (that's fine)
            npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
            if current_cafile == npm_bundle:
                return  # Points to fumitm-managed bundle, that's OK

            if os.path.exists(current_cafile) and self._all_roots_present_in_file(current_cafile):
                return  # Working config, leave it

            self.print_info("Configuring pnpm...")
            if not os.path.exists(current_cafile):
                self.print_warn(f"pnpm cafile points to non-existent file: {current_cafile}")
            else:
                self.print_warn(f"pnpm cafile doesn't contain proxy certificate: {current_cafile}")

            if not self.is_install_mode():
                self.print_action("Would remove pnpm cafile config")
                self.print_action("NODE_EXTRA_CA_CERTS will handle certificate trust for pnpm")
            else:
                subprocess.run(['pnpm', 'config', 'delete', 'cafile'], capture_output=True, check=False)
                self.print_info("Removed pnpm cafile config")
                self.print_info("pnpm will now use NODE_EXTRA_CA_CERTS for certificate trust")
        except Exception as e:
            self.print_debug(f"Error checking pnpm cafile: {e}")

    def _export_python_trust_vars(self, bundle, shell_config):
        """Point each Python TLS trust variable at the bundle with both roots.

        This includes the variables that a supplemental-root vendor sets at its own
        single-root bundle: PIP_CERT, POETRY_CERTIFICATES_PYPI_CERT, and
        BUNDLE_SSL_CA_CERT. Thus pip, poetry, and bundler trust both proxies.
        Returns True if an export changed the shell config.
        """
        trust_vars = (
            'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
            'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT',
        )
        changed = False
        for var in trust_vars:
            if self.add_to_shell_config(var, bundle, shell_config):
                changed = True
        return changed

    def setup_python_cert(self):
        """Setup Python certificate."""
        if not self.command_exists('python3') and not self.command_exists('python'):
            self.print_info("Python not found, skipping Python setup")
            return ToolResult('python', 'skipped', 'python not found in PATH')

        # Different Python installations can have different trust
        # configuration. Do not skip on a successful verify_connection(). The
        # environment variables make all Python environments work, not only
        # the one that runs this script. Virtual environments and child
        # processes inherit them.

        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)

        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        needs_setup = False

        requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')

        # A supplemental-root vendor can export REQUESTS_CA_BUNDLE at its own
        # root-owned bundle. Do not use or move that file. The vendor controls
        # it, and its next update reverts a change. Build the bundle of fumitm
        # at ~/.python-ca-bundle.pem with all roots. SSL_CERT_FILE then points
        # at that bundle.
        if requests_ca_bundle and self._is_vendor_injected_bundle(requests_ca_bundle):
            self.print_info(
                f"Ignoring vendor-injected REQUESTS_CA_BUNDLE ({requests_ca_bundle}); "
                f"using fumitm-managed bundle {python_bundle}"
            )
            requests_ca_bundle = ''

        if requests_ca_bundle:
            if os.path.exists(requests_ca_bundle):
                if not self.is_writable(requests_ca_bundle):
                    self.print_error(f"Cannot write to {requests_ca_bundle} (permission denied)")
                    new_path = self.suggest_user_path(requests_ca_bundle, "python")
                    self.print_warn(f"Suggesting alternative path: {new_path}")
                    needs_setup = True

                    if not self.is_install_mode():
                        self.print_action(f"Would create directory: {os.path.dirname(new_path)}")
                        self.print_action(f"Would copy {requests_ca_bundle} to {new_path}")
                        self.print_action(f"Would append proxy certificate to {new_path}")
                        self.print_action(f"Would update REQUESTS_CA_BUNDLE to point to {new_path}")
                    else:
                        response = self._prompt("Do you want to use this alternative path? (Y/n) ")
                        if response.lower() != 'n':
                            self._safe_makedirs(os.path.dirname(new_path))
                            if os.path.exists(requests_ca_bundle):
                                try:
                                    shutil.copy(requests_ca_bundle, new_path)
                                    self._fix_ownership(new_path)
                                except Exception:
                                    Path(new_path).touch()
                                    self._fix_ownership(new_path)

                            self._append_all_proxy_roots(new_path)

                            needs_setup = True
                            self.print_info("Configuring Python certificate...")
                            self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                            self.add_to_shell_config("REQUESTS_CA_BUNDLE", new_path, shell_config)
                            self.add_to_shell_config("SSL_CERT_FILE", new_path, shell_config)
                            self.add_to_shell_config("CURL_CA_BUNDLE", new_path, shell_config)
                            self.print_info(f"Created new certificate bundle at {new_path}")
                        else:
                            return ToolResult('python', 'skipped', 'User declined alternative path')
                else:
                    suspicious, reason = self.is_suspicious_full_bundle(requests_ca_bundle, self.cert_path)
                    if suspicious:
                        # Point at the managed bundle of fumitm. Continue to
                        # the trust-variable pass below. A return here leaves
                        # the vendor variables at the old bundle.
                        needs_setup = True
                        self.print_info("Configuring Python certificate...")
                        self.print_warn(f"REQUESTS_CA_BUNDLE looks suspiciously small ({reason})")
                        if not self.is_install_mode():
                            self.print_action(f"Would create full CA bundle at {python_bundle}")
                            self.print_action(f"Would repoint REQUESTS_CA_BUNDLE to {python_bundle}")
                        else:
                            self.create_bundle_with_system_certs(python_bundle)
                            self._append_all_proxy_roots(python_bundle)
                            self.add_to_shell_config("REQUESTS_CA_BUNDLE", python_bundle, shell_config)
                            self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                            self.add_to_shell_config("CURL_CA_BUNDLE", python_bundle, shell_config)
                            self.print_info(f"Repointed REQUESTS_CA_BUNDLE to managed bundle: {python_bundle}")

                    # Look for the certificate in the file. Do this only when
                    # the bundle is not suspicious. The suspicious branch
                    # already uses python_bundle.
                    elif not self._all_roots_present_in_file(requests_ca_bundle):
                        needs_setup = True
                        self.print_info("Configuring Python certificate...")
                        self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")

                        if not self.is_install_mode():
                            self.print_action(f"Would append proxy certificate to {requests_ca_bundle}")
                        else:
                            self.print_info(f"Appending proxy certificate to {requests_ca_bundle}")
                            self._append_all_proxy_roots(requests_ca_bundle)
                    else:
                        # REQUESTS_CA_BUNDLE is correct. Set SSL_CERT_FILE
                        # also, because httpx and the ssl module read it.
                        shell_config = self.get_shell_config(shell_type)
                        ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                        if not ssl_cert_file:
                            needs_setup = True
                            if not self.is_install_mode():
                                self.print_action(f"Would set SSL_CERT_FILE to {requests_ca_bundle}")
                            else:
                                self.add_to_shell_config("SSL_CERT_FILE", requests_ca_bundle, shell_config)
                                self.print_info(f"Set SSL_CERT_FILE to {requests_ca_bundle}")
            else:
                self.print_info("Configuring Python certificate...")
                self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                self.print_warn(f"REQUESTS_CA_BUNDLE points to a non-existent file: {requests_ca_bundle}")
                return ToolResult('python', 'failed', f'REQUESTS_CA_BUNDLE points to non-existent file: {requests_ca_bundle}')
        else:
            needs_setup = True
            self.print_info("Configuring Python certificate...")
            
            if not self.is_install_mode():
                self.print_action(f"Would create Python CA bundle at {python_bundle}")
                self.print_action("Would copy system certificates and append proxy certificate")
            else:
                self.print_info(f"Creating Python CA bundle at {python_bundle}")
                if not self.create_bundle_with_system_certs(python_bundle):
                    self.print_warn("Could not find system CA bundle, creating new bundle")
                self._append_all_proxy_roots(python_bundle)

            self.add_to_shell_config("REQUESTS_CA_BUNDLE", python_bundle, shell_config)
            self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
            self.add_to_shell_config("CURL_CA_BUNDLE", python_bundle, shell_config)

        # Examine SSL_CERT_FILE for a suspicious bundle. REQUESTS_CA_BUNDLE
        # can be correct while SSL_CERT_FILE is broken.
        ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
        if ssl_cert_file and ssl_cert_file != python_bundle:
            if os.path.exists(ssl_cert_file):
                suspicious, reason = self.is_suspicious_full_bundle(ssl_cert_file, self.cert_path)
                if suspicious:
                    needs_setup = True
                    self.print_info("Configuring SSL_CERT_FILE...")
                    self.print_warn(f"SSL_CERT_FILE looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                    else:
                        if not os.path.exists(python_bundle):
                            self.create_bundle_with_system_certs(python_bundle)
                            self._append_all_proxy_roots(python_bundle)
                        self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                        self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")
                elif not self._all_roots_present_in_file(ssl_cert_file):
                    needs_setup = True
                    self.print_info("Configuring SSL_CERT_FILE...")
                    self.print_warn("SSL_CERT_FILE doesn't contain proxy certificate")
                    if not self.is_install_mode():
                        self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                    else:
                        if not os.path.exists(python_bundle):
                            self.create_bundle_with_system_certs(python_bundle)
                            self._append_all_proxy_roots(python_bundle)
                        self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                        self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")
            else:
                needs_setup = True
                self.print_info("Configuring SSL_CERT_FILE...")
                self.print_warn(f"SSL_CERT_FILE points to non-existent file: {ssl_cert_file}")
                if not self.is_install_mode():
                    self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                else:
                    if not os.path.exists(python_bundle):
                        self.create_bundle_with_system_certs(python_bundle)
                        self._append_all_proxy_roots(python_bundle)
                    self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                    self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")

        # Take back the Python trust variables that a supplemental-root
        # vendor sets at its own single-root bundle. A branch above can exit
        # while PIP_CERT, POETRY, and BUNDLE_SSL_CA_CERT still point at that
        # bundle. Set all of them at the Python bundle with both roots.
        vendor_trust_vars = (
            'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'
        )
        aikido_active = any(e['key'] == 'aikido' for e in self.extra_roots)
        if aikido_active or any(os.environ.get(v) for v in vendor_trust_vars):
            bundle_repaired = False
            if self.is_install_mode():
                # A bundle built before Aikido was active has no Aikido root.
                # Repair it before the variables point at it.
                if not os.path.exists(python_bundle):
                    self.create_bundle_with_system_certs(python_bundle)
                    self._append_all_proxy_roots(python_bundle)
                    bundle_repaired = True
                elif not self._all_roots_present_in_file(python_bundle):
                    self._append_all_proxy_roots(python_bundle)
                    bundle_repaired = True
            else:
                bundle_repaired = (not os.path.exists(python_bundle)) or \
                    (not self._all_roots_present_in_file(python_bundle))
            exported = self._export_python_trust_vars(python_bundle, shell_config)
            if bundle_repaired or exported:
                needs_setup = True

        if not needs_setup:
            return ToolResult('python', 'already_ok', 'Python certificate already configured')
        if self.is_install_mode():
            return ToolResult('python', 'configured', 'Configured Python certificate')
        return ToolResult('python', 'skipped', 'Dry run')

    def _ensure_gcloud_properties(self, ca_bundle):
        """Make ~/.config/gcloud/properties with custom_ca_certs_file.

        The gcloud SDK reads this file during its bootstrap, before a config command
        is available. This is the only reliable way to give a custom CA bundle to
        `brew install --cask gcloud-cli`. Homebrew removes
        CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE from the environment, and the requests
        library in gcloud ignores REQUESTS_CA_BUNDLE.
        """
        properties_dir = os.path.expanduser("~/.config/gcloud")
        properties_file = os.path.join(properties_dir, "properties")
        target_line = f"custom_ca_certs_file = {ca_bundle}"

        if os.path.exists(properties_file):
            with open(properties_file, 'r') as f:
                content = f.read()
            if "custom_ca_certs_file" in content:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("custom_ca_certs_file"):
                        current_value = stripped.split("=", 1)[-1].strip()
                        if current_value == ca_bundle:
                            return False
                        if os.path.exists(current_value) and \
                                self._all_roots_present_in_file(current_value):
                            return False
                # The value is old or incorrect. Replace it.
                lines = content.splitlines()
                new_lines = []
                for line in lines:
                    if line.strip().startswith("custom_ca_certs_file"):
                        new_lines.append(target_line)
                    else:
                        new_lines.append(line)
                if not self.is_install_mode():
                    self.print_action(f"Would update custom_ca_certs_file in {properties_file}")
                else:
                    with open(properties_file, 'w') as f:
                        f.write('\n'.join(new_lines) + '\n')
                    self._fix_ownership(properties_file)
                    self.print_info(f"Updated custom_ca_certs_file in {properties_file}")
                return True

            # The file has no custom_ca_certs_file. Append it under [core].
            if "[core]" in content:
                if not self.is_install_mode():
                    self.print_action(f"Would add custom_ca_certs_file to {properties_file}")
                else:
                    content = content.replace(
                        "[core]",
                        f"[core]\n{target_line}",
                        1,
                    )
                    with open(properties_file, 'w') as f:
                        f.write(content)
                    self._fix_ownership(properties_file)
                    self.print_info(f"Added custom_ca_certs_file to {properties_file}")
            else:
                if not self.is_install_mode():
                    self.print_action(f"Would add [core] section with custom_ca_certs_file to {properties_file}")
                else:
                    with open(properties_file, 'a') as f:
                        f.write(f"\n[core]\n{target_line}\n")
                    self._fix_ownership(properties_file)
                    self.print_info(f"Added [core] section with custom_ca_certs_file to {properties_file}")
        else:
            if not self.is_install_mode():
                self.print_action(f"Would create {properties_file} with custom_ca_certs_file")
            else:
                self._safe_makedirs(properties_dir)
                with open(properties_file, 'w') as f:
                    f.write(f"[core]\n{target_line}\n")
                self._fix_ownership(properties_file)
                self.print_info(f"Created {properties_file} with custom_ca_certs_file")
        return True

    def _ensure_gcloud_reauth_trust(self, complete_bundle, shell_config):
        """Make the reauth handshake of gcloud trust the full proxy bundle.

        The IAP tunnel and the usual API calls read core/custom_ca_certs_file. But
        the reauth flow does not. gcloud runs that flow against
        reauth.googleapis.com when it must refresh the credentials. It goes through
        the requests library in gcloud, which reads REQUESTS_CA_BUNDLE and then
        CURL_CA_BUNDLE. A supplemental-root vendor such as Aikido sets both at its
        own combined bundle. That bundle has the public roots and the vendor root
        but not the primary proxy root, for example the Netskope root, which
        intercepts the Google traffic. The reauth handshake then fails with
        "self-signed certificate in certificate chain", although the property is
        correct and ``gcloud projects list`` operates.

        fumitm sets both variables at the complete bundle, with the public roots and
        each proxy root. The managed block is always last, thus it replaces the
        earlier export of the vendor. This operates only when a supplemental root is
        active, thus a host with one provider keeps its environment.

        Returns:
            bool: True when an export changed, or would change in dry-run mode.
        """
        if not self.extra_roots:
            return False
        changed = False
        for var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            if self.add_to_shell_config(var, complete_bundle, shell_config):
                changed = True
        return changed

    def setup_gcloud_cert(self):
        """Setup gcloud certificate."""
        # Make the gcloud properties file now, thus a later gcloud install
        # can start behind a MITM proxy. Set the environment variable also.
        pre_bootstrap = False
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        if os.path.exists(python_bundle):
            props_changed = self._ensure_gcloud_properties(python_bundle)
            shell_type = self.detect_shell()
            shell_config = self.get_shell_config(shell_type)
            shell_changed = self.add_to_shell_config(
                "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
                python_bundle,
                shell_config,
            )
            reauth_changed = self._ensure_gcloud_reauth_trust(
                python_bundle, shell_config
            )
            pre_bootstrap = props_changed or shell_changed or reauth_changed

        if not self.command_exists('gcloud'):
            self.print_info("gcloud not found, skipping gcloud setup")
            if pre_bootstrap:
                if self.is_install_mode():
                    return ToolResult('gcloud', 'configured', 'Pre-created gcloud properties for future install')
                return ToolResult('gcloud', 'skipped', 'Dry run')
            return ToolResult('gcloud', 'skipped', 'gcloud not found in PATH')

        # Do not stop on a successful HTTPS check. The IAP tunnel WebSocket
        # path makes its own SSL context with the ca_certs path from
        # core/custom_ca_certs_file. It ignores the system trust store and
        # SSL_CERT_FILE. Thus always set the property to a bundle that
        # contains the proxy CA.

        gcloud_cert_dir = os.path.expanduser("~/.config/gcloud/certs")
        gcloud_bundle = os.path.join(gcloud_cert_dir, "combined-ca-bundle.pem")
        needs_setup = False

        try:
            result = subprocess.run(
                ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                capture_output=True, text=True, check=False
            )
            current_ca_file = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca_file = ""
        
        if not current_ca_file:
            needs_setup = True
        elif os.path.exists(current_ca_file):
            suspicious, reason = self.is_suspicious_full_bundle(current_ca_file, self.cert_path)
            if suspicious:
                self.print_info("Configuring gcloud certificate...")
                self.print_warn(f"Existing gcloud CA file looks suspiciously small ({reason})")
                if not self.is_install_mode():
                    self.print_action(f"Would create gcloud CA bundle at {gcloud_bundle}")
                    self.print_action(f"Would run: gcloud config set core/custom_ca_certs_file {gcloud_bundle}")
                else:
                    self._safe_makedirs(gcloud_cert_dir)
                    self.create_bundle_with_system_certs(gcloud_bundle)
                    self._append_all_proxy_roots(gcloud_bundle)
                    subprocess.run(['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_bundle], capture_output=True, timeout=30, check=False)
                    self.print_info(f"Repointed gcloud custom CA file to managed bundle: {gcloud_bundle}")
                    return ToolResult('gcloud', 'configured', 'Repointed suspicious gcloud CA file')
                return ToolResult('gcloud', 'skipped', 'Dry run')

            if not self._all_roots_present_in_file(current_ca_file):
                needs_setup = True
        else:
            needs_setup = True

        if not needs_setup:
            if pre_bootstrap and self.is_install_mode():
                return ToolResult('gcloud', 'configured', 'Configured gcloud trust environment')
            return ToolResult('gcloud', 'already_ok', 'gcloud certificate already configured')

        self.print_info("Configuring gcloud certificate...")
        
        if self.is_install_mode():
            self._safe_makedirs(gcloud_cert_dir)
        
        if current_ca_file and current_ca_file != gcloud_bundle:
            self.print_warn(f"gcloud is already configured with custom CA: {current_ca_file}")
            
            if os.path.exists(current_ca_file) and not self.is_writable(current_ca_file):
                self.print_error(f"Cannot write to current gcloud CA file: {current_ca_file} (permission denied)")
                self.print_warn(f"Will use alternative path: {gcloud_bundle}")
                if not self.is_install_mode():
                    self.print_action(f"Would create new gcloud CA bundle at {gcloud_bundle}")
            else:
                if not self.is_install_mode():
                    self.print_action("Would ask to update gcloud CA configuration")
                    return ToolResult('gcloud', 'skipped', 'Dry run')
                else:
                    response = self._prompt("Do you want to update it? (y/N) ")
                    if response.lower() != 'y':
                        return ToolResult('gcloud', 'skipped', 'User declined')
        
        if not self.is_install_mode():
            self.print_action(f"Would create directory: {gcloud_cert_dir}")
            self.print_action(f"Would create gcloud CA bundle at {gcloud_bundle}")
            self.print_action("Would copy system certificates and append proxy certificate")
            self.print_action(f"Would run: gcloud config set core/custom_ca_certs_file {gcloud_bundle}")
            return ToolResult('gcloud', 'skipped', 'Dry run')
        else:
            self.print_info(f"Creating gcloud CA bundle at {gcloud_bundle}")
            self.create_bundle_with_system_certs(gcloud_bundle)
            self._append_all_proxy_roots(gcloud_bundle)

            result = subprocess.run(
                ['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_bundle],
                capture_output=True,
                timeout=30,  # Add timeout to prevent hanging
                check=False
            )
            if result.returncode == 0:
                self.print_info("gcloud configured successfully")
                # Skip diagnostics in devcontainers as they can hang
                if needs_setup and not self.is_devcontainer():
                    self.print_info("Running gcloud diagnostics...")
                    try:
                        subprocess.run(['gcloud', 'info', '--run-diagnostics'], timeout=10, check=False)
                    except subprocess.TimeoutExpired:
                        self.print_warn("gcloud diagnostics timed out, skipping")
                return ToolResult('gcloud', 'configured', 'Configured gcloud certificate')
            else:
                self.print_error("Failed to configure gcloud")
                return ToolResult('gcloud', 'failed', 'Failed to configure gcloud')

    def setup_git_cert(self):
        """Setup Git sslCAInfo to a managed full bundle."""
        if not self.command_exists('git'):
            return ToolResult('git', 'skipped', 'git not found in PATH')
        git_bundle = os.path.join(self.bundle_dir, "git/ca-bundle.pem")
        try:
            result = subprocess.run(['git', 'config', '--global', 'http.sslCAInfo'], capture_output=True, text=True, check=False)
            current_ca = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca = ""
        repoint = False
        if current_ca:
            other_provider = self._path_belongs_to_other_provider(current_ca)
            if other_provider:
                repoint = True
                self.print_info("Configuring Git certificate...")
                self.print_info(f"http.sslCAInfo points to previous provider ({other_provider}): {current_ca}")
            elif os.path.exists(current_ca):
                suspicious, reason = self.is_suspicious_full_bundle(current_ca, self.cert_path)
                if suspicious:
                    repoint = True
                    self.print_info("Configuring Git certificate...")
                    self.print_warn(f"Existing git http.sslCAInfo looks suspiciously small ({reason})")
            else:
                if self._is_apple_git():
                    return ToolResult(
                        'git', 'already_ok',
                        'sslCAInfo path missing; Apple Git uses system trust',
                    )
                repoint = True
                self.print_info("Configuring Git certificate...")
                self.print_info(
                    f"http.sslCAInfo points to non-existent file: {current_ca}"
                )
        else:
            if self._is_apple_git():
                return ToolResult(
                    'git', 'already_ok',
                    'Uses system trust store (Apple Git)',
                )
            repoint = True
            self.print_info("Configuring Git certificate...")
            self.print_info(
                "http.sslCAInfo not set and git is OpenSSL-linked"
                " (needs explicit CA bundle)"
            )
        if not repoint:
            return ToolResult('git', 'already_ok', 'sslCAInfo already correct')
        if not self.is_install_mode():
            self.print_action(f"Would create Git CA bundle at {git_bundle}")
            self.print_action(f"Would run: git config --global http.sslCAInfo {git_bundle}")
            return ToolResult('git', 'skipped', 'Dry run')
        self._safe_makedirs(os.path.dirname(git_bundle))
        self.create_bundle_with_system_certs(git_bundle)
        self._append_all_proxy_roots(git_bundle)
        subprocess.run(['git', 'config', '--global', 'http.sslCAInfo', git_bundle], capture_output=True, text=True, check=False)
        self.print_info(f"Configured git http.sslCAInfo to: {git_bundle}")
        return ToolResult('git', 'configured', f'Set http.sslCAInfo to {git_bundle}')

    def _find_effective_curlrc(self):
        """Return the config file that curl reads, or None.

        curl uses only the first file that it finds. It examines $CURL_HOME/.curlrc,
        then $XDG_CONFIG_HOME/curlrc, then ~/.curlrc.
        """
        candidates = []
        if os.environ.get('CURL_HOME'):
            candidates.append(os.path.join(os.environ['CURL_HOME'], '.curlrc'))
        if os.environ.get('XDG_CONFIG_HOME'):
            candidates.append(os.path.join(os.environ['XDG_CONFIG_HOME'], 'curlrc'))
        candidates.append(os.path.join(os.path.expanduser('~'), '.curlrc'))
        for path in candidates:
            if os.path.isfile(path):
                return path
        return None

    def _parse_curlrc_cacert(self, content):
        """Return (path, in_fumitm_block) for the effective cacert directive.

        A curlrc entry operates as a command-line option, which has more authority
        than the CURL_CA_BUNDLE variable. For an option with one value, the last
        entry wins. This function accepts the separators that curl permits
        (whitespace, '=', or ':'), an optional '--' at the start, and optional
        quotes around the value. Returns (None, False) when no directive is present.
        """
        result = (None, False)
        in_block = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == self._FUMITM_BLOCK_BEGIN:
                in_block = True
                continue
            if stripped == self._FUMITM_BLOCK_END:
                in_block = False
                continue
            match = re.match(r'(?:--)?cacert(?:\s*[=:]\s*|\s+)(.+)$', stripped)
            if not match:
                continue
            value = match.group(1).strip()
            if len(value) > 1 and value[0] in '"\'' and value.endswith(value[0]):
                value = value[1:-1]
            if value:
                result = (value, in_block)
        return result

    def _effective_curlrc_cacert(self):
        """Return (curlrc_path, cacert_path, in_fumitm_block) for the curl config.

        Returns (None, None, False) when no curlrc is present, when it is
        unreadable, or when it has no cacert directive.
        """
        curlrc = self._find_effective_curlrc()
        if not curlrc:
            return None, None, False
        try:
            with open(curlrc, 'r') as f:
                content = f.read()
        except OSError:
            return None, None, False
        cacert, in_block = self._parse_curlrc_cacert(content)
        if cacert is None:
            return None, None, False
        return curlrc, cacert, in_block

    def _set_curlrc_cacert(self, curlrc, bundle_path):
        """Write a managed cacert block at the end of curlrc.

        This is the same operation as add_to_shell_config. fumitm writes the block
        last at each write, thus its cacert replaces the cacert of an earlier vendor
        block. fumitm does not change that block.

        Returns:
            bool: True when the file changed, or would change in dry-run mode.
        """
        original = None
        if os.path.exists(curlrc):
            with open(curlrc, 'r') as f:
                original = f.read()

        other_lines, _ = self._parse_fumitm_block(original or "")
        while other_lines and other_lines[-1].strip() == '':
            other_lines.pop()
        prefix = ('\n'.join(other_lines) + '\n\n') if other_lines else ''
        block = '\n'.join([
            self._FUMITM_BLOCK_BEGIN,
            f'cacert "{bundle_path}"',
            self._FUMITM_BLOCK_END,
        ])
        new = prefix + block + '\n'

        changed = original is None or new != original
        if not self.is_install_mode():
            if changed:
                self.print_action(f'Would set cacert "{bundle_path}" in {curlrc} (fumitm block, kept last)')
            return changed
        if not changed:
            return False

        if curlrc not in self._backed_up_shell_configs and original is not None:
            with open(curlrc + '.bak', 'w') as f:
                f.write(original)
            self._fix_ownership(curlrc + '.bak')
            self._backed_up_shell_configs.add(curlrc)

        with open(curlrc, 'w') as f:
            f.write(new)
        self._fix_ownership(curlrc)
        self.print_info(f"Set cacert in {curlrc} to: {bundle_path}")
        return True

    def _fix_curlrc_override(self, target_bundle):
        """Correct a curlrc cacert directive that replaces CURL_CA_BUNDLE.

        A vendor agent can write a cacert directive into curlrc that points at a
        bundle without the primary proxy CA. That directive has more authority than
        the variable, thus curl continues to fail after --fix. fumitm appends a
        managed block with a cacert at target_bundle and keeps it last. If curlrc is
        not writable, fumitm appends the proxy roots to the bundle that the
        directive names, if that bundle is writable.

        Returns:
            ToolResult when fumitm found and corrected a directive, or None when
            there is no override. The caller then continues.
        """
        curlrc, rc_cacert, in_block = self._effective_curlrc_cacert()
        if rc_cacert is None:
            return None
        if in_block and rc_cacert == target_bundle:
            return None
        self.print_info(f"cacert directive in {curlrc} overrides CURL_CA_BUNDLE")
        self.print_info(f"  curl's effective trust store: {rc_cacert}")
        if not self.is_install_mode():
            self._set_curlrc_cacert(curlrc, target_bundle)
            return ToolResult('curl', 'skipped', 'Dry run')
        try:
            changed = self._set_curlrc_cacert(curlrc, target_bundle)
        except OSError as e:
            self.print_warn(f"Cannot write {curlrc}: {e}")
            if (os.path.isfile(rc_cacert) and os.access(rc_cacert, os.W_OK)
                    and self._append_all_proxy_roots(rc_cacert)):
                self.print_info(f"Appended proxy roots to {rc_cacert} instead")
                return ToolResult('curl', 'configured', f'Appended proxy roots to {rc_cacert}')
            self.print_info(f'Fix manually: point the cacert line in {curlrc} at {target_bundle}')
            return ToolResult('curl', 'failed', f'Could not update {curlrc}')
        if changed:
            self.print_info("Vendor cacert block left untouched; the file's manager may rewrite it, "
                            "in which case re-run fumitm")
            return ToolResult('curl', 'configured', f'Set cacert in {curlrc} to {target_bundle}')
        return ToolResult('curl', 'already_ok', f'cacert in {curlrc} already points at {target_bundle}')

    def setup_curl_cert(self):
        """Configure the certificate for curl.

        This method operates on five conditions:
        1. curl operates through the system trust, such as SecureTransport on macOS.
           fumitm makes no change.
        2. CURL_CA_BUNDLE points at a suspicious or broken bundle.
        3. CURL_CA_BUNDLE points at a file that is not present.
        4. curl fails and CURL_CA_BUNDLE is not set.
        5. A curlrc cacert directive replaces CURL_CA_BUNDLE.
        """
        if not self.command_exists('curl'):
            return ToolResult('curl', 'skipped', 'curl not found in PATH')

        # If curl already works, add no configuration.
        verify_result = self.verify_connection("curl")
        if verify_result == "WORKING":
            self.print_debug("curl already works via system trust, skipping configuration")
            return ToolResult('curl', 'already_ok', 'Works via system trust store')

        curl_bundle = os.path.join(self.bundle_dir, "curl/ca-bundle.pem")
        curl_env = os.environ.get('CURL_CA_BUNDLE', '')

        # Case 1: CURL_CA_BUNDLE is set. Look for a different provider first.
        if curl_env:
            other_provider = self._path_belongs_to_other_provider(curl_env)
            if other_provider:
                self.print_info("Configuring curl certificate bundle...")
                self.print_info(f"CURL_CA_BUNDLE points to previous provider ({other_provider}): {curl_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                    self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                    return ToolResult('curl', 'skipped', 'Dry run')
            elif not os.path.exists(curl_env):
                self.print_info("Configuring curl certificate bundle...")
                self.print_warn(f"CURL_CA_BUNDLE points to non-existent file: {curl_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                    self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                    return ToolResult('curl', 'skipped', 'Dry run')
            else:
                suspicious, reason = self.is_suspicious_full_bundle(curl_env, self.cert_path)
                if suspicious:
                    self.print_info("Configuring curl certificate bundle...")
                    self.print_warn(f"Existing CURL_CA_BUNDLE looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                        self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                        return ToolResult('curl', 'skipped', 'Dry run')
                else:
                    # The bundle is correct but curl fails. A cacert
                    # directive in curlrc has more authority than
                    # CURL_CA_BUNDLE.
                    rc_result = self._fix_curlrc_override(curl_env)
                    if rc_result is not None:
                        return rc_result
                    self.print_warn("curl connection failed but CURL_CA_BUNDLE looks valid")
                    self.print_info("This may require manual investigation")
                    return ToolResult('curl', 'already_ok', 'CURL_CA_BUNDLE looks valid; may need manual investigation')
        else:
            # Case 2: CURL_CA_BUNDLE is not set and curl does not operate.
            self.print_info("Configuring curl certificate bundle...")
            if not self.is_install_mode():
                self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                self.print_action(f"Would set CURL_CA_BUNDLE={curl_bundle}")
                return ToolResult('curl', 'skipped', 'Dry run')

        self._safe_makedirs(os.path.dirname(curl_bundle))
        self.create_bundle_with_system_certs(curl_bundle)
        self._append_all_proxy_roots(curl_bundle)
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        self.add_to_shell_config("CURL_CA_BUNDLE", curl_bundle, shell_config)
        rc_result = self._fix_curlrc_override(curl_bundle)
        if rc_result is not None and rc_result.status == 'failed':
            return rc_result
        self.print_info(f"Configured CURL_CA_BUNDLE to: {curl_bundle}")
        return ToolResult('curl', 'configured', f'Set CURL_CA_BUNDLE to {curl_bundle}')

    def setup_aws_cert(self):
        """Configure the certificate for the AWS CLI.

        Sets AWS_CA_BUNDLE at a CA bundle that contains the proxy certificate. This
        corrects the SSL errors of a command such as `aws configure sso` or
        `aws s3 ls`.
        """
        if not self.command_exists('aws'):
            return ToolResult('aws', 'skipped', 'aws not found in PATH')

        aws_bundle = os.path.join(self.bundle_dir, "aws/ca-bundle.pem")
        aws_env = os.environ.get('AWS_CA_BUNDLE', '')
        verify_result = self.verify_connection("aws")

        # Case 1: AWS_CA_BUNDLE is set. Look for a different provider first.
        if aws_env:
            other_provider = self._path_belongs_to_other_provider(aws_env)
            if other_provider:
                self.print_info("Configuring AWS CLI certificate bundle...")
                self.print_info(f"AWS_CA_BUNDLE points to previous provider ({other_provider}): {aws_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create AWS CA bundle at {aws_bundle}")
                    self.print_action(f"Would repoint AWS_CA_BUNDLE to {aws_bundle}")
                    return ToolResult('aws', 'skipped', 'Dry run')
            elif not os.path.exists(aws_env):
                self.print_info("Configuring AWS CLI certificate bundle...")
                self.print_warn(f"AWS_CA_BUNDLE points to non-existent file: {aws_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create AWS CA bundle at {aws_bundle}")
                    self.print_action(f"Would repoint AWS_CA_BUNDLE to {aws_bundle}")
                    return ToolResult('aws', 'skipped', 'Dry run')
            else:
                suspicious, reason = self.is_suspicious_full_bundle(aws_env, self.cert_path)
                if suspicious:
                    self.print_info("Configuring AWS CLI certificate bundle...")
                    self.print_warn(f"Existing AWS_CA_BUNDLE looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would create AWS CA bundle at {aws_bundle}")
                        self.print_action(f"Would repoint AWS_CA_BUNDLE to {aws_bundle}")
                        return ToolResult('aws', 'skipped', 'Dry run')
                elif not self._all_roots_present_in_file(aws_env, likely=True):
                    # The bundle is correct but has no proxy certificate.
                    self.print_info("Configuring AWS CLI certificate bundle...")
                    self.print_info(f"AWS_CA_BUNDLE bundle is missing the {self.provider['name']} proxy certificate")
                    if not self.is_install_mode():
                        self.print_action(f"Would create AWS CA bundle at {aws_bundle}")
                        self.print_action(f"Would repoint AWS_CA_BUNDLE to {aws_bundle}")
                        return ToolResult('aws', 'skipped', 'Dry run')
                else:
                    if verify_result == "WORKING":
                        self.print_debug("AWS CLI already works with configured bundle, skipping configuration")
                    else:
                        # The bundle is correct and has the certificate. The
                        # cause of the failure is unknown.
                        self.print_warn("AWS CLI connection failed but AWS_CA_BUNDLE looks valid")
                        self.print_info("This may require manual investigation")
                    return ToolResult('aws', 'already_ok', 'AWS_CA_BUNDLE looks valid')
        else:
            if verify_result == "WORKING":
                self.print_debug("AWS CLI already works via system trust, skipping configuration")
                return ToolResult('aws', 'already_ok', 'Works via system trust store')
            # Case 2: AWS_CA_BUNDLE is not set and aws does not operate.
            self.print_info("Configuring AWS CLI certificate bundle...")
            if not self.is_install_mode():
                self.print_action(f"Would create AWS CA bundle at {aws_bundle}")
                self.print_action(f"Would set AWS_CA_BUNDLE={aws_bundle}")
                return ToolResult('aws', 'skipped', 'Dry run')

        self._safe_makedirs(os.path.dirname(aws_bundle))
        self.create_bundle_with_system_certs(aws_bundle)
        self._append_all_proxy_roots(aws_bundle)
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        self.add_to_shell_config("AWS_CA_BUNDLE", aws_bundle, shell_config)
        self.print_info(f"Configured AWS_CA_BUNDLE to: {aws_bundle}")
        return ToolResult('aws', 'configured', f'Set AWS_CA_BUNDLE to {aws_bundle}')

    def check_git_status(self, temp_warp_cert):
        """Check Git configuration status for http.sslCAInfo."""
        has_issues = False
        if self.command_exists('git'):
            try:
                result = subprocess.run(['git', 'config', '--global', 'http.sslCAInfo'], capture_output=True, text=True, check=False)
                git_ca = result.stdout.strip() if result.returncode == 0 else ""
                if git_ca:
                    self.print_info(f"  http.sslCAInfo is set to: {git_ca}")
                    other_provider = self._path_belongs_to_other_provider(git_ca)
                    if other_provider:
                        self.print_warn(f"  ⚠ http.sslCAInfo points to a previous provider's path ({other_provider})")
                        self.print_action("    Run with --fix to migrate to the current provider's bundle")
                        has_issues = True
                    elif os.path.exists(git_ca):
                        suspicious, reason = self.is_suspicious_full_bundle(git_ca, None)
                        if suspicious:
                            self.print_warn(f"  ⚠ http.sslCAInfo looks suspiciously small ({reason})")
                            git_bundle_path = os.path.join(self.bundle_dir, "git/ca-bundle.pem")
                            self.print_action(f"    Run with --fix or use: git config --global http.sslCAInfo {git_bundle_path}")
                            has_issues = True
                    else:
                        self.print_warn(f"  ✗ http.sslCAInfo points to non-existent file: {git_ca}")
                        has_issues = True
                else:
                    if self._is_apple_git():
                        self.print_info(
                            "  - http.sslCAInfo not configured"
                            " (Apple Git uses system trust store)"
                        )
                    else:
                        self.print_warn(
                            "  - http.sslCAInfo not configured"
                            " (OpenSSL-linked git needs explicit CA bundle)"
                        )
                        has_issues = True
            except Exception:
                self.print_warn("  ✗ Failed to check git configuration")
                has_issues = True
        else:
            self.print_info("  - Git not installed")
        return has_issues

    def check_curl_status(self, temp_warp_cert):
        """Check curl configuration status."""
        has_issues = False
        if self.command_exists('curl'):
            verify_result = self.verify_connection("curl")

            if verify_result == "WORKING":
                self.print_info("  ✓ curl can connect through proxy")

                # Check if it's using SecureTransport (macOS system curl)
                try:
                    result = subprocess.run(['curl', '--version'], capture_output=True, text=True, check=False)
                    if 'SecureTransport' in result.stdout:
                        self.print_info("  ✓ Using macOS system curl with SecureTransport (uses system keychain)")
                    elif os.environ.get('CURL_CA_BUNDLE'):
                        curl_bundle = os.environ['CURL_CA_BUNDLE']
                        self.print_info(f"  - CURL_CA_BUNDLE is set to: {curl_bundle}")
                        other_provider = self._path_belongs_to_other_provider(curl_bundle)
                        if other_provider:
                            self.print_warn(f"  ⚠ CURL_CA_BUNDLE points to a previous provider's path ({other_provider})")
                            self.print_action("    Run with --fix to migrate to the current provider's bundle")
                            has_issues = True
                        elif os.path.exists(curl_bundle):
                            suspicious, reason = self.is_suspicious_full_bundle(curl_bundle, temp_warp_cert)
                            if suspicious:
                                self.print_warn(f"  ⚠ CURL_CA_BUNDLE looks suspiciously small ({reason})")
                                self.print_action("    Run with --fix to repoint to a full CA bundle")
                                has_issues = True
                    else:
                        self.print_info("  - Using system certificate trust (no custom CA needed)")
                except Exception:
                    pass
            else:
                curl_bundle = os.environ.get('CURL_CA_BUNDLE', '')
                curlrc, rc_cacert, _ = self._effective_curlrc_cacert()
                rc_covered = (
                    rc_cacert is not None and os.path.exists(rc_cacert)
                    and self._status_roots_present(temp_warp_cert, rc_cacert, likely=True)
                )
                if rc_cacert is not None and not rc_covered:
                    self.print_warn(f"  ✗ cacert directive in {curlrc} overrides CURL_CA_BUNDLE")
                    self.print_info(f"    curl's effective trust store: {rc_cacert}")
                    self.print_warn("    it is missing the proxy CA certificate (or does not exist)")
                    self.print_action("    Run with --fix to point it at a fumitm-managed bundle")
                    has_issues = True
                elif curl_bundle:
                    other_provider = self._path_belongs_to_other_provider(curl_bundle)
                    if other_provider:
                        self.print_warn(f"  ✗ CURL_CA_BUNDLE points to a previous provider's path ({other_provider})")
                        self.print_action("    Run with --fix to migrate to the current provider's bundle")
                    elif os.path.exists(curl_bundle):
                        suspicious, reason = self.is_suspicious_full_bundle(curl_bundle, temp_warp_cert)
                        if suspicious:
                            self.print_warn(f"  ✗ CURL_CA_BUNDLE points to suspicious bundle ({reason})")
                            self.print_action("    Run with --fix to create a full CA bundle")
                        else:
                            self.print_warn("  ✗ curl configured but connection test failed")
                    else:
                        self.print_warn(f"  ✗ CURL_CA_BUNDLE points to non-existent file: {curl_bundle}")
                    has_issues = True
                else:
                    self.print_warn("  ✗ curl connection test failed")
                    self.print_action("    Run with --fix to configure CURL_CA_BUNDLE")
                    has_issues = True
        else:
            self.print_info("  - curl not installed")
        return has_issues

    def check_aws_status(self, temp_warp_cert):
        """Check AWS CLI configuration status."""
        has_issues = False
        if self.command_exists('aws'):
            verify_result = self.verify_connection("aws")

            if verify_result == "WORKING":
                self.print_info("  ✓ AWS CLI can connect through proxy")

                # Check env var status (informational only)
                aws_bundle = os.environ.get('AWS_CA_BUNDLE', '')
                if aws_bundle:
                    self.print_info(f"  - AWS_CA_BUNDLE is set to: {aws_bundle}")
                    other_provider = self._path_belongs_to_other_provider(aws_bundle)
                    if other_provider:
                        self.print_warn(f"  ⚠ AWS_CA_BUNDLE points to a previous provider's path ({other_provider})")
                        self.print_action("    Run with --fix to migrate to the current provider's bundle")
                        has_issues = True
                    elif os.path.exists(aws_bundle):
                        suspicious, reason = self.is_suspicious_full_bundle(aws_bundle, temp_warp_cert)
                        if suspicious:
                            self.print_warn(f"  ⚠ AWS_CA_BUNDLE looks suspiciously small ({reason})")
                            self.print_action("    Run with --fix to repoint to a full CA bundle")
                            has_issues = True
                else:
                    self.print_info("  - Using system certificate trust (no custom CA needed)")
            else:
                aws_bundle = os.environ.get('AWS_CA_BUNDLE', '')
                if aws_bundle:
                    other_provider = self._path_belongs_to_other_provider(aws_bundle)
                    if other_provider:
                        self.print_warn(f"  ✗ AWS_CA_BUNDLE points to a previous provider's path ({other_provider})")
                        self.print_action("    Run with --fix to migrate to the current provider's bundle")
                    elif os.path.exists(aws_bundle):
                        suspicious, reason = self.is_suspicious_full_bundle(aws_bundle, temp_warp_cert)
                        if suspicious:
                            self.print_warn(f"  ✗ AWS_CA_BUNDLE points to suspicious bundle ({reason})")
                            self.print_action("    Run with --fix to create a full CA bundle")
                        else:
                            self.print_warn("  ✗ AWS CLI configured but connection test failed")
                    else:
                        self.print_warn(f"  ✗ AWS_CA_BUNDLE points to non-existent file: {aws_bundle}")
                    has_issues = True
                else:
                    self.print_warn("  ✗ AWS CLI connection test failed")
                    self.print_action("    Run with --fix to configure AWS_CA_BUNDLE")
                    has_issues = True
        else:
            self.print_info("  - AWS CLI not installed")
        return has_issues

    def get_jenv_java_homes(self):
        """Return the Java home directories from jenv.

        Returns:
            list: The physical JDK installation paths.
        """
        if not self.command_exists('jenv'):
            return []

        try:
            result = subprocess.run(
                ['jenv', 'versions', '--verbose'],
                capture_output=True,
                text=True,
                timeout=10, check=False
            )

            if result.returncode != 0:
                return []

            java_homes = set()
            for line in result.stdout.splitlines():
                # Look for lines with --> which indicate symlink targets
                if '-->' in line:
                    path = line.split('-->')[1].strip()
                    if not path:
                        continue
                    # Look for cacerts to confirm a JDK. The "system" entry
                    # often gives the working directory or the home directory.
                    cacerts = os.path.join(path, 'lib', 'security', 'cacerts')
                    jre_cacerts = os.path.join(path, 'jre', 'lib', 'security', 'cacerts')
                    if os.path.exists(cacerts) or os.path.exists(jre_cacerts):
                        java_homes.add(path)

            return sorted(java_homes)
        except Exception as e:
            self.print_debug(f"Error getting jenv Java homes: {e}")
            return []

    def setup_java_cert(self):
        """Setup Java certificate for all detected installations."""
        if not self.command_exists('java') and not self.command_exists('keytool'):
            return ToolResult('java', 'skipped', 'Java/keytool not found')

        java_homes = self.find_all_java_homes()

        if not java_homes:
            self.print_warn("No Java installations found")
            return ToolResult('java', 'skipped', 'No Java installations found')

        if len(java_homes) > 1:
            self.print_info(f"Found {len(java_homes)} Java installation(s)")

        configured_count = 0
        already_ok_count = 0
        failed_count = 0

        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"  ✗ {version_name}: Could not find cacerts file")
                failed_count += 1
                continue

            status = self._ensure_roots_in_keystore('keytool', cacerts, version_name)
            if status == 'already_ok':
                self.print_info(f"  ✓ {version_name}: Certificate already installed")
                already_ok_count += 1
            elif status == 'configured':
                configured_count += 1
            else:
                failed_count += 1

        total = len(java_homes)
        if failed_count > 0 and configured_count == 0 and already_ok_count == 0:
            return ToolResult('java', 'failed', f'All {failed_count} Java installation(s) failed')
        if failed_count > 0:
            changed = configured_count > 0
            message_parts = []
            if configured_count > 0:
                message_parts.append(f'{configured_count}/{total} Java installation(s) configured')
            if already_ok_count > 0:
                message_parts.append(f'{already_ok_count}/{total} already OK')
            message_parts.append(f'{failed_count}/{total} failed')
            return ToolResult('java', 'failed', '; '.join(message_parts), changed)
        if configured_count > 0:
            return ToolResult('java', 'configured', f'{configured_count}/{total} Java installation(s) configured')
        return ToolResult('java', 'already_ok', 'All Java installations already configured')

    def setup_jenv_cert(self):
        """Setup Java certificates for all jenv-managed Java installations."""
        java_homes = self.get_jenv_java_homes()

        if not java_homes:
            return ToolResult('jenv', 'skipped', 'No jenv installations found')

        if not self.command_exists('keytool'):
            self.print_warn("keytool not found, cannot configure jenv Java installations")
            return ToolResult('jenv', 'skipped', 'keytool not found')

        self.print_info(f"Found {len(java_homes)} jenv-managed Java installation(s)")

        configured_count = 0
        already_ok_count = 0
        failed_count = 0

        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"  Skipping {version_name}: cacerts file not found")
                failed_count += 1
                continue

            status = self._ensure_roots_in_keystore('keytool', cacerts, version_name)
            if status == 'already_ok':
                self.print_info(f"  ✓ {version_name}: Certificate already installed")
                already_ok_count += 1
            elif status == 'configured':
                configured_count += 1
            else:
                failed_count += 1

        total = len(java_homes)
        if failed_count > 0 and configured_count == 0 and already_ok_count == 0:
            return ToolResult('jenv', 'failed', f'All {failed_count} jenv installation(s) failed')
        if failed_count > 0:
            changed = configured_count > 0
            message_parts = []
            if configured_count > 0:
                message_parts.append(f'{configured_count}/{total} jenv installation(s) configured')
            if already_ok_count > 0:
                message_parts.append(f'{already_ok_count}/{total} already OK')
            message_parts.append(f'{failed_count}/{total} failed')
            return ToolResult('jenv', 'failed', '; '.join(message_parts), changed)
        if configured_count > 0:
            return ToolResult('jenv', 'configured', f'{configured_count}/{total} jenv installation(s) configured')
        return ToolResult('jenv', 'already_ok', 'All jenv installations already configured')

    def setup_gradle_cert(self):
        """Setup Gradle certificate configuration."""
        gradle_props = self.get_gradle_properties_path()

        if not self.command_exists('gradle') and not os.path.exists(gradle_props):
            return ToolResult('gradle', 'skipped', 'gradle not found in PATH')

        parsed = self._property_lines_with_vendor_scope(gradle_props)
        if parsed is None:
            self.print_error(f"Could not read Gradle properties at {gradle_props}")
            return ToolResult(
                'gradle', 'failed',
                'Could not read Gradle properties; existing override preserved'
            )
        pinned_java_home = self._gradle_pinned_java_home(parsed)
        if self._aikido_active:
            cacerts = self._gradle_java_cacerts(gradle_props, parsed=parsed)
            if not cacerts:
                if pinned_java_home:
                    message = (
                        'org.gradle.java.home has no Java cacerts file: '
                        f'{pinned_java_home}'
                    )
                    self.print_error(message)
                    return ToolResult('gradle', 'failed', message)
                self.print_error("Could not find Java cacerts file for Gradle")
                return ToolResult('gradle', 'skipped', 'Java cacerts file not found')
            java_status = self._ensure_roots_in_keystore(
                'keytool', cacerts, 'Gradle Java truststore'
            )
            if java_status == 'failed':
                return ToolResult(
                    'gradle', 'failed',
                    'Could not prepare Java trust before removing Gradle override'
                )
            if (
                self.is_install_mode()
                and not self._keystore_has_expected_roots('keytool', cacerts)
            ):
                self.print_error(
                    "Could not verify all proxy roots in Gradle's Java truststore"
                )
                return ToolResult(
                    'gradle', 'failed',
                    'Java trust verification failed; Gradle override preserved'
                )

            managed = self._gradle_fumitm_truststore_properties()
            truststore_override = {
                'systemProp.javax.net.ssl.trustStore':
                    managed['systemProp.javax.net.ssl.trustStore']
            }
            changed = False
            # The password, type, and TLS values are not unique to fumitm. The
            # exact custom-cacerts path proves ownership before removing them.
            if self._properties_have_values_outside_vendor_blocks(
                    parsed, truststore_override):
                changed = self._remove_property_values_outside_vendor_blocks(
                    gradle_props, managed, 'Gradle properties', parsed=parsed
                )
            if (changed or java_status == 'configured') and self.is_install_mode():
                if changed and java_status == 'configured':
                    message = 'Configured Java trust and removed fumitm Gradle override'
                elif changed:
                    message = 'Removed fumitm Gradle truststore override'
                else:
                    message = 'Configured Java trust for Gradle'
                return ToolResult(
                    'gradle', 'configured', message
                )
            if changed or java_status == 'configured':
                return ToolResult('gradle', 'skipped', 'Dry run')
            return ToolResult(
                'gradle', 'already_ok', 'Gradle uses Aikido/JDK trust configuration'
            )

        cacerts = self._gradle_java_cacerts(gradle_props, parsed=parsed)
        if not cacerts:
            if pinned_java_home:
                message = (
                    'org.gradle.java.home has no Java cacerts file: '
                    f'{pinned_java_home}'
                )
                self.print_error(message)
                return ToolResult('gradle', 'failed', message)
            self.print_error("Could not find Java cacerts file for Gradle")
            return ToolResult('gradle', 'skipped', 'Java cacerts file not found')

        gradle_cacerts = self.get_gradle_custom_cacerts_path()
        truststore_status = self.ensure_gradle_custom_truststore(cacerts, gradle_cacerts)
        if truststore_status == 'failed':
            return ToolResult('gradle', 'failed', 'Failed to rebuild Gradle custom truststore')

        props_to_set = {
            'systemProp.javax.net.ssl.trustStore': gradle_cacerts,
            'systemProp.javax.net.ssl.trustStorePassword': 'changeit',
            'systemProp.javax.net.ssl.trustStoreType': 'PKCS12',
            'systemProp.https.protocols': 'TLSv1.2'
        }

        changed = self.update_properties_file(gradle_props, props_to_set, "Gradle properties")
        if not changed and truststore_status == 'already_ok':
            return ToolResult('gradle', 'already_ok', 'Gradle properties already configured')
        if self.is_install_mode():
            return ToolResult('gradle', 'configured', 'Configured Gradle custom truststore')
        return ToolResult('gradle', 'skipped', 'Dry run')

    def setup_dbeaver_cert(self):
        """Setup DBeaver certificate."""
        dbeaver_keytool = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/bin/keytool"
        dbeaver_cacerts = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"

        if not os.path.exists(dbeaver_keytool):
            return ToolResult('dbeaver', 'skipped', 'DBeaver not installed')

        if not os.path.exists(dbeaver_cacerts):
            self.print_error(f"DBeaver cacerts file not found at: {dbeaver_cacerts}")
            return ToolResult('dbeaver', 'failed', 'DBeaver cacerts file not found')

        self.print_info("Configuring DBeaver certificate...")
        self.print_info("Found DBeaver at default install location")

        status = self._ensure_roots_in_keystore(dbeaver_keytool, dbeaver_cacerts, 'DBeaver')
        if status == 'already_ok':
            return ToolResult('dbeaver', 'already_ok', 'Certificate already installed')
        if status == 'configured':
            return ToolResult('dbeaver', 'configured', 'Certificate added to DBeaver keystore')
        return ToolResult('dbeaver', 'failed', 'Failed to add certificate (may require sudo)')
    
    def _last_active_wgetrc_ca(self, content):
        """Return the path from the last active ca_certificate= line, or None.

        wget uses the last directive. Thus the trust check must examine the final
        ca_certificate= entry that is not a comment, and not the first entry.
        """
        found = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if stripped.startswith('ca_certificate='):
                found = stripped.split('=', 1)[1].strip()
        return found

    def setup_wget_cert(self):
        """Setup wget certificate."""
        if not self.command_exists('wget'):
            return ToolResult('wget', 'skipped', 'wget not found in PATH')

        # If wget already works, add no configuration.
        verify_result = self.verify_connection("wget")
        if verify_result == "WORKING":
            self.print_debug("wget already works via system trust, skipping configuration")
            return ToolResult('wget', 'already_ok', 'Works via system trust store')

        wgetrc_path = os.path.expanduser("~/.wgetrc")
        wget_bundle = os.path.join(self.bundle_dir, "wget/ca-bundle.pem")
        config_line = f"ca_certificate={wget_bundle}"

        original = ''
        if os.path.exists(wgetrc_path):
            with open(wgetrc_path, 'r') as f:
                original = f.read()

        already_ok = (
            self._last_active_wgetrc_ca(original) == wget_bundle
            and os.path.exists(wget_bundle)
            and self._all_roots_present_in_file(wget_bundle)
        )
        if already_ok:
            return ToolResult('wget', 'already_ok', 'wget certificate already configured')

        self.print_info("Configuring wget certificate...")
        if not self.is_install_mode():
            self.print_action(f"Would create wget CA bundle at {wget_bundle}")
            self.print_action(f"Would set in {wgetrc_path}: {config_line}")
            return ToolResult('wget', 'skipped', 'Dry run')

        # Build the bundle with the primary root and each supplemental root,
        # thus wget trusts the proxy that intercepts the connection.
        self._safe_makedirs(os.path.dirname(wget_bundle))
        self.create_bundle_with_system_certs(wget_bundle)
        self._append_all_proxy_roots(wget_bundle)

        # Rewrite ~/.wgetrc. Remove each active ca_certificate directive and
        # append ours last.
        kept = [
            line for line in original.splitlines()
            if not line.strip().startswith('ca_certificate=')
        ]
        while kept and kept[-1].strip() == '':
            kept.pop()
        new = (('\n'.join(kept) + '\n\n') if kept else '') + config_line + '\n'

        if wgetrc_path not in self._backed_up_shell_configs:
            if os.path.exists(wgetrc_path):
                with open(wgetrc_path + '.bak', 'w') as f:
                    f.write(original)
                self._fix_ownership(wgetrc_path + '.bak')
            self._backed_up_shell_configs.add(wgetrc_path)

        with open(wgetrc_path, 'w') as f:
            f.write(new)
        self._fix_ownership(wgetrc_path)
        self.print_info(f"Configured wget ca_certificate to: {wget_bundle}")
        return ToolResult('wget', 'configured', 'Configured wget ca_certificate')
    
    def _podman_vm_running(self):
        """Check whether a Podman machine is currently running."""
        try:
            result = subprocess.run(
                ['podman', 'machine', 'list'],
                capture_output=True, text=True, check=False
            )
            return 'Currently running' in result.stdout
        except Exception:
            return False

    def _check_cert_in_podman_vm(self):
        """Return True if every proxy root is present in the Podman VM."""
        try:
            for cert_name, _ in self._all_container_certs():
                result = subprocess.run(
                    ['podman', 'machine', 'ssh',
                     f'test -f /etc/pki/ca-trust/source/anchors/{cert_name}.pem'],
                    capture_output=True, check=False
                )
                if result.returncode != 0:
                    return False
            return True
        except Exception:
            return False

    def _install_cert_via_podman_ssh(self):
        """Install the certificate into the Podman VM with podman machine ssh.

        A Podman VM uses Fedora, thus this method uses the /etc/pki/ca-trust paths.
        fumitm uses this method when Docker nsenter is not available.

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            for cert_name, cert_path in self._all_container_certs():
                with open(cert_path, 'r') as f:
                    cert_content = f.read()
                result = subprocess.run(
                    ['podman', 'machine', 'ssh',
                     f'sudo tee /etc/pki/ca-trust/source/anchors/{cert_name}.pem'],
                    input=cert_content, text=True, capture_output=True, check=False
                )
                if result.returncode != 0:
                    return False, 'Failed to copy certificate into VM'

            result = subprocess.run(
                ['podman', 'machine', 'ssh', 'sudo update-ca-trust'],
                capture_output=True, check=False
            )
            if result.returncode == 0:
                return True, 'Certificate installed in Podman VM'
            return False, 'Certificate copied but update-ca-trust failed'
        except Exception as e:
            return False, str(e)

    def setup_podman_cert(self):
        """Configure the certificate for Podman.

        fumitm writes to ~/.docker/certs.d/ for registry trust, and into the Podman
        VM with podman machine ssh. It always uses the Podman SSH and not Docker
        nsenter. Thus it does not install into the VM of a different runtime when
        both Podman and Docker are present.
        """
        if not self.command_exists('podman'):
            return ToolResult('podman', 'skipped', 'Podman not installed')

        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        persistent_installed = self._container_certs_present(docker_certs_dir)

        vm_is_running = self._podman_vm_running()
        vm_needs_cert = False
        if vm_is_running:
            try:
                vm_needs_cert = not self._check_cert_in_podman_vm()
            except Exception:
                pass

        if persistent_installed and (not vm_is_running or not vm_needs_cert):
            self.print_debug("Podman certificate already installed, skipping")
            return ToolResult('podman', 'already_ok', 'Certificate already installed')

        self.print_info("Configuring Podman certificate...")

        if not self.is_install_mode():
            if not persistent_installed:
                self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running and vm_needs_cert:
                self.print_action("Would install certificate into Podman VM")
        else:
            persistent_changed = False
            vm_failed = False

            if not persistent_installed:
                self._install_container_certs(docker_certs_dir)
                persistent_changed = True

            if vm_is_running and vm_needs_cert:
                self.print_info("Installing certificate into Podman VM...")
                success, msg = self._install_cert_via_podman_ssh()

                if success:
                    self.print_info(msg)
                else:
                    self.print_warn(f"Failed to install certificate into VM: {msg}")
                    vm_failed = True
            elif vm_is_running and not vm_needs_cert:
                self.print_info("Certificate already installed in VM")
            elif not vm_is_running:
                self.print_info("Podman machine is not running")

            if vm_failed and not persistent_changed:
                return ToolResult('podman', 'failed', 'Failed to install certificate into VM')
            if vm_failed:
                return ToolResult('podman', 'configured', 'Persistent cert installed but VM install failed')
            if persistent_changed:
                return ToolResult('podman', 'configured', 'Certificate installed')
            return ToolResult('podman', 'already_ok', 'Certificate already installed')
    
    def _check_cert_in_rancher_vm(self):
        """Check whether the CA cert exists in the Rancher Desktop VM."""
        try:
            for cert_name, _ in self._all_container_certs():
                result = subprocess.run(
                    ['rdctl', 'shell', 'test', '-f',
                     f'/usr/local/share/ca-certificates/{cert_name}.crt'],
                    capture_output=True, check=False
                )
                if result.returncode != 0:
                    return False
            return True
        except Exception:
            return False

    def _install_cert_via_rdctl_shell(self):
        """Install the certificate into the Rancher Desktop VM with rdctl shell.

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            for cert_name, cert_path in self._all_container_certs():
                with open(cert_path, 'r') as f:
                    cert_content = f.read()
                result = subprocess.run(
                    ['rdctl', 'shell', 'sudo', 'tee',
                     f'/usr/local/share/ca-certificates/{cert_name}.crt'],
                    input=cert_content, text=True, capture_output=True, check=False
                )
                if result.returncode != 0:
                    return False, 'Failed to copy certificate into VM'

            result = subprocess.run(
                ['rdctl', 'shell', 'sudo', 'update-ca-certificates'],
                capture_output=True, check=False
            )
            if result.returncode == 0:
                return True, 'Certificate installed in Rancher Desktop VM'
            return False, 'Certificate copied but update-ca-certificates failed'
        except Exception as e:
            return False, str(e)

    def setup_rancher_cert(self):
        """Configure the certificate for Rancher Desktop.

        fumitm writes to ~/.docker/certs.d/ for registry trust, and into the VM with
        rdctl shell. If that fails, it uses Docker nsenter.
        """
        if not self.command_exists('rdctl'):
            return ToolResult('rancher', 'skipped', 'Rancher Desktop not installed')

        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        persistent_installed = self._container_certs_present(docker_certs_dir)

        vm_is_running = False
        vm_needs_cert = False
        try:
            result = subprocess.run(['rdctl', 'version'], capture_output=True, text=True, check=False)
            vm_is_running = result.returncode == 0
            if vm_is_running:
                vm_needs_cert = not self._check_cert_in_rancher_vm()
        except Exception:
            pass

        if persistent_installed and (not vm_is_running or not vm_needs_cert):
            self.print_debug("Rancher Desktop certificate already installed, skipping")
            return ToolResult('rancher', 'already_ok', 'Certificate already installed')

        self.print_info("Configuring Rancher Desktop certificate...")

        if not self.is_install_mode():
            if not persistent_installed:
                self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running and vm_needs_cert:
                self.print_action("Would install certificate into Rancher Desktop VM")
        else:
            persistent_changed = False
            vm_failed = False

            if not persistent_installed:
                self._install_container_certs(docker_certs_dir)
                persistent_changed = True

            if vm_is_running and vm_needs_cert:
                self.print_info("Installing certificate into Rancher Desktop VM...")
                # Use native rdctl shell, fall back to Docker nsenter
                success, msg = self._install_cert_via_rdctl_shell()
                if not success and self.command_exists('docker'):
                    self.print_debug(f"rdctl shell failed ({msg}), trying nsenter")
                    success, msg = self._install_cert_in_docker_vm()
                if success:
                    self.print_info(msg)
                else:
                    self.print_warn(f"Failed to install certificate into VM: {msg}")
                    vm_failed = True
            elif vm_is_running and not vm_needs_cert:
                self.print_info("Certificate already installed in VM")
            elif not vm_is_running:
                self.print_info("Rancher Desktop is not running")

            if vm_failed and not persistent_changed:
                return ToolResult('rancher', 'failed', 'Failed to install certificate into VM')
            if vm_failed:
                return ToolResult('rancher', 'configured', 'Persistent cert installed but VM install failed')
            if persistent_changed:
                return ToolResult('rancher', 'configured', 'Certificate installed')
            return ToolResult('rancher', 'already_ok', 'Certificate already installed')
    
    def setup_android_emulator_cert(self):
        """Setup Android Emulator certificate."""
        if not self.command_exists('adb') or not self.command_exists('emulator'):
            self.print_info("Android SDK tools not found, skipping Android Emulator setup")
            return ToolResult('android', 'skipped', 'Android SDK tools not found')

        self.print_info("Checking for Android Emulator setup...")

        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, check=False)
            running_devices = sum(1 for line in result.stdout.splitlines() if 'emulator-' in line)

            if running_devices == 0:
                self.print_info("No Android emulator is currently running")
                self.print_info("Please start an emulator with: emulator -avd <your_avd_id> -writable-system -selinux permissive")
                return ToolResult('android', 'skipped', 'No emulator running')
        except Exception:
            return ToolResult('android', 'skipped', 'Failed to check for emulators')

        self.print_warn("Android Emulator certificate installation requires a writable system partition")
        self.print_warn("Make sure your emulator was started with -writable-system flag")

        if not self.is_install_mode():
            self.print_action("Would restart ADB with root permissions: adb root")
            self.print_action("Would remount system partition: adb remount")
            self.print_action(f"Would push certificate to emulator: adb push {self.cert_path} /system/etc/security/cacerts/{self.provider['container_cert_name']}.pem")
            self.print_action(f"Would set permissions: adb shell chmod 644 /system/etc/security/cacerts/{self.provider['container_cert_name']}.pem")
            self.print_action("Would reboot emulator: adb reboot")
        else:
            response = self._prompt("Do you want to install the certificate on the running Android emulator? (y/N) ")
            if response.lower() == 'y':
                self.print_info("Installing certificate on Android emulator...")

                # Restart ADB with root
                result = subprocess.run(['adb', 'root'], capture_output=True, check=False)
                if result.returncode != 0:
                    self.print_error("Failed to restart ADB with root permissions")
                    self.print_info("Make sure your emulator doesn't have Google Play Store")
                    return ToolResult('android', 'failed', 'Failed to restart ADB with root permissions')

                # Remount system partition
                result = subprocess.run(['adb', 'remount'], capture_output=True, check=False)
                if result.returncode != 0:
                    self.print_error("Failed to remount system partition")
                    self.print_info("Make sure emulator was started with -writable-system flag")
                    return ToolResult('android', 'failed', 'Failed to remount system partition')

                # Push each proxy root (primary + supplemental) into the emulator
                push_failed = False
                for cert_name, cert_path in self._all_container_certs():
                    dest = f'/system/etc/security/cacerts/{cert_name}.pem'
                    result = subprocess.run(
                        ['adb', 'push', cert_path, dest], capture_output=True, check=False
                    )
                    if result.returncode != 0:
                        push_failed = True
                        break
                    subprocess.run(
                        ['adb', 'shell', 'chmod', '644', dest], capture_output=True, check=False
                    )
                if not push_failed:
                    self.print_info("Certificate installed. Rebooting emulator...")
                    subprocess.run(['adb', 'reboot'], capture_output=True, check=False)
                    self.print_info("Android emulator certificate installed successfully")
                    return ToolResult('android', 'configured', 'Certificate installed on emulator')
                else:
                    self.print_error("Failed to push certificate to emulator")
                    return ToolResult('android', 'failed', 'Failed to push certificate to emulator')
            else:
                return ToolResult('android', 'skipped', 'User declined installation')
    
    @staticmethod
    def _colima_cmd(profile, *args):
        """Build a Colima command for one profile."""
        return ['colima', '--profile', profile, *args]

    def _check_cert_in_colima_vm(self, profile='default'):
        """Check whether every managed CA cert exists in a Colima VM."""
        try:
            for cert_name, _ in self._all_container_certs():
                result = subprocess.run(
                    self._colima_cmd(
                        profile, 'ssh', '--', 'test', '-f',
                        f'/usr/local/share/ca-certificates/{cert_name}.crt'
                    ),
                    capture_output=True, timeout=30, check=False
                )
                if result.returncode != 0:
                    return False
            return True
        except subprocess.TimeoutExpired:
            self.print_debug(f"Timed out checking Colima profile {profile}")
            return False
        except Exception:
            return False

    def _install_cert_via_colima_ssh(self, profile='default'):
        """Install the certificate into the Colima VM with colima ssh.

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            for cert_name, cert_path in self._all_container_certs():
                with open(cert_path, 'r') as f:
                    cert_content = f.read()
                result = subprocess.run(
                    self._colima_cmd(
                        profile, 'ssh', '--', 'sudo', 'tee',
                        f'/usr/local/share/ca-certificates/{cert_name}.crt'
                    ),
                    input=cert_content, text=True, capture_output=True,
                    timeout=60, check=False
                )
                if result.returncode != 0:
                    return False, 'Failed to copy certificate into VM'

            result = subprocess.run(
                self._colima_cmd(
                    profile, 'ssh', '--', 'sudo', 'update-ca-certificates'
                ),
                capture_output=True, timeout=60, check=False
            )
            if result.returncode == 0:
                return True, 'Certificate installed in Colima VM'
            return False, 'Certificate copied but update-ca-certificates failed'
        except subprocess.TimeoutExpired:
            return False, 'colima ssh timed out'
        except Exception as e:
            return False, str(e)

    def setup_colima_cert(self):
        """Configure the certificate for Colima.

        fumitm keeps persistent copies in ~/.docker/certs.d/ and installs the roots
        into the selected VM with colima ssh. The native route is authoritative:
        falling back to Docker nsenter could target a different installed runtime
        and could require the registry access that this repair is meant to restore.
        """
        if not self.command_exists('colima'):
            return ToolResult('colima', 'skipped', 'Colima not installed')

        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        persistent_installed = self._container_certs_present(docker_certs_dir)

        profile = self._colima_profile_for_tool()
        vm_is_running = False
        vm_needs_cert = False
        try:
            status_result = subprocess.run(
                self._colima_cmd(profile, 'status'),
                capture_output=True, timeout=10, check=False
            )
            vm_is_running = (status_result.returncode == 0)
            if vm_is_running:
                vm_needs_cert = not self._check_cert_in_colima_vm(profile)
        except Exception:
            pass

        if persistent_installed and (not vm_is_running or not vm_needs_cert):
            self.print_debug("Colima certificate already installed, skipping")
            return ToolResult('colima', 'already_ok', 'Certificate already installed')

        self.print_info("Configuring Colima certificate...")

        if not self.is_install_mode():
            if not persistent_installed:
                self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running and vm_needs_cert:
                self.print_action("Would install certificate into Colima VM")
        else:
            persistent_changed = False
            vm_changed = False
            vm_failed = False
            vm_failure_message = None

            if not persistent_installed:
                self._install_container_certs(docker_certs_dir)
                persistent_changed = True

            if vm_is_running and vm_needs_cert:
                self.print_info("Installing certificate into Colima VM...")
                success, msg = self._install_cert_via_colima_ssh(profile)
                if success:
                    self.print_info(msg)
                    vm_changed = True
                    if not self._restart_docker_in_colima(profile):
                        vm_failed = True
                        vm_failure_message = (
                            'VM certificate installed but Docker engine restart failed'
                        )
                else:
                    self.print_warn(f"Failed to install certificate into VM: {msg}")
                    vm_failed = True
                    vm_failure_message = f'VM install failed: {msg}'
            elif vm_is_running and not vm_needs_cert:
                self.print_info("Certificate already installed in VM")
            elif not vm_is_running:
                self.print_info("Colima is not running - certificate will be applied on next start")

            if vm_failed:
                if persistent_changed:
                    message = f'Persistent cert installed; {vm_failure_message}'
                else:
                    message = vm_failure_message
                return ToolResult(
                    'colima', 'failed', message, persistent_changed or vm_changed
                )
            if persistent_changed or vm_changed:
                return ToolResult('colima', 'configured', 'Certificate installed')
            return ToolResult('colima', 'already_ok', 'Certificate already installed')

    def _docker_is_running(self):
        """Check whether a Docker daemon is running (any backend)."""
        try:
            result = subprocess.run(
                ['docker', 'info'],
                capture_output=True, text=True, timeout=10, check=False
            )
            return result.returncode == 0
        except Exception:
            return False

    def _effective_docker_endpoint(self):
        """Return the endpoint selected by the Docker CLI.

        Docker gives DOCKER_HOST precedence over the current context. Matching
        that precedence is important when a user has selected one context but the
        current shell still points at another daemon.
        """
        docker_host = os.environ.get('DOCKER_HOST', '').strip()
        if docker_host:
            self.print_debug(f"Using Docker endpoint from DOCKER_HOST: {docker_host}")
            return docker_host

        try:
            result = subprocess.run(
                [
                    'docker', 'context', 'inspect', '--format',
                    '{{.Endpoints.docker.Host}}'
                ],
                capture_output=True, text=True, timeout=10, check=False
            )
            endpoint = result.stdout.strip()
            if result.returncode == 0 and endpoint:
                self.print_debug(f"Using Docker endpoint from current context: {endpoint}")
                return endpoint
        except Exception as e:
            self.print_debug(f"Could not inspect the current Docker context: {e}")
        return None

    @staticmethod
    def _colima_profile_from_endpoint(endpoint):
        """Return the Colima profile encoded in a Docker Unix socket path."""
        if not endpoint or not endpoint.startswith('unix://'):
            return None
        socket_path = endpoint[len('unix://'):]
        match = re.search(r'/\.colima/([^/]+)/docker\.sock$', socket_path)
        if not match:
            return None
        profile = match.group(1)
        if not re.fullmatch(r'[A-Za-z0-9._-]+', profile):
            return None
        return profile

    def _active_colima_profile_for_docker(self):
        """Return the active Docker daemon's Colima profile, if it has one."""
        if not self.command_exists('colima'):
            return None
        return self._colima_profile_from_endpoint(self._effective_docker_endpoint())

    def _colima_profile_for_tool(self):
        """Choose the Colima profile used by the explicit Colima tool.

        Prefer the profile selected by Docker. If Docker does not identify one,
        use the sole running profile from ``colima list``. Ambiguous or unavailable
        state falls back to Colima's default profile.

        Several running profiles with no Docker selection is a state fumitm cannot
        resolve on its own, and picking one arbitrarily would repair the wrong VM.
        It says so instead: without the warning the default profile is not running
        either, and the run ends on "Colima is not running" while the VMs the user
        cares about are up and untrusted.
        """
        profile = self._active_colima_profile_for_docker()
        if profile:
            return profile

        try:
            result = subprocess.run(
                ['colima', 'list', '--json'],
                capture_output=True, text=True, timeout=10, check=False
            )
            if result.returncode == 0:
                running = []
                for line in result.stdout.splitlines():
                    try:
                        entry = json.loads(line)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    name = entry.get('name')
                    status = entry.get('status')
                    if (
                        isinstance(name, str)
                        and re.fullmatch(r'[A-Za-z0-9._-]+', name)
                        and isinstance(status, str)
                        and status.lower() == 'running'
                    ):
                        running.append(name)
                if len(running) == 1:
                    self.print_debug(f"Using the only running Colima profile: {running[0]}")
                    return running[0]
                if len(running) > 1 and 'default' not in running:
                    self.print_warn(
                        "Several Colima profiles are running and Docker selects "
                        f"none of them: {', '.join(sorted(running))}"
                    )
                    self.print_info(
                        "Point DOCKER_HOST or the Docker context at the profile "
                        "to repair, or run: colima --profile <name> start"
                    )
        except Exception as e:
            self.print_debug(f"Could not list Colima profiles: {e}")
        return 'default'

    def _find_nsenter_image(self):
        """Find a local Docker image that has nsenter.

        fumitm tries the usual small images with --pull=never, thus it makes no
        network request. A pull would fail when the Docker daemon does not yet trust
        the MITM CA.

        Returns:
            str or None: The image name, or None.
        """
        candidates = ['alpine:latest', 'alpine', 'busybox:latest', 'busybox',
                       'debian:latest', 'ubuntu:latest']
        for image in candidates:
            try:
                result = subprocess.run(
                    ['docker', 'image', 'inspect', image],
                    capture_output=True, timeout=5, check=False
                )
                if result.returncode == 0:
                    self.print_debug(f"Using locally cached image: {image}")
                    return image
            except Exception:
                self.print_debug(f"Image inspect failed for {image}")
                continue
        return None

    def _run_nsenter(self, script, stdin_data=None, timeout=30):
        """Run a command in the namespace of the Docker VM with nsenter.

        fumitm looks for a local image first and makes no network pull. If it finds
        no image, it pulls alpine:latest.

        Returns:
            subprocess.CompletedProcess, or None when fumitm finds no image.
        """
        image = self._find_nsenter_image()
        if not image:
            # Pull alpine. This can fail behind a MITM proxy.
            self.print_debug("No local image found, attempting to pull alpine")
            try:
                pull = subprocess.run(
                    ['docker', 'pull', 'alpine:latest'],
                    capture_output=True, timeout=30, check=False
                )
                if pull.returncode == 0:
                    image = 'alpine:latest'
            except Exception:
                pass
        if not image:
            return None

        cmd = ['docker', 'run', '--rm', '--privileged', '--pid=host']
        if stdin_data is not None:
            cmd.append('-i')
        cmd += [image, 'nsenter', '-t', '1', '-m', '--', 'sh', '-c', script]

        kwargs = {'capture_output': True, 'text': True, 'timeout': timeout}
        if stdin_data is not None:
            kwargs['input'] = stdin_data
        return subprocess.run(cmd, **kwargs, check=False)

    def _check_cert_in_docker_vm(self):
        """Find if the proxy CA certificate is in the Docker VM.

        Uses nsenter with a local container image to examine the file system of the
        VM. Examines the Debian paths and the Fedora paths.
        """
        try:
            for cert_name, _ in self._all_container_certs():
                check_script = (
                    f'test -f /usr/local/share/ca-certificates/{cert_name}.crt'
                    f' || test -f /etc/pki/ca-trust/source/anchors/{cert_name}.pem'
                )
                result = self._run_nsenter(check_script)
                if result is None or result.returncode != 0:
                    return False
            return True
        except Exception:
            return False

    def _install_cert_in_docker_vm(self):
        """Install the proxy CA certificate into the trust store of the Docker VM.

        Uses Docker nsenter, thus it operates with each framework: OrbStack, Colima,
        Docker Desktop, Lima, and others. It finds the Debian paths or the Fedora
        paths automatically. It uses a local image, thus it does not fail when the
        daemon cannot pull from a registry.

        Returns:
            tuple: (success: bool, message: str)
        """
        # Write each root with its own file name, thus all roots go into the
        # VM. Debian and Alpine use .crt in /usr/local/share/ca-certificates/.
        # Fedora and RHEL use .pem in /etc/pki/ca-trust/source/anchors/.
        try:
            for cert_name, cert_path in self._all_container_certs():
                install_script = (
                    f'if [ -d /usr/local/share/ca-certificates ]; then'
                    f'  cat > /usr/local/share/ca-certificates/{cert_name}.crt'
                    f'  && update-ca-certificates 2>/dev/null;'
                    f' elif [ -d /etc/pki/ca-trust/source/anchors ]; then'
                    f'  cat > /etc/pki/ca-trust/source/anchors/{cert_name}.pem'
                    f'  && update-ca-trust 2>/dev/null;'
                    f' else exit 1; fi'
                )
                with open(cert_path, 'r') as f:
                    cert_content = f.read()
                result = self._run_nsenter(install_script, stdin_data=cert_content,
                                           timeout=60)
                if result is None:
                    return False, 'No Docker image available for nsenter (try: docker pull alpine)'
                if result.returncode != 0:
                    self.print_debug(f"nsenter stderr: {result.stderr.strip()}")
                    return False, 'nsenter command failed'
            return True, 'Certificate installed in Docker VM'
        except subprocess.TimeoutExpired:
            return False, 'nsenter timed out'
        except Exception as e:
            return False, str(e)

    def _restart_docker_in_vm(self):
        """Start the Docker daemon in the VM again.

        fumitm finds the framework and uses the correct command.
        """
        restart_strategies = [
            (['orb', 'restart', 'docker'], 'orb'),
            (['colima', 'ssh', '--', 'sudo', 'systemctl', 'restart', 'docker'], 'colima'),
        ]
        for cmd, tool in restart_strategies:
            if self.command_exists(tool):
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, timeout=30, check=False
                    )
                    if result.returncode == 0:
                        self.print_info("Docker engine restarted")
                        return True
                except Exception:
                    pass

        # Generic fallback: restart via nsenter
        try:
            result = self._run_nsenter(
                'command -v systemctl >/dev/null'
                ' && systemctl restart docker 2>/dev/null'
                ' || kill -HUP 1 2>/dev/null'
            )
            if result is not None and result.returncode == 0:
                self.print_info("Docker engine restarted")
                return True
        except Exception:
            pass

        self.print_warn("Could not restart Docker engine automatically")
        self.print_info("Restart Docker manually for the certificate to take effect")
        return False

    def _restart_docker_in_colima(self, profile='default'):
        """Restart Docker in the selected Colima profile."""
        try:
            result = subprocess.run(
                self._colima_cmd(
                    profile, 'ssh', '--', 'sudo', 'systemctl', 'restart', 'docker'
                ),
                capture_output=True, timeout=30, check=False
            )
            if result.returncode == 0:
                self.print_info("Docker engine restarted")
                return True
        except Exception:
            pass
        self.print_warn("Could not restart Docker engine automatically")
        self.print_info(f"Restart Colima profile {profile} manually for the certificate to take effect")
        return False

    def setup_docker_cert(self):
        """Install the proxy CA certificate for Docker with any backend.

        This operates with OrbStack, Colima, Docker Desktop, Lima, Rancher Desktop,
        and other Docker runtimes. There are two layers of trust:

        1. Persistent host-side certificate copies in ~/.docker/certs.d/.
        2. Trust in the VM through a native backend command when available, or
           nsenter otherwise. Thus the Docker daemon and BuildKit trust the CA.
           This covers docker pull, docker push, and BuildKit fetch operations.
        """
        if not self.command_exists('docker'):
            return ToolResult('docker', 'skipped', 'Docker not installed')

        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_name = f"{self.provider['container_cert_name']}.crt"
        cert_dest = os.path.join(docker_certs_dir, cert_name)

        persistent_installed = self._container_certs_present(docker_certs_dir)

        vm_is_running = self._docker_is_running()
        colima_profile = None
        vm_needs_cert = False
        if vm_is_running:
            colima_profile = self._active_colima_profile_for_docker()
            if colima_profile:
                self.print_debug(
                    f"Docker uses Colima profile {colima_profile}; using native VM access"
                )
                vm_needs_cert = not self._check_cert_in_colima_vm(colima_profile)
            else:
                vm_needs_cert = not self._check_cert_in_docker_vm()

        if persistent_installed and (not vm_is_running or not vm_needs_cert):
            self.print_debug("Docker certificate already installed, skipping")
            return ToolResult('docker', 'already_ok', 'Certificate already installed')

        self.print_info("Configuring Docker certificate...")

        if not self.is_install_mode():
            if not persistent_installed:
                self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running and vm_needs_cert:
                self.print_action("Would install certificate into Docker VM")
        else:
            persistent_changed = False
            vm_changed = False
            vm_failed = False
            vm_failure_message = None

            if not persistent_installed:
                self._install_container_certs(docker_certs_dir)
                persistent_changed = True

            if vm_is_running and vm_needs_cert:
                self.print_info("Installing certificate into Docker VM...")
                if colima_profile:
                    success, msg = self._install_cert_via_colima_ssh(colima_profile)
                else:
                    success, msg = self._install_cert_in_docker_vm()
                if success:
                    self.print_info(msg)
                    vm_changed = True
                    if colima_profile:
                        restarted = self._restart_docker_in_colima(colima_profile)
                    else:
                        restarted = self._restart_docker_in_vm()
                    if not restarted:
                        vm_failed = True
                        vm_failure_message = (
                            'VM certificate installed but Docker engine restart failed'
                        )
                else:
                    self.print_warn(f"Failed to install certificate into VM: {msg}")
                    vm_failed = True
                    vm_failure_message = f'VM install failed: {msg}'
            elif vm_is_running and not vm_needs_cert:
                self.print_info("Certificate already installed in VM")
            elif not vm_is_running:
                self.print_info("Docker is not running - certificate will apply when started")

            if vm_failed:
                if persistent_changed:
                    message = f'Persistent cert installed; {vm_failure_message}'
                else:
                    message = vm_failure_message
                return ToolResult(
                    'docker', 'failed', message, persistent_changed or vm_changed
                )
            if persistent_changed or vm_changed:
                return ToolResult('docker', 'configured', 'Certificate installed')
            return ToolResult('docker', 'already_ok', 'Certificate already installed')

    def _print_docker_build_hint(self):
        """Give the necessary Dockerfile changes for trust during a build.

        A build container uses the CA store of the base image and not the trust
        store of the host VM. The user must put the proxy certificate into the
        Dockerfile for each RUN command that makes an HTTPS connection, such as a
        pip install, an npm install, or a curl command. This applies to each Docker
        runtime.
        """
        cert_name = f"{self.provider['container_cert_name']}.crt"
        cert_src = os.path.expanduser(f"~/.docker/certs.d/{cert_name}")
        short = self.provider['short_name']
        print()
        self.print_warn(f"Docker builds require a Dockerfile change to trust the {short} CA.")
        self.print_warn("Without this, pip install / npm install / curl will fail with SSL errors.")
        print()
        self.print_info("Step 1: Copy the cert into your build context:")
        self.print_info(f"  cp {cert_src} .")
        print()
        self.print_info("Step 2: Add these lines to your Dockerfile BEFORE any HTTPS commands")
        self.print_info("        (pip install, npm install, apt-get, curl, wget, etc.):")
        print()
        self.print_info(f"  COPY {cert_name} /usr/local/share/ca-certificates/{cert_name}")
        self.print_info("  RUN update-ca-certificates")
        print()
        self.print_info("Alternative: use a BuildKit named context (no copy needed):")
        self.print_info(f"  docker build --build-context certs={os.path.dirname(cert_src)} .")
        self.print_info("  # Dockerfile: COPY --from=certs"
                        f" {cert_name} /usr/local/share/ca-certificates/{cert_name}")

    def verify_connection(self, tool_name):
        """Verify if a tool can connect through proxy."""
        if self.skip_verify:
            self.print_debug(f"Skipping {tool_name} verification (--skip-verify flag)")
            return "SKIPPED"
        
        # Skip verification in devcontainers as network doesn't go through proxy
        if self.is_devcontainer():
            self.print_debug(f"Skipping {tool_name} verification in devcontainer environment")
            return "SKIPPED"
        
        test_url = "https://www.cloudflare.com"
        result = "UNKNOWN"
        
        self.print_debug(f"Testing {tool_name} connection to {test_url}")
        
        if tool_name == "node":
            if self.command_exists('node'):
                self.print_debug(f"Node.js found at: {shutil.which('node')}")
                self.print_debug(f"NODE_EXTRA_CA_CERTS: {os.environ.get('NODE_EXTRA_CA_CERTS', 'not set')}")
                
                node_script = f"""
const https = require('https');
https.get('{test_url}', {{headers: {{'User-Agent': 'Mozilla/5.0'}}}}, (res) => {{
    console.error('HTTP Status:', res.statusCode);
    console.error('SSL authorized:', res.socket.authorized);
    // Any HTTP response is OK - we're testing SSL
    process.exit(0);
}}).on('error', (err) => {{
    console.error('Error:', err.message);
    console.error('Error code:', err.code);
    // Exit with error for any TLS certificate issue
    const sslErrors = [
        'UNABLE_TO_GET_ISSUER_CERT',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'CERT_HAS_EXPIRED',
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'CERT_REJECTED',
        'CERT_NOT_YET_VALID',
        'ERR_TLS_CERT_ALTNAME_INVALID',
    ];
    process.exit(sslErrors.includes(err.code) ? 1 : 0);
}});
"""
                
                try:
                    proc_result = subprocess.run(
                        ['node', '-e', node_script],
                        capture_output=True, text=True, check=False
                    )
                    
                    if proc_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("Node.js test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug("Node.js test failed")
                    
                    if self.is_debug_mode() and proc_result.stderr:
                        self.print_debug(f"Node.js output: {proc_result.stderr}")
                except Exception as e:
                    self.print_debug(f"Node.js test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"
        
        elif tool_name == "python":
            self.print_info("Checking if Python trusts system proxy certificate...")
            
            try:
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.print_debug(f"Success - HTTP {response.code}")
                    result = "WORKING"
                    
                    self.print_debug(f"Python SSL default verify paths: {ssl.get_default_verify_paths()}")
                    self.print_debug("Python successfully trusts the system proxy certificate")
                    
            except urllib.error.HTTPError as e:
                self.print_debug(f"HTTP Error {e.code} - but SSL worked")
                # An HTTP error such as 403 is acceptable. This tests SSL.
                result = "WORKING"
            except urllib.error.URLError as e:
                self.print_debug(f"URL Error: {e.reason}")
                # An SSL error shows that the certificate is not trusted.
                result = "FAILED"
                
                if os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE'):
                    self.print_debug("Python needs environment variables set for certificate trust")
                else:
                    self.print_debug("Python does not trust the system certificate by default")
            except ssl.SSLError as e:
                self.print_debug(f"SSL Error: {e}")
                result = "FAILED"
            except Exception as e:
                self.print_debug(f"Unexpected error: {type(e).__name__}: {e}")
                result = "FAILED"
        
        elif tool_name == "curl":
            if self.command_exists('curl'):
                self.print_debug(f"curl found at: {shutil.which('curl')}")
                
                try:
                    # Check curl version for SecureTransport
                    version_result = subprocess.run(
                        ['curl', '--version'],
                        capture_output=True, text=True, check=False
                    )
                    self.print_debug(f"curl version: {version_result.stdout.splitlines()[0]}")
                    
                    if self.is_debug_mode():
                        curl_result = subprocess.run(
                            ['curl', '-v', '-s', '-o', '/dev/null', test_url],
                            capture_output=True, text=True, check=False
                        )
                    else:
                        curl_result = subprocess.run(
                            ['curl', '-s', '-o', '/dev/null', test_url],
                            capture_output=True, check=False
                        )
                    
                    if curl_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("curl test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"curl test failed with exit code: {curl_result.returncode}")
                    
                    if self.is_debug_mode() and curl_result.stderr:
                        for line in curl_result.stderr.splitlines():
                            if any(keyword in line for keyword in ['SSL', 'certificate', 'TLS']):
                                self.print_debug(f"curl: {line}")
                except Exception as e:
                    self.print_debug(f"curl test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"
        
        elif tool_name == "wget":
            if self.command_exists('wget'):
                self.print_debug(f"wget found at: {shutil.which('wget')}")
                self.print_debug(f"wget config: {os.path.expanduser('~/.wgetrc')}")
                
                try:
                    if self.is_debug_mode():
                        wget_result = subprocess.run(
                            ['wget', '--debug', '-O', '/dev/null', test_url],
                            capture_output=True, text=True, check=False
                        )
                    else:
                        wget_result = subprocess.run(
                            ['wget', '-q', '-O', '/dev/null', test_url],
                            capture_output=True, check=False
                        )
                    
                    if wget_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("wget test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"wget test failed with exit code: {wget_result.returncode}")
                    
                    if self.is_debug_mode() and wget_result.stderr:
                        for line in wget_result.stderr.splitlines():
                            if any(keyword in line for keyword in ['SSL', 'certificate', 'CA']):
                                self.print_debug(f"wget: {line}")
                except Exception as e:
                    self.print_debug(f"wget test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"

        elif tool_name == "aws":
            if self.command_exists('aws'):
                self.print_debug(f"aws found at: {shutil.which('aws')}")

                try:
                    # --no-sign-request makes an HTTPS call with no
                    # credentials. Without it, aws can stop before the network
                    # call and hide an SSL problem.
                    aws_result = subprocess.run(
                        ['aws', '--no-sign-request', 'sts', 'get-caller-identity'],
                        capture_output=True, text=True, timeout=15, check=False
                    )

                    stderr_lower = aws_result.stderr.lower()
                    if 'ssl' in stderr_lower or 'certificate' in stderr_lower:
                        result = "FAILED"
                        self.print_debug(f"AWS SSL error: {aws_result.stderr}")
                    else:
                        # Any response shows that TLS works.
                        result = "WORKING"
                        if aws_result.returncode == 0:
                            self.print_debug("AWS API call succeeded")
                        else:
                            self.print_debug("AWS API call returned error (but TLS works)")
                            self.print_debug(f"aws stderr: {aws_result.stderr.strip()[:100]}")
                except subprocess.TimeoutExpired:
                    self.print_debug("AWS test timed out")
                    result = "FAILED"
                except Exception as e:
                    self.print_debug(f"AWS test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"

        elif tool_name == "gcloud":
            if self.command_exists('gcloud'):
                self.print_debug(f"gcloud found at: {shutil.which('gcloud')}")

                try:
                    # 'gcloud projects list --limit=1' makes an HTTPS call to
                    # the GCP APIs. Only the SSL handshake must succeed.
                    gcloud_result = subprocess.run(
                        ['gcloud', 'projects', 'list', '--limit=1'],
                        capture_output=True, text=True, timeout=15, check=False
                    )

                    stderr_lower = gcloud_result.stderr.lower()
                    if 'ssl' in stderr_lower or 'certificate' in stderr_lower:
                        result = "FAILED"
                        self.print_debug(f"gcloud SSL error: {gcloud_result.stderr}")
                    else:
                        # Any response shows that TLS works.
                        result = "WORKING"
                        if gcloud_result.returncode == 0:
                            self.print_debug("gcloud API call succeeded")
                        else:
                            self.print_debug("gcloud API call returned error (but TLS works)")
                            self.print_debug(f"gcloud stderr: {gcloud_result.stderr.strip()[:100]}")
                except subprocess.TimeoutExpired:
                    self.print_debug("gcloud test timed out")
                    result = "FAILED"
                except Exception as e:
                    self.print_debug(f"gcloud test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"

        self.print_debug(f"Test result for {tool_name}: {result}")
        return result
    
    def check_aikido_adopt_status(self, temp_warp_cert):
        """Check whether Aikido has adopted the provider root."""
        has_issues = False
        if not any(e['key'] == 'aikido' for e in self.extra_roots):
            self.print_info("  - Aikido not active")
            return has_issues
        if platform.system() != 'Darwin':
            self.print_info("  - Aikido adoption is macOS-only")
            return has_issues
        doctor = self._find_aikido_doctor()
        if not doctor:
            self.print_info(
                "  - aikido-doctor not found in trusted system PATH "
                "(run with --debug to see whether a candidate was rejected)"
            )
            return has_issues
        if not self._aikido_doctor_supports_adopt(doctor):
            self.print_info("  - aikido-doctor predates certconfig adopt")
            return has_issues
        if self._aikido_built_bundles() is None:
            run_dir = SUPPLEMENTAL_ROOTS['aikido']['run_dir']
            self.print_warn(f"  ✗ Could not read Aikido's bundle directory {run_dir}")
            self.print_action("    Adoption cannot be verified until that is readable")
            return True
        if self._aikido_trusts_root(temp_warp_cert):
            self.print_info("  ✓ Provider root adopted into Aikido's CA bundles")
        else:
            self.print_warn("  ✗ Provider root not adopted by Aikido")
            self.print_action("    Run with --fix to adopt it via aikido-doctor")
            has_issues = True
        return has_issues

    def check_brew_cacerts_status(self, temp_warp_cert):
        """Check whether Homebrew's ca-certificates bundle contains the proxy CA."""
        has_issues = False
        if not self.command_exists('brew'):
            self.print_info("  - Homebrew not installed")
            return has_issues

        try:
            result = subprocess.run(
                ['brew', 'list', 'ca-certificates'],
                capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                self.print_info(
                    "  - ca-certificates formula not installed"
                )
                return has_issues
        except Exception:
            self.print_info(
                "  - Could not check ca-certificates formula"
            )
            return has_issues

        brew_prefix = self._get_brew_prefix()
        bundle_path = os.path.join(
            brew_prefix, 'etc', 'ca-certificates', 'cert.pem'
        )

        if not os.path.exists(bundle_path):
            self.print_warn(f"  ✗ Homebrew CA bundle not found at {bundle_path}")
            self.print_action(
                "    Run with --fix to regenerate "
                "(brew postinstall ca-certificates)"
            )
            has_issues = True
        elif self._status_roots_present(temp_warp_cert, bundle_path):
            self.print_info(
                "  ✓ Homebrew CA bundle contains proxy certificate"
            )
        else:
            self.print_warn(
                "  ✗ Homebrew CA bundle missing proxy certificate"
            )
            self.print_action(
                "    Run with --fix to regenerate "
                "(brew postinstall ca-certificates)"
            )
            has_issues = True

        return has_issues

    def check_node_status(self, temp_warp_cert):
        """Check Node.js configuration status."""
        has_issues = False
        if self.command_exists('node'):
            node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
            if node_extra_ca_certs:
                self.print_info(f"  NODE_EXTRA_CA_CERTS is set to: {node_extra_ca_certs}")
                other_provider = self._path_belongs_to_other_provider(node_extra_ca_certs)
                if other_provider:
                    self.print_warn(f"  ⚠ NODE_EXTRA_CA_CERTS points to a previous provider's path ({other_provider})")
                    self.print_action("    Run with --fix to migrate to the current provider's bundle")
                    has_issues = True
                elif os.path.exists(node_extra_ca_certs):
                    if self._status_roots_present(temp_warp_cert, node_extra_ca_certs):
                        self.print_info("  ✓ NODE_EXTRA_CA_CERTS contains current certificate")
                        verify_result = self.verify_connection("node")
                        if verify_result == "WORKING":
                            self.print_info("  ✓ Node.js can connect through proxy")
                        else:
                            self.print_warn("  ✗ Node.js connection test failed")
                            has_issues = True
                    else:
                        self.print_warn("  ✗ NODE_EXTRA_CA_CERTS file exists but doesn't contain current certificate")
                        self.print_action("    Run with --fix to append the certificate to this file")
                        has_issues = True
                else:
                    self.print_warn(f"  ✗ NODE_EXTRA_CA_CERTS points to non-existent file: {node_extra_ca_certs}")
                    has_issues = True
            else:
                self.print_warn("  ✗ NODE_EXTRA_CA_CERTS not configured")
                has_issues = True
            
            if self.command_exists('npm'):
                try:
                    result = subprocess.run(['npm', 'config', 'get', 'cafile'], capture_output=True, text=True, check=False)
                    npm_cafile = result.stdout.strip() if result.returncode == 0 else ""
                    
                    if npm_cafile and npm_cafile not in ["null", "undefined"]:
                        other_provider = self._path_belongs_to_other_provider(npm_cafile)
                        if other_provider:
                            self.print_warn(f"  ⚠ npm cafile points to a previous provider's path ({other_provider})")
                            self.print_action("    Run with --fix to migrate to the current provider's bundle")
                            has_issues = True
                        elif os.path.exists(npm_cafile):
                            if self._status_roots_present(temp_warp_cert, npm_cafile):
                                self.print_info("  ✓ npm cafile contains current certificate")
                                suspicious, reason = self.is_suspicious_full_bundle(npm_cafile, None)
                                if suspicious:
                                    self.print_warn(f"  ⚠ npm cafile looks suspiciously small ({reason})")
                                    self.print_action("    Run with --fix to repoint npm to a full CA bundle")
                                    has_issues = True
                            else:
                                self.print_warn("  ✗ npm cafile doesn't contain current certificate")
                                has_issues = True
                        else:
                            self.print_warn("  ✗ npm cafile points to non-existent file")
                            has_issues = True
                    else:
                        self.print_warn("  ✗ npm cafile not configured")
                        has_issues = True
                except Exception:
                    pass

            if self.command_exists('yarn'):
                try:
                    result = subprocess.run(['yarn', '--version'], capture_output=True, text=True, check=False)
                    yarn_version = result.stdout.strip()
                    is_berry = yarn_version and yarn_version[0] in ('2', '3', '4')
                    config_key = 'httpsCaFilePath' if is_berry else 'cafile'

                    result = subprocess.run(['yarn', 'config', 'get', config_key],
                                           capture_output=True, text=True, check=False)
                    yarn_cafile = result.stdout.strip()

                    if yarn_cafile and yarn_cafile not in ['undefined', '']:
                        other_provider = self._path_belongs_to_other_provider(yarn_cafile)
                        npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
                        if other_provider:
                            self.print_warn(f"  ⚠ yarn {config_key} points to a previous provider's path ({other_provider})")
                            self.print_action("    Run with --fix to remove this stale configuration")
                            has_issues = True
                        elif yarn_cafile == npm_bundle:
                            self.print_info(f"  ✓ yarn {config_key} points to managed npm bundle")
                        elif os.path.exists(yarn_cafile):
                            if self._status_roots_present(temp_warp_cert, yarn_cafile):
                                self.print_info(f"  ✓ yarn {config_key} contains current certificate")
                            else:
                                self.print_warn(f"  ⚠ yarn {config_key} doesn't contain proxy certificate: {yarn_cafile}")
                                self.print_action("    Run with --fix to remove this stale configuration")
                                has_issues = True
                        else:
                            self.print_warn(f"  ⚠ yarn {config_key} points to non-existent file: {yarn_cafile}")
                            self.print_action("    Run with --fix to remove this stale configuration")
                            has_issues = True
                    else:
                        self.print_info("  ✓ yarn using NODE_EXTRA_CA_CERTS (no explicit cafile)")
                except Exception:
                    pass

            if self.command_exists('pnpm'):
                try:
                    result = subprocess.run(['pnpm', 'config', 'get', 'cafile'],
                                           capture_output=True, text=True, check=False)
                    pnpm_cafile = result.stdout.strip()

                    if pnpm_cafile and pnpm_cafile not in ['undefined', '']:
                        other_provider = self._path_belongs_to_other_provider(pnpm_cafile)
                        npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
                        if other_provider:
                            self.print_warn(f"  ⚠ pnpm cafile points to a previous provider's path ({other_provider})")
                            self.print_action("    Run with --fix to remove this stale configuration")
                            has_issues = True
                        elif pnpm_cafile == npm_bundle:
                            self.print_info("  ✓ pnpm cafile points to managed npm bundle")
                        elif os.path.exists(pnpm_cafile):
                            if self._status_roots_present(temp_warp_cert, pnpm_cafile):
                                self.print_info("  ✓ pnpm cafile contains current certificate")
                            else:
                                self.print_warn(f"  ⚠ pnpm cafile doesn't contain proxy certificate: {pnpm_cafile}")
                                self.print_action("    Run with --fix to remove this stale configuration")
                                has_issues = True
                        else:
                            self.print_warn(f"  ⚠ pnpm cafile points to non-existent file: {pnpm_cafile}")
                            self.print_action("    Run with --fix to remove this stale configuration")
                            has_issues = True
                    else:
                        self.print_info("  ✓ pnpm using NODE_EXTRA_CA_CERTS (no explicit cafile)")
                except Exception:
                    pass
        else:
            self.print_info("  - Node.js not installed")
        return has_issues

    def check_python_status(self, temp_warp_cert):
        """Check Python configuration status."""
        has_issues = False
        if self.command_exists('python3') or self.command_exists('python'):
            python_verify_result = self.verify_connection("python")
            
            if python_verify_result == "WORKING":
                self.print_info("  ✓ Python trusts the system proxy certificate")
                self.print_info("  ✓ Python can connect through proxy without additional configuration")
                # verify_connection() uses the default trust of Python, which
                # reads REQUESTS_CA_BUNDLE. A rustls client such as uv reads
                # SSL_CERT_FILE. A managed SSL_CERT_FILE without a necessary
                # root leaves uv broken while Python works. Report it.
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if (ssl_cert_file and os.path.exists(ssl_cert_file)
                        and not self._status_roots_present(temp_warp_cert, ssl_cert_file)):
                    self.print_warn(
                        f"  ✗ SSL_CERT_FILE ({ssl_cert_file}) is missing a required root"
                    )
                    self.print_action(
                        "    Run with --fix to add all roots (needed by uv/rustls clients)"
                    )
                    has_issues = True
            else:
                python_configured = False
                
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if requests_ca_bundle:
                    self.print_info(f"  REQUESTS_CA_BUNDLE is set to: {requests_ca_bundle}")
                    if os.path.exists(requests_ca_bundle):
                        if self._status_roots_present(temp_warp_cert, requests_ca_bundle):
                            self.print_info("  ✓ REQUESTS_CA_BUNDLE contains current certificate")
                            suspicious, reason = self.is_suspicious_full_bundle(requests_ca_bundle, None)
                            if suspicious:
                                self.print_warn(f"  ⚠ REQUESTS_CA_BUNDLE looks suspiciously small ({reason})")
                                self.print_action("    Run with --fix to repoint to a full CA bundle")
                                has_issues = True
                            python_configured = True
                        else:
                            self.print_warn("  ✗ REQUESTS_CA_BUNDLE file exists but doesn't contain current certificate")
                            self.print_action("    Run with --fix to create a new bundle with both certificates")
                    else:
                        self.print_warn(f"  ✗ REQUESTS_CA_BUNDLE points to non-existent file: {requests_ca_bundle}")

                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if ssl_cert_file:
                    self.print_info(f"  SSL_CERT_FILE is set to: {ssl_cert_file}")
                    if (os.path.exists(ssl_cert_file)
                            and self._status_roots_present(temp_warp_cert, ssl_cert_file)):
                        self.print_info("  ✓ SSL_CERT_FILE contains current certificate")
                        suspicious, reason = self.is_suspicious_full_bundle(ssl_cert_file, None)
                        if suspicious:
                            self.print_warn(f"  ⚠ SSL_CERT_FILE looks suspiciously small ({reason})")
                            self.print_action("    Run with --fix to repoint to a full CA bundle")
                            has_issues = True
                        python_configured = True
                
                if not python_configured:
                    if not requests_ca_bundle and not ssl_cert_file:
                        self.print_warn("  ✗ Python does not trust system certificate by default")
                        self.print_warn("  ✗ No Python certificate environment variables configured")
                        has_issues = True
                    else:
                        has_issues = True
        else:
            self.print_info("  - Python not installed")
        return has_issues

    def check_gcloud_status(self, temp_warp_cert):
        """Check gcloud configuration status."""
        has_issues = False
        if self.command_exists('gcloud'):
            verify_result = self.verify_connection("gcloud")

            if verify_result == "WORKING":
                self.print_info("  ✓ gcloud can connect through proxy")

                # The IAP tunnel WebSocket path needs
                # core/custom_ca_certs_file, also when HTTPS already works.
                # Thus a missing or old value is an issue.
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True, check=False
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        self.print_info(f"  - Custom CA configured at: {gcloud_ca}")
                        if self._status_roots_present(temp_warp_cert, gcloud_ca):
                            self.print_info("  ✓ Custom CA contains current certificate")
                        else:
                            self.print_warn("  ✗ gcloud CA file doesn't contain current certificate")
                            self.print_action("    Run with --fix to update the CA configuration (required for IAP tunneling)")
                            has_issues = True
                    else:
                        self.print_warn("  ✗ core/custom_ca_certs_file is not set")
                        self.print_action("    Run with --fix to configure (required for `gcloud compute ssh --tunnel-through-iap`)")
                        has_issues = True
                except Exception:
                    self.print_warn("  ✗ Failed to check gcloud configuration")
                    has_issues = True
            elif verify_result == "SKIPPED":
                # Verification is not possible. Examine the configuration.
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True, check=False
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        if self._status_roots_present(temp_warp_cert, gcloud_ca):
                            self.print_info("  ✓ gcloud configured with current certificate")
                            suspicious, reason = self.is_suspicious_full_bundle(gcloud_ca, None)
                            if suspicious:
                                self.print_warn(f"  ⚠ gcloud custom CA file looks suspiciously small ({reason})")
                                self.print_action("    Run with --fix to repoint to a full CA bundle")
                                has_issues = True
                        else:
                            self.print_warn("  ✗ gcloud CA file doesn't contain current certificate")
                            has_issues = True
                    else:
                        self.print_info("  - gcloud custom CA not configured (verification skipped)")
                except Exception:
                    self.print_warn("  ✗ Failed to check gcloud configuration")
                    has_issues = True
            else:
                self.print_warn("  ✗ gcloud connection test failed")
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True, check=False
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        if self._status_roots_present(temp_warp_cert, gcloud_ca):
                            self.print_warn("  - Custom CA is configured with WARP cert but connection still fails")
                            self.print_action("    Check gcloud and Python configuration")
                        else:
                            self.print_warn("  ✗ gcloud CA file doesn't contain current certificate")
                            self.print_action("    Run with --fix to update the CA configuration")
                    else:
                        self.print_warn("  ✗ gcloud not configured with custom CA")
                        self.print_action("    Run with --fix to configure gcloud CA")
                    has_issues = True
                except Exception:
                    self.print_warn("  ✗ Failed to check gcloud configuration")
                    has_issues = True
        else:
            self.print_info("  - gcloud not installed (would configure if present)")
        return has_issues

    def check_java_status(self, temp_warp_cert):
        """Check Java configuration status for all installations."""
        has_issues = False

        if not self.command_exists('java') and not self.command_exists('keytool'):
            self.print_info("  - Java not installed (would configure if present)")
            return has_issues

        java_homes = self.find_all_java_homes()

        if not java_homes:
            self.print_warn("  ✗ No Java installations found")
            return True

        if len(java_homes) > 1:
            self.print_info(f"  Checking {len(java_homes)} Java installation(s):")

        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"  ✗ {version_name}: cacerts file not found")
                has_issues = True
                continue

            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True, check=False
                )
                if result.returncode == 0:
                    self.print_info(f"  ✓ {version_name}: Certificate installed")
                else:
                    self.print_warn(f"  ✗ {version_name}: Certificate missing")
                    has_issues = True
            except Exception:
                self.print_warn(f"  ✗ {version_name}: Could not check certificate status")
                has_issues = True

        return has_issues

    def check_jenv_status(self, temp_warp_cert):
        """Check jenv-managed Java installations status."""
        has_issues = False
        java_homes = self.get_jenv_java_homes()

        if not java_homes:
            return has_issues

        if not self.command_exists('keytool'):
            self.print_warn("  ✗ keytool not found, cannot check jenv Java installations")
            return True

        self.print_info(f"  Checking {len(java_homes)} jenv-managed Java installation(s):")

        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"    ✗ {version_name}: cacerts file not found")
                has_issues = True
                continue

            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True, check=False
                )
                if result.returncode == 0 and self.provider['keytool_alias'] in result.stdout.decode():
                    self.print_info(f"    ✓ {version_name}: Certificate installed")
                else:
                    self.print_warn(f"    ✗ {version_name}: Certificate missing")
                    has_issues = True
            except Exception:
                self.print_warn(f"    ✗ {version_name}: Failed to check keystore")
                has_issues = True

        return has_issues

    def check_gradle_status(self, temp_warp_cert):
        """Check Gradle configuration status."""
        has_issues = False
        gradle_props = self.get_gradle_properties_path()
        if self.command_exists('gradle') or os.path.exists(gradle_props):
            parsed = self._property_lines_with_vendor_scope(gradle_props)
            if parsed is None:
                self.print_warn(
                    f"  ✗ Could not read Gradle properties at {gradle_props}"
                )
                return True
            if self._aikido_active:
                pinned_java_home = self._gradle_pinned_java_home(parsed)
                managed = self._gradle_fumitm_truststore_properties()
                truststore_override = {
                    'systemProp.javax.net.ssl.trustStore':
                        managed['systemProp.javax.net.ssl.trustStore']
                }
                if self._properties_have_values_outside_vendor_blocks(
                    parsed, truststore_override
                ):
                    self.print_warn(
                        "  ✗ fumitm Gradle truststore override hides Aikido/JDK trust"
                    )
                    self.print_action("    Run with --fix to remove the override")
                    return True
                cacerts = self._gradle_java_cacerts(gradle_props, parsed=parsed)
                if not cacerts:
                    if pinned_java_home:
                        self.print_warn(
                            "  ✗ org.gradle.java.home has no Java cacerts file: "
                            f"{pinned_java_home}"
                        )
                        return True
                    self.print_warn("  ✗ Could not find Java cacerts for Gradle")
                    return True
                if not self._keystore_has_expected_roots(
                    'keytool', cacerts, primary_cert_path=temp_warp_cert
                ):
                    self.print_warn(
                        "  ✗ Gradle's JDK is missing one or more proxy roots"
                    )
                    self.print_action("    Run with --fix to prepare Java trust")
                    return True
                self.print_info("  ✓ Gradle uses Aikido/JDK trust configuration")
                return False
            if os.path.exists(gradle_props):
                current_props = {
                    key: value
                    for _, _, key, value in parsed
                    if key is not None
                }
                gradle_cacerts = self.get_gradle_custom_cacerts_path()
                expected = {
                    'systemProp.javax.net.ssl.trustStore': gradle_cacerts,
                    'systemProp.javax.net.ssl.trustStorePassword': 'changeit',
                    'systemProp.javax.net.ssl.trustStoreType': 'PKCS12',
                    'systemProp.https.protocols': 'TLSv1.2'
                }

                for key, value in expected.items():
                    current = current_props.get(key, '')
                    if current == value and current:
                        self.print_info(f"  ✓ {key} set correctly in Gradle properties")
                    else:
                        self.print_warn(f"  ✗ {key} not set correctly in Gradle properties")
                        has_issues = True
                if self._gradle_custom_truststore_has_roots(gradle_cacerts):
                    self.print_info("  ✓ Gradle custom truststore contains current proxy root(s)")
                else:
                    self.print_warn("  ✗ Gradle custom truststore is missing current proxy root(s)")
                    has_issues = True
            else:
                self.print_warn("  ✗ Gradle properties file not found")
                has_issues = True
        else:
            self.print_info("  - Gradle not installed (would configure if present)")
        return has_issues

    def check_dbeaver_status(self, temp_warp_cert):
        """Check DBeaver configuration status."""
        has_issues = False
        dbeaver_app = "/Applications/DBeaver.app"
        if os.path.exists(dbeaver_app):
            dbeaver_keytool = f"{dbeaver_app}/Contents/Eclipse/jre/Contents/Home/bin/keytool"
            dbeaver_cacerts = f"{dbeaver_app}/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
            if os.path.exists(dbeaver_keytool) and os.path.exists(dbeaver_cacerts):
                try:
                    result = subprocess.run(
                        [dbeaver_keytool, '-list', '-alias', self.provider['keytool_alias'],
                         '-keystore', dbeaver_cacerts, '-storepass', 'changeit'],
                        capture_output=True, check=False
                    )
                    if result.returncode == 0 and self.provider['keytool_alias'] in result.stdout.decode():
                        self.print_info("  ✓ DBeaver keystore contains proxy certificate")
                    else:
                        self.print_warn("  ✗ DBeaver keystore missing proxy certificate")
                        has_issues = True
                except Exception:
                    self.print_warn("  ✗ Failed to check DBeaver keystore")
                    has_issues = True
            else:
                self.print_warn("  ✗ DBeaver JRE not found at expected location")
        else:
            self.print_info("  - DBeaver not installed at /Applications/DBeaver.app")
        return has_issues

    def check_wget_status(self, temp_warp_cert):
        """Check wget configuration status."""
        has_issues = False
        if self.command_exists('wget'):
            verify_result = self.verify_connection("wget")

            wgetrc_path = os.path.expanduser("~/.wgetrc")
            configured_ca = None
            if os.path.exists(wgetrc_path):
                with open(wgetrc_path, 'r') as f:
                    configured_ca = self._last_active_wgetrc_ca(f.read())
            has_all_roots = bool(
                configured_ca and os.path.exists(configured_ca)
                and self._status_roots_present(temp_warp_cert, configured_ca)
            )

            if verify_result == "WORKING":
                self.print_info("  ✓ wget can connect through proxy")
                if has_all_roots:
                    self.print_info("  ✓ wget configured with proxy certificate")
                else:
                    self.print_info("  - Using system certificate trust (no custom CA needed)")
            else:
                if has_all_roots:
                    self.print_warn("  ✗ wget configured but connection test failed")
                else:
                    self.print_warn("  ✗ wget not configured with proxy certificate")
                has_issues = True
        else:
            self.print_info("  - wget not installed")
        return has_issues

    def check_podman_status(self, temp_warp_cert):
        """Report the status of the Podman configuration.

        Examines the permanent ~/.docker/certs.d/ location and the VM.
        """
        has_issues = False
        if self.command_exists('podman'):
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self._status_container_certs_present(temp_warp_cert, docker_certs_dir):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            try:
                result = subprocess.run(['podman', 'machine', 'list'], capture_output=True, text=True, check=False)
                if 'Currently running' in result.stdout:
                    result = subprocess.run(
                        ['podman', 'machine', 'ssh', f'test -f /etc/pki/ca-trust/source/anchors/{self.provider["container_cert_name"]}.pem'],
                        capture_output=True, check=False
                    )
                    if result.returncode == 0:
                        self.print_info("  ✓ Certificate installed in running VM")
                    else:
                        self.print_info("  - Certificate not in VM (run fumitm --fix to install)")
                else:
                    self.print_info("  - Podman machine is stopped (certificate will be available on start)")
            except Exception:
                self.print_info("  - Could not check Podman VM status")
        else:
            self.print_info("  - Podman not installed")
        return has_issues

    def check_rancher_status(self, temp_warp_cert):
        """Report the status of the Rancher Desktop configuration.

        Examines the permanent ~/.docker/certs.d/ location and the VM.
        """
        has_issues = False
        if self.command_exists('rdctl'):
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self._status_container_certs_present(temp_warp_cert, docker_certs_dir):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            try:
                version_result = subprocess.run(['rdctl', 'version'], capture_output=True, text=True, check=False)
                if version_result.returncode == 0:
                    if self._check_cert_in_rancher_vm():
                        self.print_info("  ✓ Certificate installed in running VM")
                    else:
                        self.print_info("  - Certificate not in VM (run fumitm --fix to install)")
                else:
                    self.print_info("  - Rancher Desktop is stopped (certificate will be available on start)")
            except Exception:
                self.print_info("  - Could not check Rancher Desktop VM status")
        else:
            self.print_info("  - Rancher Desktop not installed")
        return has_issues

    def check_docker_status(self, temp_warp_cert):
        """Report the status of the Docker configuration with any backend.

        Examines the permanent ~/.docker/certs.d/ location. When Docker operates,
        it also examines the VM CA store through the active backend.
        """
        has_issues = False
        if self.command_exists('docker'):
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(
                docker_certs_dir,
                f"{self.provider['container_cert_name']}.crt"
            )

            if os.path.exists(cert_path):
                if self._status_container_certs_present(temp_warp_cert, docker_certs_dir):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            if self._docker_is_running():
                colima_profile = self._active_colima_profile_for_docker()
                if colima_profile:
                    vm_has_cert = self._check_cert_in_colima_vm(colima_profile)
                else:
                    vm_has_cert = self._check_cert_in_docker_vm()
                if vm_has_cert:
                    self.print_info("  ✓ Certificate installed in Docker VM")
                else:
                    self.print_info("  - Certificate not in VM (run fumitm --fix to install)")
                    has_issues = True
            else:
                self.print_info("  - Docker is not running")
        else:
            self.print_info("  - Docker not installed")
        return has_issues

    def check_android_status(self, temp_warp_cert):
        """Check Android Emulator configuration status."""
        has_issues = False
        if self.command_exists('adb') and self.command_exists('emulator'):
            try:
                result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, check=False)
                running_emulators = sum(1 for line in result.stdout.splitlines() if 'emulator-' in line)
                if running_emulators > 0:
                    self.print_info("  - Android emulator detected (manual installation available)")
                    self.print_info("    Run with --fix to see installation instructions")
                else:
                    self.print_info("  - Android SDK detected but no emulator running")
            except Exception:
                self.print_info("  - Android SDK detected")
        else:
            self.print_info("  - Android SDK not installed (would help configure if present)")
        return has_issues

    def check_colima_status(self, temp_warp_cert):
        """Report the status of the Colima configuration.

        Examines the permanent ~/.docker/certs.d/ location and the VM.
        """
        has_issues = False
        if self.command_exists('colima'):
            profile = self._colima_profile_for_tool()
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self._status_container_certs_present(temp_warp_cert, docker_certs_dir):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            try:
                status_result = subprocess.run(
                    self._colima_cmd(profile, 'status'),
                    capture_output=True, timeout=10, check=False
                )
                if status_result.returncode == 0:
                    if self._check_cert_in_colima_vm(profile):
                        self.print_info("  ✓ Certificate installed in running VM")
                    else:
                        self.print_info("  - Certificate not in VM (will be applied on restart)")
                else:
                    self.print_info("  - Colima is stopped (certificate will be loaded on start)")
            except Exception:
                self.print_info("  - Could not check Colima VM status")
        else:
            self.print_info("  - Colima not installed")
        return has_issues

    def _get_status_cert(self):
        """Get the current provider certificate for a status comparison.

        Returns:
            str or None: The path of a temporary file with the certificate, or None
            on a failure.
        """
        provider_name = self.provider['name']

        if self.provider is PROVIDERS['warp']:
            if not self.command_exists('warp-cli'):
                self.print_error(f"warp-cli command not found. Please ensure {provider_name} is installed.")
                return None
            try:
                result = subprocess.run(
                    ['warp-cli', 'certs', '--no-paginate'],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                        tf.write(result.stdout.strip())
                        return tf.name
                self.print_error(f"Failed to retrieve {provider_name} certificate")
                return None
            except Exception as e:
                self.print_error(f"Error retrieving {provider_name} certificate: {e}")
                return None

        elif self.provider is PROVIDERS['netskope']:
            # For Netskope, read the cert from the stored cert_path or known source
            cert_content = None
            if os.path.exists(self.cert_path):
                with open(self.cert_path, 'r') as f:
                    cert_content = f.read().strip()
            else:
                cert_content = self._get_netskope_cert()

            if cert_content:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                    tf.write(cert_content)
                    return tf.name
            self.print_error(f"Could not find {provider_name} certificate for status check")
            return None

        self.print_error(f"No status cert retrieval for provider {provider_name}")
        return None

    def _check_provider_connection(self):
        """Find if the MITM proxy operates.

        Returns:
            bool: True if fumitm found a problem.
        """
        provider_name = self.provider['name']
        short = self.provider['short_name']

        if self.provider is PROVIDERS['warp']:
            self.print_status(f"{provider_name} Connection:")
            if self.command_exists('warp-cli'):
                try:
                    result = subprocess.run(['warp-cli', 'status'], capture_output=True, text=True, check=False)
                    warp_status = result.stdout if result.returncode == 0 else "unknown"
                    if "Connected" in warp_status:
                        self.print_info(f"  ✓ {short} is connected")
                        return False
                    else:
                        self.print_warn(f"  ✗ {short} is not connected")
                        self.print_action("  Run: warp-cli connect")
                        return True
                except Exception:
                    self.print_error(f"  ✗ Failed to check {short} status")
                    return True
            else:
                self.print_error("  ✗ warp-cli not found")
                self.print_action(f"  Install {provider_name} client")
                return True

        elif self.provider is PROVIDERS['netskope']:
            self.print_status(f"{provider_name} Connection:")
            plat = platform.system()
            proc_pattern = 'Netskope Client' if plat == 'Darwin' else 'STAgent'
            proc_label = 'Netskope Client' if plat == 'Darwin' else 'STAgent'
            try:
                result = subprocess.run(
                    ['pgrep', '-f', proc_pattern],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    self.print_info(f"  ✓ {proc_label} is running")
                    return False
                else:
                    self.print_warn(f"  ✗ {proc_label} is not running")
                    return True
            except Exception:
                # Fallback: check if cert source file exists
                cert_sources = self.provider.get('cert_sources', {}).get(plat, [])
                if any(os.path.exists(p) for p in cert_sources):
                    self.print_info(f"  ✓ {short} certificate file found")
                    return False
                self.print_warn(f"  ✗ Could not verify {short} status")
                return True

        return False

    def check_all_status(self):
        """Check status of all configurations."""
        has_issues = False
        temp_warp_cert = None
        provider_name = self.provider['name']
        short = self.provider['short_name']

        self.print_info(f"Checking {provider_name} Certificate Status")
        self.print_info("=" * (len(f"Checking {provider_name} Certificate Status")))
        print()

        temp_warp_cert = self._get_status_cert()
        if not temp_warp_cert:
            return False

        self.print_debug(f"Retrieved {short} certificate for comparison")
        self.cert_fingerprint = self.get_cert_fingerprint(temp_warp_cert)
        self.print_debug(f"{short} certificate fingerprint: {self.cert_fingerprint}")

        # Materialize the supplemental roots, thus each status check can look
        # for them in the managed bundles.
        self._prepare_extra_roots()
        self._announce_extra_roots()

        if self._check_provider_connection():
            has_issues = True
        print()
        
        self.print_status("Certificate Status:")
        
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-checkend', '86400', '-in', temp_warp_cert],
                capture_output=True, check=False
            )
            if result.returncode == 0:
                self.print_info(f"  ✓ {short} certificate is valid")
                
                cert_locations = []
                cert_found = False
                
                if os.path.exists(self.cert_path):
                    with open(self.cert_path, 'r') as f:
                        existing_cert = f.read()
                    with open(temp_warp_cert, 'r') as f:
                        warp_cert_content = f.read()
                    if existing_cert == warp_cert_content:
                        cert_locations.append(f"    - {self.cert_path}")
                        cert_found = True
                
                node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
                if (node_extra_ca_certs and os.path.exists(node_extra_ca_certs)
                        and self.certificate_exists_in_file(temp_warp_cert, node_extra_ca_certs)):
                    cert_locations.append(f"    - {node_extra_ca_certs} (NODE_EXTRA_CA_CERTS)")
                    cert_found = True
                
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if (requests_ca_bundle and os.path.exists(requests_ca_bundle)
                        and self.certificate_exists_in_file(temp_warp_cert, requests_ca_bundle)):
                    cert_locations.append(f"    - {requests_ca_bundle} (REQUESTS_CA_BUNDLE)")
                    cert_found = True
                
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if (ssl_cert_file and os.path.exists(ssl_cert_file)
                        and self.certificate_exists_in_file(temp_warp_cert, ssl_cert_file)):
                    cert_locations.append(f"    - {ssl_cert_file} (SSL_CERT_FILE)")
                    cert_found = True
                
                if cert_found:
                    self.print_info(f"  ✓ {short} certificate found in:")
                    for loc in cert_locations:
                        print(loc)
                else:
                    self.print_warn(f"  ✗ {short} certificate not found in any configured location")
                    self.print_action("    Run with --fix to install the certificate")
                    has_issues = True
            else:
                self.print_warn(f"  ✗ {short} certificate is expired or expiring soon")
                has_issues = True
        except Exception:
            self.print_error("  ✗ Failed to check certificate validity")
            has_issues = True
        print()
        
        if self.selected_tools:
            selected_tools_info = self.get_selected_tools_info()
            self.print_info(f"Selected tools: {', '.join(selected_tools_info)}")
            print()
        
        for tool_key, tool_info in self.tools_registry.items():
            if not self.should_process_tool(tool_key):
                continue
            
            self.print_status(f"{tool_info['name']} Configuration:")
            if tool_info.get('check_func'):
                tool_has_issues = tool_info['check_func'](temp_warp_cert)
                if tool_has_issues:
                    has_issues = True
            print()
        # Check Docker/Container certificate location if not filtering
        if not self.selected_tools:
            self.print_status("Docker/Container Configuration:")
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")
            if os.path.exists(cert_path):
                if self._status_container_certs_present(temp_warp_cert, docker_certs_dir):
                    self.print_info(f"  ✓ Certificate installed in {docker_certs_dir}")
                    self.print_info("    (Used by: Docker, OrbStack, Colima, Podman, Rancher Desktop, Lima)")
                    self._print_docker_build_hint()
                else:
                    self.print_warn(f"  ✗ Certificate in {docker_certs_dir} is outdated")
            else:
                # Only warn if container tools are detected
                has_container_tools = (self.command_exists('docker') or
                                       self.command_exists('orb') or
                                       self.command_exists('colima') or
                                       self.command_exists('podman') or
                                       self.command_exists('rdctl'))
                if has_container_tools:
                    self.print_warn(f"  ✗ Certificate not in {docker_certs_dir}")
                    self.print_action("    Run with --fix to install for container tools")
                else:
                    self.print_info("  - No container runtimes detected")
            print()
        if not self.selected_tools:
            self.print_status("Additional Tools (not yet automated):")
            self.print_info("  - RubyGems/Bundler: May work with SSL_CERT_FILE environment variable")
            self.print_info("  - PHP/Composer: May need CURL_CA_BUNDLE and php.ini configuration")
            self.print_info("  - Firefox: Uses its own certificate store in profile")
            self.print_info("  - Other Homebrew tools: May need individual configuration")
            print()
        
        # Summary
        self.print_info("Summary:")
        self.print_info("========")
        if has_issues:
            self.print_warn("Some configurations need attention.")
            self.print_action("Run './fumitm.py --fix' to fix the issues")
        else:
            self.print_info(f"✓ All configured tools are properly set up for {provider_name}")
        print()
        
        if temp_warp_cert:
            os.unlink(temp_warp_cert)
    
    def _run_setup(self, tool_key, func):
        """Run a setup function and find its result.

        fumitm counts the errors: print_error() increments _setup_error_count during
        the run. Thus fumitm finds a failure and the signature of the setup function
        does not change.

        The accuracy of the status before each function returns a ToolResult:
        - 'failed' is reliable. print_error ran, or an exception occurred.
        - 'completed' means "ran with no error". The change is unknown.
        - 'configured' and 'already_ok' need an explicit ToolResult.
        """
        self._in_setup_context = True
        self._setup_error_count = 0
        self._current_tool_key = tool_key
        try:
            ret = func()
            if isinstance(ret, ToolResult):
                return ret
            if self._setup_error_count > 0:
                return ToolResult(tool_key, 'failed', 'Errors during setup')
            return ToolResult(tool_key, 'completed', 'Ran without errors')
        except NonInteractiveError:
            raise
        except Exception as e:
            self.print_error(f"{tool_key}: {e}")
            return ToolResult(tool_key, 'failed', str(e))
        finally:
            self._in_setup_context = False
            self._setup_error_count = 0
            self._current_tool_key = None

    @staticmethod
    def _compute_changes_made(results):
        """Find changes_made from a list of ToolResult values.

        Returns True if a tool gave 'configured'. Returns False if each tool gave
        'already_ok' or 'skipped', or if the list is empty. Returns None if only the
        old 'completed' status is present, because the change is then unknown.
        """
        if not results:
            return False
        if any(getattr(r, 'changed', None) is True for r in results):
            return True
        if all(r.status == 'skipped' for r in results):
            return False
        has_configured = any(r.status == 'configured' for r in results)
        has_already_ok = any(r.status == 'already_ok' for r in results)
        if has_configured:
            return True
        if any(getattr(r, 'changed', None) is False for r in results) and not any(
            r.status == 'completed' for r in results
        ):
            return False
        if has_already_ok and not any(r.status == 'completed' for r in results):
            return False
        return None

    def _print_summary(self, results):
        """Print human-readable and machine-parseable summary after install."""
        counts = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        partial = sum(
            1 for r in results
            if r.status == 'failed' and getattr(r, 'changed', None) is True
        )
        configured = counts.get('configured', 0)
        completed = counts.get('completed', 0)
        already_ok = counts.get('already_ok', 0)
        skipped = counts.get('skipped', 0)
        failed = counts.get('failed', 0) - partial

        parts = []
        if configured:
            parts.append(f"{configured} configured")
        if completed:
            parts.append(f"{completed} completed")
        if already_ok:
            parts.append(f"{already_ok} already OK")
        if skipped:
            parts.append(f"{skipped} skipped")
        if partial:
            parts.append(f"{partial} partially configured")
        if failed:
            parts.append(f"{failed} failed")
        summary_text = ', '.join(parts) if parts else 'no tools processed'

        self.print_info(f"Summary: {summary_text}")

        changes_made = self._compute_changes_made(results)
        succeeded = configured + already_ok + completed + partial
        problems = failed + partial
        if problems > 0 and succeeded == 0:
            exit_code = 1
        elif problems > 0:
            exit_code = 3
        else:
            exit_code = 0

        result_obj = {
            'changes_made': changes_made,
            'configured': configured,
            'completed': completed,
            'already_ok': already_ok,
            'skipped': skipped,
            'partial': partial,
            'failed': failed,
            'exit_code': exit_code,
            'shell_reload_required': self.shell_modified,
            'shell_reload_command': (
                self._shell_reload_command() if self.shell_modified else None
            ),
            'shell_env_file': self._shell_env_file(),
        }
        # Stable machine-parseable line for Ansible changed_when
        print(f"FUMITM_RESULT: {json.dumps(result_obj)}")

        # JSON-lines summary event
        if self._json_log_file_handle:
            event = {
                'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'level': 'info',
                'phase': 'summary',
                'tool': None,
                'action': None,
                'result': 'partial' if failed > 0 else 'ok',
                'message': summary_text,
                'error_code': None,
            }
            self._json_log_file_handle.write(json.dumps(event) + '\n')
            self._json_log_file_handle.flush()

        return exit_code

    def _shell_reload_command(self):
        """Return the command that activates the exports in the current shell.

        A POSIX shell sources the small env file and never a full rc file. A second
        run of .zshrc or .bashrc repeats agents, hooks, aliases, and PATH changes
        that are not idempotent. Returns None for a shell with no safe command. This
        includes fish, which cannot source the POSIX env file and whose config.fish
        would repeat the same startup work. A fish user must start a new session
        until a fish env file is available.
        """
        shell_type = self.detect_shell()
        if self._uses_env_file(shell_type):
            return f'. {self._FUMITM_ENV_FILE_SHELL}'
        return None

    def _shell_env_file(self):
        """Return the absolute path of the env file, or None if it is absent.

        fumitm reports this path in FUMITM_RESULT for an automation wrapper. A root
        Jamf process with --run-as-user writes the env file of the target user, but
        shell_reload_command is relative to HOME and would resolve against the HOME
        of the wrapper (/var/root). This path is absolute and resolves against the
        corrected home directory of the target user.

        This value is independent of shell_modified. On a converged run nothing on
        disk changes, but a new wrapper process did not inherit the environment and
        still needs this path for its children.

        Trust boundary: the target user owns the file and can write it. fumitm
        corrects the ownership after each write. Thus a privileged wrapper must
        never source it, because that runs user-controlled shell code as root. The
        wrapper must drop privileges and let the child source the file as the target
        user, for example with sudo -u. fumitm reports only the path and never the
        content of the file.
        """
        if not self._uses_env_file(self.detect_shell()):
            return None
        path = self._env_file_path()
        return path if os.path.exists(path) else None

    def _print_shell_reload_notice(self):
        """Give the final instruction to activate the exports in this shell.

        A child process cannot change the environment of its parent shell. Thus
        after a --fix the terminal keeps the old variables until the user sources
        the env file. The command in the README does this also. fumitm writes this
        notice last, thus later output does not hide it. In headless mode fumitm
        does not write it: a root Jamf policy log has no interactive shell.
        Automation reads the shell_reload_* fields in FUMITM_RESULT.
        """
        if not self.shell_modified or self.headless:
            return
        command = self._shell_reload_command()
        print()
        self.print_warn("=" * 60)
        self.print_warn("CURRENT SHELL NOT YET UPDATED")
        self.print_warn("=" * 60)
        self.print_warn("Environment changes only apply to new shells.")
        self.print_warn("To activate them in THIS terminal, run:")
        print()
        if command:
            self.print_info(f"  {command}")
        else:
            self.print_info("  exec $SHELL -l  (restarts your shell)")
        print()
        self.print_info("Or simply open a new terminal window.")

    def main(self):
        """Main entry point for the FumitmPython instance."""
        self._open_log_files()
        try:
            return self._main_inner()
        finally:
            self._cleanup_extra_root_temp_files()
            self._close_log_files()

    def _main_inner(self):
        """Core logic, separated so main() can wrap it in log-file cleanup."""
        try:
            header = f"{self.provider['name']} Certificate Installation Script (Python)"
            self.print_info(header, phase='init')
            self.print_info("=" * len(header), phase='init')

            if self.is_debug_mode():
                self.print_debug(f"Fumitm version: {VERSION_INFO['version']} (commit: {VERSION_INFO['commit']})")
                self.print_debug(f"Branch: {VERSION_INFO['branch']} | Date: {VERSION_INFO['date']}")
                if VERSION_INFO['dirty']:
                    self.print_debug("Working directory has uncommitted changes")
                self.print_debug("Script: Python implementation")
                self.print_debug(f"Running on: {platform.platform()}")
                self.print_debug(f"Python version: {sys.version}")
                self.print_debug(f"Shell: {os.environ.get('SHELL', 'unknown')}")
                self.print_debug(f"PATH: {os.environ.get('PATH', '')}")
                self.print_debug(f"Home directory: {os.path.expanduser('~')}")
                self.print_debug(f"Certificate path: {self.cert_path}")
                if self._is_running_as_sudo():
                    uid, gid = self._get_real_user_ids()
                    self.print_debug(f"Running as sudo (real user UID={uid}, GID={gid})")
                if self._run_as_user:
                    self.print_debug(f"Target user: {self._run_as_user} (UID={self._target_uid})")
                if not self.is_install_mode():
                    self.print_debug("Status mode: Using fast certificate checks")
                else:
                    self.print_debug("Install mode: Using thorough certificate checks")

            # Check for updates (skipped in headless or with --skip-update-check)
            if not self.skip_update_check:
                self.check_for_updates()

            if self.is_devcontainer():
                if not self.skip_verify:
                    self.skip_verify = True
                print()
                self.print_info("Detected: Running inside a devcontainer/WSL")
                if not self.command_exists('warp-cli'):
                    self.print_info("   warp-cli is not available in this container")
                    self.print_info("   Certificate must be obtained from your Windows host")
                self.print_info("   Network verification tests will be skipped")
                print()

            self.check_environment_sanity()

            # Check for root-owned files that would cause PermissionError
            self.check_ownership_sanity()

            if self.selected_tools:
                invalid_tools = self.validate_selected_tools()
                if invalid_tools:
                    self.print_error(f"Invalid tool selection: {', '.join(invalid_tools)}")
                    self.print_info("Use --list-tools to see available tools and their tags")
                    return 1

                selected_info = self.get_selected_tools_info()
                if not selected_info:
                    self.print_warn("No tools match your selection")
                    return 1

            if not self.is_install_mode():
                status_ok = self.check_all_status()
                if status_ok is False:
                    return 1
            else:
                self.print_info("Running in FIX mode - changes will be made to your system")
                print()

                if not self.download_certificate():
                    self.print_error("Failed to download certificate. Exiting.")
                    return 1

                # Materialize the supplemental roots, thus each tool fixer can
                # append them with the primary provider certificate.
                self._prepare_extra_roots()
                self._announce_extra_roots()

                if self.selected_tools:
                    self.print_info(f"Processing selected tools: {', '.join(self.get_selected_tools_info())}")
                    print()

                results = []
                no_user = (os.getuid() == 0 and not self._has_user_context())
                for tool_key, tool_info in self.tools_registry.items():
                    if not self.should_process_tool(tool_key):
                        continue
                    setup_func = tool_info.get('setup_func')
                    if not setup_func:
                        continue
                    # Skip user/hybrid-scoped tools when running as root without user context
                    if no_user and tool_info.get('scope') in ('user', 'hybrid'):
                        results.append(ToolResult(tool_key, 'skipped', 'No user context'))
                        self.print_warn(
                            f"Skipping {tool_info['name']} (no user context)",
                            phase='tool', tool=tool_key, result='skipped',
                        )
                        continue
                    result = self._run_setup(tool_key, setup_func)
                    results.append(result)

                print()
                exit_code = self._print_summary(results)

                # Show Docker build guidance once if any container tool was processed
                container_keys = self._container_tool_keys()
                any_container_processed = any(
                    r.tool in container_keys and r.status != 'skipped'
                    for r in results
                )
                if any_container_processed:
                    self._print_docker_build_hint()

                print()
                self.print_info(f"Certificate location: {self.cert_path}")
                self.print_info("For additional applications, please refer to the documentation.")
                self._print_shell_reload_notice()
                return exit_code

            print()
            self.print_info(f"Certificate location: {self.cert_path}")
            self.print_info("For additional applications, please refer to the documentation.")
            return 0

        except NonInteractiveError as e:
            self.print_error(str(e))
            return 2
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 130
        except Exception as e:
            self.print_error(f"Unexpected error: {e}")
            if self.is_debug_mode():
                import traceback
                traceback.print_exc()
            return 1


def main():
    parser = argparse.ArgumentParser(
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Author: {__author__} | Default: status check only (use --fix to make changes)"
    )

    parser.add_argument('--fix', action='store_true',
                        help='Actually make changes (default is status check only)')
    parser.add_argument('--tools', '--tool', action='append', dest='tools',
                        help='Specific tools to check/fix (can be specified multiple times). '
                             'Examples: --tools node --tools python or --tools node-npm,gcloud')
    parser.add_argument('--list-tools', action='store_true',
                        help='List all available tools and their tags')
    parser.add_argument('--cert-file', metavar='PATH',
                        help='Path to certificate file (useful for devcontainers where warp-cli is unavailable)')
    parser.add_argument('--manual-cert', action='store_true',
                        help='Force manual certificate input mode (for devcontainers)')
    parser.add_argument('--skip-verify', action='store_true',
                        help='Skip network verification tests (useful in devcontainers)')
    parser.add_argument('--provider', choices=list(PROVIDERS.keys()),
                        help='MITM proxy provider (default: auto-detect)')
    parser.add_argument('--with-aikido', action='store_true',
                        help='Force-add the Aikido Endpoint Protection root CA to all '
                             'bundles even if it is not auto-detected. On hosts with no '
                             'live Aikido agent, supply the root via --aikido-cert or a '
                             'previously saved ~/.aikido-ca.pem')
    parser.add_argument('--aikido-cert', metavar='PATH',
                        help='Path to a PEM file containing the Aikido root CA, used as '
                             'the preferred source for --with-aikido on no-agent images')
    parser.add_argument('--no-aikido', action='store_true',
                        help='Do not add the Aikido root CA even if Aikido is detected')
    parser.add_argument('--yes', '-y', action='store_true',
                        help='Answer yes to all prompts (for non-interactive use)')
    parser.add_argument('--debug', '--verbose', action='store_true',
                        help='Show detailed debug information')
    parser.add_argument('--version', '-V', action='store_true',
                        help='Show version information and exit')

    # Headless/MDM flags
    parser.add_argument('--headless', action='store_true',
                        help='Non-interactive mode: disables color, skips update check. '
                             'Does NOT imply --yes (consent must be explicit).')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable ANSI color output')
    parser.add_argument('--skip-update-check', action='store_true',
                        help='Skip checking for updates')
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument('--log-file', metavar='PATH',
                           help='Write plain-text log to PATH (overwrites each run)')
    log_group.add_argument('--log-dir', metavar='DIR',
                           help='Write per-run text logs to DIR with fumitm-latest.log symlink')

    json_log_group = parser.add_mutually_exclusive_group()
    json_log_group.add_argument('--json-log-file', metavar='PATH',
                                help='Write JSON-lines event log to PATH (overwrites each run)')
    json_log_group.add_argument('--json-log-dir', metavar='DIR',
                                help='Write per-run JSON-lines logs to DIR with fumitm-latest.jsonl symlink')
    parser.add_argument('--run-as-user', metavar='USERNAME',
                        help='Configure certs for USERNAME (requires root). '
                             'Use "auto" to detect console user on macOS.')

    args = parser.parse_args()

    if args.version:
        print(f"fumitm {__version__}")
        version_info = VERSION_INFO
        if version_info['commit'] != 'unknown':
            print(f"  Git commit: {version_info['commit']} ({version_info['date']})")
            print(f"  Branch: {version_info['branch']}")
            if version_info['dirty']:
                print("  (with local modifications)")
        sys.exit(0)

    headless = args.headless or os.environ.get('FUMITM_HEADLESS') == '1'
    if headless:
        args.no_color = True
        args.skip_update_check = True

    # Respect NO_COLOR environment variable (https://no-color.org/)
    no_color = args.no_color or os.environ.get('NO_COLOR') is not None

    if args.run_as_user and os.getuid() != 0:
        parser.error('--run-as-user requires root privileges')

    if args.list_tools:
        temp_fumitm = FumitmPython(no_color=no_color)
        print("Available tools:")
        for tool_key, tool_info in temp_fumitm.tools_registry.items():
            tags_str = ', '.join(tool_info['tags'])
            print(f"  {tool_key:<10} - {tool_info['name']:<20} Tags: {tags_str}")
        print("\nExamples: ./fumitm.py --fix --tools node,python  or  ./fumitm.py --fix --tools node-npm --tools gcp")
        sys.exit(0)

    selected_tools = []
    if args.tools:
        for tool_arg in args.tools:
            selected_tools.extend(
                [t.strip() for t in tool_arg.split(',') if t.strip()]
            )

    if args.with_aikido and args.no_aikido:
        parser.error('--with-aikido and --no-aikido are mutually exclusive')
    if args.aikido_cert and args.no_aikido:
        parser.error('--aikido-cert cannot be combined with --no-aikido')

    mode = 'install' if args.fix else 'status'

    fumitm_instance = FumitmPython(
        mode=mode,
        debug=args.debug,
        selected_tools=selected_tools,
        cert_file=args.cert_file,
        manual_cert=args.manual_cert,
        skip_verify=args.skip_verify,
        provider=args.provider,
        auto_yes=args.yes,
        no_color=no_color,
        headless=headless,
        skip_update_check=args.skip_update_check,
        log_file=args.log_file,
        log_dir=args.log_dir,
        json_log_file=args.json_log_file,
        json_log_dir=args.json_log_dir,
        run_as_user=args.run_as_user,
        with_aikido=args.with_aikido,
        no_aikido=args.no_aikido,
        aikido_cert_file=args.aikido_cert,
    )
    exit_code = fumitm_instance.main()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
