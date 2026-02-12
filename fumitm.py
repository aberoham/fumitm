#!/usr/bin/env python3

import os
import sys
import subprocess
import tempfile
import shutil
import argparse
import platform
import json
import ssl
import base64
import hashlib
import pwd
import socket
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# Version and metadata
__description__ = "MITM Proxy Certificate Fixer Upper for macOS and Linux"
__author__ = "Ingersoll & Claude"
__version__ = "2026.2.11.3"  # CalVer: YYYY.MM.DD (auto-updated on release)


def parse_calver(version_str):
    """Parse CalVer version string into comparable tuple.

    Args:
        version_str: Version like "2025.12.18" or "2025.12.18.1"

    Returns:
        tuple: (year, month, day, patch) where patch is 0 for base versions
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
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if we're in a git repository
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=script_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            # Get commit hash (short)
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['commit'] = result.stdout.strip()
            
            # Get commit date
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%cd', '--date=short'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['date'] = result.stdout.strip()
            
            # Get branch name
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['branch'] = result.stdout.strip()
            
            # Check if working directory is dirty
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['dirty'] = True
            
            # Get tag if available
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                cwd=script_dir,
                capture_output=True,
                text=True,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['version'] = result.stdout.strip()
            else:
                # No tags, use commit count as version
                result = subprocess.run(
                    ['git', 'rev-list', '--count', 'HEAD'],
                    cwd=script_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    count = result.stdout.strip()
                    version_info['version'] = f"0.{count}.0"
            
            # Add dirty flag to version if needed
            if version_info['dirty'] and version_info['version'] != 'unknown':
                version_info['version'] += '-dirty'
    
    except Exception:
        # Git not available or not a git repository
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

# Provider configurations: each MITM proxy that fumitm supports. The tool setup
# logic is identical across providers — only certificate sources, paths, and
# display names differ.
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

class FumitmPython:
    def __init__(self, mode='status', debug=False, selected_tools=None, cert_file=None, manual_cert=False, skip_verify=False, provider=None):
        self.mode = mode
        self.debug = debug
        self.shell_modified = False
        self.cert_fingerprint = ""
        self.selected_tools = selected_tools or []
        self.cert_file = cert_file
        self.manual_cert = manual_cert
        self.skip_verify = skip_verify

        # When running under sudo on Linux, $HOME may resolve to /root instead
        # of the real user's home directory. Correct it before any expanduser calls
        # so that certificate and bundle paths land in the right place.
        sudo_user = os.environ.get('SUDO_USER')
        if os.getuid() == 0 and sudo_user:
            try:
                real_home = pwd.getpwnam(sudo_user).pw_dir
                if os.path.expanduser('~') != real_home:
                    os.environ['HOME'] = real_home
            except KeyError:
                pass

        # Resolve which MITM proxy provider to use. When provider is None,
        # auto-detection checks WARP first, then Netskope.
        self.provider = self._resolve_provider(provider)
        self.cert_path = os.path.expanduser(self.provider['cert_path'])
        self.bundle_dir = os.path.expanduser(self.provider['bundle_dir'])

        # Define tool registry with tags and descriptions
        self.tools_registry = {
            'node': {
                'name': 'Node.js',
                'tags': ['node', 'nodejs', 'node-npm', 'javascript', 'js'],
                'setup_func': self.setup_node_cert,
                'check_func': self.check_node_status,
                'description': 'Node.js runtime and npm package manager'
            },
            'python': {
                'name': 'Python',
                'tags': ['python', 'python3', 'pip', 'requests'],
                'setup_func': self.setup_python_cert,
                'check_func': self.check_python_status,
                'description': 'Python runtime and pip package manager'
            },
            'gcloud': {
                'name': 'Google Cloud SDK',
                'tags': ['gcloud', 'google-cloud', 'gcp'],
                'setup_func': self.setup_gcloud_cert,
                'check_func': self.check_gcloud_status,
                'description': 'Google Cloud SDK (gcloud CLI)'
            },
            'java': {
                'name': 'Java/JVM',
                'tags': ['java', 'jvm', 'keytool', 'jdk'],
                'setup_func': self.setup_java_cert,
                'check_func': self.check_java_status,
                'description': 'Java runtime and development kit'
            },
            'jenv': {
                'name': 'jenv (Java Environment Manager)',
                'tags': ['jenv', 'java', 'jvm', 'jdk'],
                'setup_func': self.setup_jenv_cert,
                'check_func': self.check_jenv_status,
                'description': 'jenv-managed Java installations'
            },
            'gradle': {
                'name': 'Gradle',
                'tags': ['gradle'],
                'setup_func': self.setup_gradle_cert,
                'check_func': self.check_gradle_status,
                'description': 'Gradle build tool'
            },
            'dbeaver': {
                'name': 'DBeaver',
                'tags': ['dbeaver', 'database', 'db'],
                'setup_func': self.setup_dbeaver_cert,
                'check_func': self.check_dbeaver_status,
                'description': 'DBeaver database client'
            },
            'wget': {
                'name': 'wget',
                'tags': ['wget', 'download'],
                'setup_func': self.setup_wget_cert,
                'check_func': self.check_wget_status,
                'description': 'wget download utility'
            },
            'podman': {
                'name': 'Podman',
                'tags': ['podman', 'container', 'docker-alternative'],
                'setup_func': self.setup_podman_cert,
                'check_func': self.check_podman_status,
                'description': 'Podman container runtime'
            },
            'rancher': {
                'name': 'Rancher Desktop',
                'tags': ['rancher', 'rancher-desktop', 'kubernetes', 'k8s'],
                'setup_func': self.setup_rancher_cert,
                'check_func': self.check_rancher_status,
                'description': 'Rancher Desktop Kubernetes'
            },
            'android': {
                'name': 'Android Emulator',
                'tags': ['android', 'emulator', 'adb'],
                'setup_func': self.setup_android_emulator_cert,
                'check_func': self.check_android_status,
                'description': 'Android SDK emulator'
            },
            'colima': {
                'name': 'Colima',
                'tags': ['colima', 'docker', 'docker-desktop', 'container', 'vm'],
                'setup_func': self.setup_colima_cert,
                'check_func': self.check_colima_status,
                'description': 'Colima Docker runtime'
            },
            'git': {
                'name': 'Git',
                'tags': ['git'],
                'setup_func': self.setup_git_cert,
                'check_func': self.check_git_status,
                'description': 'Git version control'
            },
            'curl': {
                'name': 'curl',
                'tags': ['curl', 'http'],
                'setup_func': self.setup_curl_cert,
                'check_func': self.check_curl_status,
                'description': 'curl HTTP client'
            }
        }
        
        # Add platform check
        if platform.system() != 'Darwin':
            self.print_warn("This script is designed for macOS. Most features will not work correctly.")

    def _resolve_provider(self, requested):
        """Determine which MITM proxy provider to use.

        When no provider is explicitly requested, auto-detection checks WARP
        first (via warp-cli), then Netskope (via known cert file paths or
        STAgent process). If both are detected, WARP is preferred and an info
        message about Netskope availability is printed.
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

        # Neither detected — fall back to WARP so existing error messages about
        # missing warp-cli still make sense.
        return PROVIDERS['warp']

    def _path_belongs_to_other_provider(self, path):
        """Check whether a path lives under a different provider's bundle directory.

        Returns the other provider's display name if the path is under a
        different provider's bundle_dir, or None if it belongs to the current
        provider or is unrelated to any known provider.
        """
        for config in PROVIDERS.values():
            other_dir = os.path.expanduser(config['bundle_dir'])
            if other_dir == self.bundle_dir:
                continue
            if path.startswith(other_dir + os.sep):
                return config['name']
        return None

    def _detect_warp(self):
        """Return True if Cloudflare WARP appears to be installed."""
        return shutil.which('warp-cli') is not None

    def _detect_netskope(self):
        """Return True if Netskope appears to be installed.

        Checks known certificate file paths first (fast), then falls back to
        looking for a running Netskope process. On macOS, the client runs as
        "Netskope Client"; on Linux, it runs as STAgent.
        """
        plat = platform.system()
        cert_sources = PROVIDERS['netskope'].get('cert_sources', {}).get(plat, [])
        for path in cert_sources:
            if os.path.exists(path):
                return True

        # Check for encrypted cert variant
        for path in cert_sources:
            if os.path.exists(path + '.enc'):
                return True

        # Fall back to process check with platform-appropriate process name
        try:
            proc_pattern = 'Netskope Client' if plat == 'Darwin' else 'STAgent'
            result = subprocess.run(
                ['pgrep', '-f', proc_pattern],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return True
        except Exception:
            pass

        return False

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
        
        # Check if tool key or any of its tags match the selection
        for selection in self.selected_tools:
            selection_lower = selection.lower()
            if selection_lower == tool_key:
                return True
            if selection_lower in [tag.lower() for tag in tool_info.get('tags', [])]:
                return True
        
        return False
    
    def get_selected_tools_info(self):
        """Get information about selected tools."""
        if not self.selected_tools:
            return list(self.tools_registry.keys())
        
        selected = []
        for tool_key, tool_info in self.tools_registry.items():
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
            
            # Check all tools for matching key or tag
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
    
    # Printing functions
    def print_info(self, msg):
        print(f"{GREEN}[INFO]{NC} {msg}")
    
    def print_warn(self, msg):
        print(f"{YELLOW}[WARN]{NC} {msg}")
    
    def print_error(self, msg):
        print(f"{RED}[ERROR]{NC} {msg}")
    
    def print_status(self, msg):
        print(f"{BLUE}[STATUS]{NC} {msg}")
    
    def print_action(self, msg):
        print(f"{YELLOW}[ACTION]{NC} {msg}")
    
    def print_debug(self, msg):
        if self.is_debug_mode():
            print(f"{BLUE}[DEBUG]{NC} {msg}", file=sys.stderr)

    def check_for_updates(self):
        """Check if a newer version of fumitm is available on GitHub.

        Uses CalVer version comparison instead of file hashes to avoid
        false positives from local modifications or formatting differences.
        Skips the update warning when running from a local git working copy
        (non-main branch or dirty tree), since the user is likely developing.

        Uses an unverified SSL context since proxy certificate trust might not
        be configured yet (which is why the user is running this script).

        Returns:
            bool: True if an update is available, False otherwise
        """
        import re

        try:
            # Use unverified SSL context - WARP might not be configured yet
            context = ssl._create_unverified_context()
            url = "https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py"

            self.print_debug(f"Checking for updates from {url}")

            req = urllib.request.Request(url, headers={'User-Agent': 'fumitm-update-check'})
            with urllib.request.urlopen(req, context=context, timeout=10) as response:
                remote_content = response.read().decode('utf-8')

            # Extract remote version using regex
            version_match = re.search(r'^__version__\s*=\s*["\']([0-9.]+)["\']',
                                      remote_content, re.MULTILINE)

            if not version_match:
                self.print_debug("Could not extract version from remote file")
                return False

            remote_version = version_match.group(1)
            local_version = __version__

            self.print_debug(f"Local version:  {local_version}")
            self.print_debug(f"Remote version: {remote_version}")

            # Parse and compare versions
            try:
                local_tuple = parse_calver(local_version)
                remote_tuple = parse_calver(remote_version)
            except ValueError as e:
                self.print_debug(f"Version parse error: {e}")
                return False

            if remote_tuple > local_tuple:
                # When running from a git working copy on a non-main branch or
                # with local modifications, the version mismatch is expected.
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
                # Use -k to skip cert verification since user's curl may be broken
                # (which is likely why they're running this script)
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
    
    def is_writable(self, path):
        """Check if a file/directory is writable."""
        if os.path.isfile(path):
            return os.access(path, os.W_OK)
        elif os.path.isdir(os.path.dirname(path)):
            return os.access(os.path.dirname(path), os.W_OK)
        else:
            # Path doesn't exist, check parent directories
            parent = os.path.dirname(path)
            while not os.path.isdir(parent) and parent != '/':
                parent = os.path.dirname(parent)
            return os.access(parent, os.W_OK)
    
    def suggest_user_path(self, original_path, purpose):
        """Suggest alternative path."""
        filename = os.path.basename(original_path)
        return os.path.join(self.bundle_dir, purpose, filename)

    def _is_running_as_sudo(self):
        """True when the process is root via sudo, not actual root login."""
        return os.getuid() == 0 and 'SUDO_UID' in os.environ

    def _get_real_user_ids(self):
        """Return (uid, gid) of the real user, even when running under sudo."""
        if self._is_running_as_sudo():
            return (int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        return (os.getuid(), os.getgid())

    def _fix_ownership(self, path):
        """Chown a home-directory path back to the real user when running under sudo.

        System paths outside $HOME (e.g. /etc/ssl) are left untouched so that
        files which legitimately belong to root stay root-owned.
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

    def detect_shell(self):
        """Detect the user's default shell with multiple fallbacks."""
        # Try environment variable first (current session)
        shell_path = os.environ.get('SHELL')
        
        # Fallback to pwd module (system configured default)
        if not shell_path:
            try:
                shell_path = pwd.getpwuid(os.getuid()).pw_shell
            except Exception:
                shell_path = None
        
        # Final fallback for modern macOS
        if not shell_path:
            shell_path = '/bin/zsh'
        
        # Extract just the shell name
        shell_name = os.path.basename(shell_path)
        
        # Normalize common shells
        known_shells = {'bash', 'zsh', 'fish', 'sh', 'tcsh', 'csh', 'dash'}
        
        if shell_name in known_shells:
            return shell_name
        else:
            # Return actual name rather than 'unknown'
            return shell_name

    def get_shell_config(self, shell_type):
        """Get shell config file."""
        home = os.path.expanduser("~")
        if shell_type == 'bash':
            # For macOS, .bash_profile is the primary config file for login shells
            for config in ['.bash_profile', '.bashrc', '.profile']:
                if os.path.exists(os.path.join(home, config)):
                    return os.path.join(home, config)
            return os.path.join(home, '.profile')
        elif shell_type == 'zsh':
            return os.path.join(home, '.zshrc')
        elif shell_type == 'fish':
            return os.path.join(home, '.config/fish/config.fish')
        else:
            return os.path.join(home, '.profile')

    def check_environment_sanity(self):
        """Check for broken CA-related environment variables pointing to non-existent files.

        This catches common issues where users have stale environment variables
        from previous WARP setups or removed shell config exports without unsetting
        the variables in their current session.

        Returns:
            bool: True if any broken variables were found, False otherwise
        """
        # Environment variables to check (simple file path variables)
        ca_env_vars = [
            'CURL_CA_BUNDLE',
            'SSL_CERT_FILE',
            'REQUESTS_CA_BUNDLE',
            'NODE_EXTRA_CA_CERTS',
            'GIT_SSL_CAINFO',
        ]

        broken_vars = []

        # Check simple path variables
        for var_name in ca_env_vars:
            var_value = os.environ.get(var_name, '')
            if var_value and not os.path.exists(var_value):
                broken_vars.append((var_name, var_value))

        # Special handling for JAVA_OPTS which may contain -Djavax.net.ssl.trustStore=...
        java_opts = os.environ.get('JAVA_OPTS', '')
        if java_opts:
            import re
            match = re.search(r'-Djavax\.net\.ssl\.trustStore=([^\s]+)', java_opts)
            if match:
                truststore_path = match.group(1)
                if not os.path.exists(truststore_path):
                    broken_vars.append(('JAVA_OPTS (trustStore)', truststore_path))

        if not broken_vars:
            return False

        # Display prominent warning
        print()
        self.print_warn("=" * 60)
        self.print_warn("BROKEN ENVIRONMENT DETECTED")
        self.print_warn("=" * 60)
        print()
        self.print_warn("The following environment variables point to non-existent files:")
        print()

        for var_name, var_value in broken_vars:
            self.print_error(f"  {var_name}={var_value}")
            self.print_error(f"    FILE DOES NOT EXIST")
            print()

        # Provide remediation steps
        self.print_info("To fix in your CURRENT shell session:")
        for var_name, _ in broken_vars:
            if var_name.startswith('JAVA_OPTS'):
                self.print_info(f"  unset JAVA_OPTS  # (or edit to remove trustStore)")
            else:
                self.print_info(f"  unset {var_name}")
        print()

        self.print_info("To fix PERMANENTLY, remove/comment the export lines from:")
        shell_type = self.detect_shell()
        if shell_type == 'zsh':
            self.print_info("  ~/.zshrc, ~/.zprofile")
        elif shell_type == 'bash':
            self.print_info("  ~/.bashrc, ~/.bash_profile, ~/.profile")
        elif shell_type == 'fish':
            self.print_info("  ~/.config/fish/config.fish")
        else:
            self.print_info("  ~/.profile, ~/.bashrc, or your shell's config file")
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
        """Detect and warn about root-owned files in the user's home directory.

        When users accidentally run ``sudo ./fumitm.py --fix``, the script creates
        files owned by root inside ``$HOME``. Subsequent non-root runs then fail
        with PermissionError. This method detects that situation and either warns
        (when not root) or proactively corrects ownership (when running as sudo).

        Returns:
            bool: True if problems were found (or corrected), False if clean.
        """
        managed_paths = [self.cert_path, self.bundle_dir]
        home = os.path.expanduser('~')

        if self._is_running_as_sudo():
            # Running as sudo — fix any pre-existing root-owned managed files
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
                self.print_warn(f"Running as sudo — corrected ownership on {len(fixed)} file(s) in {home}")
                self.print_info("New files created during this run will also be owned by the real user")
            else:
                self.print_info("Running as sudo — ownership correction will be applied to new files")
            return bool(fixed)

        # Not root — check for root-owned files and warn
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
                    capture_output=True, text=True
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
                    result = subprocess.run(['/usr/libexec/java_home'], capture_output=True, text=True)
                    if result.returncode == 0:
                        java_home = result.stdout.strip()

                if not java_home:
                    result = subprocess.run(
                        ['java', '-XshowSettings:properties', '-version'],
                        capture_output=True, text=True, stderr=subprocess.STDOUT
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
        if not os.path.exists(cacerts):
            cacerts = os.path.join(java_home, 'jre/lib/security/cacerts')
        return cacerts if os.path.exists(cacerts) else ''

    def java_version_label(self, java_home):
        """Derive a human-readable label from a Java home path, e.g. 'temurin-21'."""
        if 'Contents/Home' in java_home:
            return os.path.basename(os.path.dirname(os.path.dirname(java_home))).replace('.jdk', '')
        return os.path.basename(java_home)

    def find_all_java_homes(self):
        """Find all Java installations on the system.

        Returns:
            list: List of unique Java home paths with valid cacerts
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
                        text=True
                    )
                    for line in result.stdout.splitlines():
                        if line and '/' in line and '/Contents/Home' in line:
                            # Extract path from end of line
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
                    text=True
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
        for line in existing_lines:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                current_props[key] = val

        if all(current_props.get(k) == v for k, v in props_to_set.items()):
            return False

        self.print_info(f"Setting up {desc}...")

        updated_lines = []
        remaining = props_to_set.copy()
        for line in existing_lines:
            stripped = line.strip()
            replaced = False
            for key in list(remaining):
                if stripped.startswith(key + '='):
                    updated_lines.append(f"{key}={remaining.pop(key)}\n")
                    replaced = True
                    break
            if not replaced:
                updated_lines.append(line)

        for key, value in remaining.items():
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
    
    def certificate_likely_exists_in_file(self, cert_file, target_file):
        """Fast certificate check using pure Python string matching.

        This function uses no subprocess calls for performance. It extracts
        the first 100 characters of base64 content from the certificate and
        searches for that unique portion in the target file.

        Args:
            cert_file: Path to the certificate to search for
            target_file: Path to the bundle file to search in

        Returns:
            bool: True if certificate likely exists in target file
        """
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False

        try:
            # Extract base64 content from cert file (skip BEGIN/END markers)
            with open(cert_file, 'r') as f:
                cert_lines = []
                in_cert = False
                for line in f:
                    if '-----BEGIN CERTIFICATE-----' in line:
                        in_cert = True
                    elif '-----END CERTIFICATE-----' in line:
                        in_cert = False
                    elif in_cert:
                        cert_lines.append(line.strip())

                if not cert_lines:
                    return False

                # Get first 100 chars of base64 content - enough to be unique
                cert_unique_portion = ''.join(cert_lines)[:100]

            # Search for this unique portion in target file
            with open(target_file, 'r') as tf:
                target_content = tf.read()
                # Normalize whitespace for comparison
                target_normalized = ''.join(target_content.split())

                if cert_unique_portion in target_normalized:
                    self.print_debug(f"Certificate likely exists in {target_file} (found matching content)")
                    return True

        except Exception as e:
            self.print_debug(f"Error checking certificate content: {e}")

        return False
    
    def certificate_exists_in_file(self, cert_file, target_file):
        """Check if a certificate already exists in a file.

        Uses fast pure-Python string matching for performance. The previous
        fingerprint-based comparison was O(N) in subprocess calls where N is
        the number of certificates in the target file. The string matching
        approach is O(1) and sufficient for duplicate detection.

        Args:
            cert_file: Path to the certificate to search for
            target_file: Path to the bundle file to search in

        Returns:
            bool: True if certificate exists in target file
        """
        # Use the fast pure-Python check for all modes
        # This is sufficient because:
        # 1. False negatives (cert exists but not found) -> duplicate appended, harmless
        # 2. False positives (cert not there but found) -> extremely unlikely with 100-char match
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
        """Detect bundles that likely contain only WARP CA or are too small to be full.

        Returns (is_suspicious: bool, reason: str)
        """
        try:
            if not os.path.exists(bundle_path):
                return (False, "")
            size = 0
            try:
                size = os.path.getsize(bundle_path)
            except Exception:
                # Fallback: approximate by length of content
                try:
                    with open(bundle_path, 'r') as f:
                        size = len(f.read().encode('utf-8'))
                except Exception:
                    size = 0

            cert_count = self.count_certificates_in_file(bundle_path)
            # Debug one-liner summary
            if self.is_debug_mode():
                self.print_debug(f"Bundle stats for {bundle_path}: {cert_count} cert(s), size={size}B")

            # Obvious misconfig: just a single certificate
            if cert_count <= 1:
                return (True, f"contains {cert_count} certificate(s), size={size}B")

            # Small count and small file size heuristics
            if cert_count <= SMALL_BUNDLE_MAX_CERTS and size <= SMALL_BUNDLE_MAX_SIZE_BYTES:
                return (True, f"contains {cert_count} certificates and is only {size}B")

            # If we have a reference WARP cert, exact-equality to it is suspicious
            if warp_cert_path and self.files_are_identical(bundle_path, warp_cert_path):
                return (True, "bundle is identical to the proxy certificate file")

            return (False, "")
        except Exception as e:
            self.print_debug(f"Error checking suspicious bundle {bundle_path}: {e}")
            return (False, "")

    def get_bundle_stats(self, path):
        """Return (cert_count, size_bytes) for a certificate bundle path."""
        try:
            count = self.count_certificates_in_file(path)
            size = os.path.getsize(path) if os.path.exists(path) else 0
            return count, size
        except Exception:
            return 0, 0

    def create_bundle_with_system_certs(self, bundle_path):
        """Create a CA bundle initialized with system certificates.

        Copies system CA certificates to the specified bundle path. This is used
        when creating new certificate bundles for tools that need a full CA chain.

        Args:
            bundle_path: Path where the bundle should be created

        Returns:
            bool: True if system certs were copied, False if empty bundle created
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
        """Safely append a certificate to a target file, ensuring proper PEM formatting.

        This method handles the case where the target file doesn't end with a newline,
        which would otherwise produce malformed PEM like:
        -----END CERTIFICATE----------BEGIN CERTIFICATE-----

        Args:
            cert_file: Path to the certificate file to append
            target_file: Path to the target bundle file

        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(cert_file):
            self.print_error(f"Certificate file not found: {cert_file}")
            return False

        # Check if certificate already exists in target
        if self.certificate_exists_in_file(cert_file, target_file):
            self.print_debug(f"Certificate already exists in {target_file}, skipping append")
            return True

        try:
            # Read certificate content
            with open(cert_file, 'r') as cf:
                cert_content = cf.read()

            # Ensure certificate content ends with newline
            if not cert_content.endswith('\n'):
                cert_content = cert_content + '\n'

            # Check if target file exists and whether it ends with a newline
            needs_leading_newline = False
            if os.path.exists(target_file):
                with open(target_file, 'rb') as tf:
                    # Seek to end and read last byte
                    tf.seek(0, 2)  # Seek to end
                    if tf.tell() > 0:  # File is not empty
                        tf.seek(-1, 2)  # Seek to last byte
                        last_byte = tf.read(1)
                        # Check for newline (LF) or carriage return (CR for CRLF)
                        if last_byte not in (b'\n', b'\r'):
                            needs_leading_newline = True

            # Append certificate with proper formatting
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

    def add_to_shell_config(self, var_name, var_value, shell_config):
        """Add export to shell config."""
        # Check if the export already exists
        if os.path.exists(shell_config):
            with open(shell_config, 'r') as f:
                content = f.read()
                
            if f"export {var_name}=" in content:
                self.print_warn(f"{var_name} already exists in {shell_config}")
                # Find current value
                for line in content.splitlines():
                    if line.strip().startswith(f"export {var_name}="):
                        self.print_info(f"Current value: {line.strip()}")
                        break
                
                if not self.is_install_mode():
                    self.print_action(f"Would ask to update {var_name} in {shell_config}")
                    self.print_action(f"Would set: export {var_name}=\"{var_value}\"")
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() == 'y':
                        # Comment out old entries
                        lines = content.splitlines()
                        new_lines = []
                        for line in lines:
                            if line.strip().startswith(f"export {var_name}="):
                                new_lines.append(f"#{line}")
                            else:
                                new_lines.append(line)
                        
                        # Add new entry
                        new_lines.append(f'export {var_name}="{var_value}"')
                        
                        # Write back
                        with open(shell_config + '.bak', 'w') as f:
                            f.write(content)
                        self._fix_ownership(shell_config + '.bak')
                        with open(shell_config, 'w') as f:
                            f.write('\n'.join(new_lines) + '\n')
                        self._fix_ownership(shell_config)

                        self.shell_modified = True
                        self.print_info(f"Updated {var_name} in {shell_config}")
                return

        # Variable doesn't exist, add it
        if not self.is_install_mode():
            self.print_action(f"Would add to {shell_config}:")
            self.print_action(f'export {var_name}="{var_value}"')
        else:
            with open(shell_config, 'a') as f:
                f.write(f'\nexport {var_name}="{var_value}"\n')
            self._fix_ownership(shell_config)
            self.shell_modified = True
            self.print_info(f"Added {var_name} to {shell_config}")
    
    def is_devcontainer(self):
        """Check if running inside a VS Code devcontainer."""
        # Check for devcontainer environment variables
        if os.environ.get('REMOTE_CONTAINERS') or os.environ.get('CODESPACES'):
            return True
        
        # Check for .dockerenv file (Docker container indicator)
        if os.path.exists('/.dockerenv'):
            return True
        
        # Check for container environment in cgroup
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup = f.read()
                if 'docker' in cgroup or 'containerd' in cgroup:
                    return True
        except Exception:
            pass
        
        # Check for WSL
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
        self.print_info(f"1. On your Windows host, open PowerShell/Terminal and run:")
        self.print_info(f"   {BLUE}warp-cli certs --no-paginate{NC}")
        self.print_info(f"2. Copy the entire output (including BEGIN/END lines)")
        self.print_info(f"3. Come back here and paste it")
        print()
        self.print_info("ALTERNATIVE METHOD:")
        self.print_info(f"1. Save the certificate to a file accessible from this container")
        self.print_info(f"2. Run: ./fumitm.py --fix --cert-file /path/to/cert.pem")
        print()
        
        choice = input("Ready to paste? Press ENTER to continue, 'F' for file path, or 'Q' to quit: ").strip().upper()
        
        if choice == 'Q':
            return None
        elif choice == 'F':
            file_path = input("Enter the path to the certificate file: ").strip()
            if not file_path:
                self.print_error("No file path provided")
                return None
            
            # Expand user path
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
            # Default to paste mode - make it easier
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
        
        # Validate the certificate format
        if not cert_content.strip():
            self.print_error("No certificate provided")
            return None
        
        if "-----BEGIN CERTIFICATE-----" not in cert_content:
            self.print_error("Invalid certificate format: missing BEGIN CERTIFICATE marker")
            return None
        
        if "-----END CERTIFICATE-----" not in cert_content:
            self.print_error("Invalid certificate format: missing END CERTIFICATE marker")
            return None
        
        # Ensure proper formatting
        cert_lines = cert_content.strip().split('\n')
        formatted_cert = '\n'.join(cert_lines) + '\n'
        
        return formatted_cert
    
    def _get_warp_cert(self):
        """Retrieve the CA certificate from warp-cli.

        Returns:
            str or None: PEM certificate text, or None on failure.
        """
        try:
            result = subprocess.run(
                ['warp-cli', 'certs', '--no-paginate'],
                capture_output=True, text=True
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
        """Retrieve the Netskope CA certificate.

        Tries these sources in order:
        1. Known file paths (nscacert_combined.pem, then nscacert.pem)
        2. macOS Keychain extraction (root + intermediate)
        3. Detects encrypted .enc certs and advises --cert-file

        Returns:
            str or None: PEM certificate text, or None on failure.
        """
        plat = platform.system()
        cert_sources = self.provider.get('cert_sources', {}).get(plat, [])

        # Try reading from known file paths
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

        # Check for encrypted cert variant — the encryptClientConfig hardening
        # flag encrypts on-disk certs. We note this and try the keychain instead.
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
        """Extract Netskope root and intermediate CA certificates from the macOS System Keychain.

        The root CA typically has a CN containing "certadmin" and the
        intermediate has a CN containing "goskope". The -c flag on
        security find-certificate does substring matching, which handles
        org-specific variants like ca.thg.goskope.com.

        Returns:
            str or None: Combined PEM certificate text, or None on failure.
        """
        certs = []

        # Root CA (CN contains "certadmin")
        try:
            result = subprocess.run(
                ['security', 'find-certificate', '-c', 'certadmin', '-p',
                 '/Library/Keychains/System.keychain'],
                capture_output=True, text=True
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
                capture_output=True, text=True
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
            # Check if certificate already exists
            if os.path.exists(self.cert_path):
                self.print_info(f"Found existing certificate at {self.cert_path}")
                # In install mode, ask if they want to update it
                if self.is_install_mode():
                    response = input("Do you want to update it with a new certificate? (y/N) ")
                    if response.lower() == 'y':
                        warp_cert = self.get_certificate_from_user()
                        if not warp_cert:
                            return False
                    else:
                        with open(self.cert_path, 'r') as f:
                            warp_cert = f.read()
                        self.print_info("Using existing certificate")
                else:
                    # In status mode, just use existing
                    with open(self.cert_path, 'r') as f:
                        warp_cert = f.read()
                    self.print_info("Using existing certificate for status check")
            else:
                # No existing cert - must get from user
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
        
        # Create a temp file for the proxy certificate
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
            temp_cert.write(warp_cert)
            temp_cert_path = temp_cert.name
        
        # Verify it's a valid PEM certificate
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-in', temp_cert_path],
                capture_output=True
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

        # Check if certificate needs to be saved
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

        # Save certificate if needed
        if needs_save:
            if not self.is_install_mode():
                self.print_action(f"Would save certificate to {self.cert_path}")
            else:
                # Save certificate
                shutil.copy(temp_cert_path, self.cert_path)
                self._fix_ownership(self.cert_path)
                self.print_info(f"Certificate saved to {self.cert_path}")

        # Clean up
        os.unlink(temp_cert_path)
        
        # Cache the fingerprint for later use
        self.get_cert_fingerprint()
        
        return True
    
    def setup_node_cert(self):
        """Setup Node.js certificate."""
        if not self.command_exists('node'):
            return
        
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        needs_setup = False
        
        node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
        
        if node_extra_ca_certs:
            other_provider = self._path_belongs_to_other_provider(node_extra_ca_certs)
            if other_provider:
                # Path belongs to a different provider — migrate to current provider's bundle
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
                    self.add_to_shell_config("NODE_EXTRA_CA_CERTS", node_bundle, shell_config)
                    self.print_info(f"Migrated Node.js CA bundle to {node_bundle}")
            elif os.path.exists(node_extra_ca_certs):
                # Check if the file contains our certificate using normalized comparison
                if self.certificate_exists_in_file(self.cert_path, node_extra_ca_certs):
                    # Certificate already exists in NODE_EXTRA_CA_CERTS, skip to npm setup
                    pass
                else:
                    needs_setup = True
                    self.print_info("Configuring Node.js certificate...")
                    self.print_info(f"NODE_EXTRA_CA_CERTS is already set to: {node_extra_ca_certs}")

                    # Check if we can write to the file
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
                            response = input("Do you want to use this alternative path? (Y/n) ")
                            if response.lower() != 'n':
                                self._safe_makedirs(os.path.dirname(new_path))
                                if os.path.exists(node_extra_ca_certs):
                                    try:
                                        shutil.copy(node_extra_ca_certs, new_path)
                                        self._fix_ownership(new_path)
                                    except Exception:
                                        Path(new_path).touch()
                                        self._fix_ownership(new_path)

                                self.safe_append_certificate(self.cert_path, new_path)

                                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", new_path, shell_config)
                                self.print_info(f"Created new certificate bundle at {new_path}")
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would append proxy certificate to {node_extra_ca_certs}")
                        else:
                            self.print_info(f"Appending proxy certificate to {node_extra_ca_certs}")
                            self.safe_append_certificate(self.cert_path, node_extra_ca_certs)
            else:
                needs_setup = True
                self.print_info("Configuring Node.js certificate...")
                self.print_warn(f"NODE_EXTRA_CA_CERTS points to a non-existent file: {node_extra_ca_certs}")
                self.print_warn("Please fix this manually")
        else:
            needs_setup = True
            self.print_info("Configuring Node.js certificate...")
            # NODE_EXTRA_CA_CERTS not set, create a new bundle
            node_bundle = os.path.join(self.bundle_dir, "node/ca-bundle.pem")
            
            if not self.is_install_mode():
                self.print_action(f"Would create Node.js CA bundle at {node_bundle}")
                self.print_action("Would include proxy certificate in the bundle")
                self.print_action(f"Would set NODE_EXTRA_CA_CERTS={node_bundle}")
            else:
                self.print_info(f"Creating Node.js CA bundle at {node_bundle}")
                self._safe_makedirs(os.path.dirname(node_bundle))
                
                # Start with just the proxy certificate
                # (NODE_EXTRA_CA_CERTS supplements system certs, doesn't replace them)
                shutil.copy(self.cert_path, node_bundle)
                self._fix_ownership(node_bundle)

                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", node_bundle, shell_config)
                self.print_info("Created Node.js CA bundle with proxy certificate")
        
        # Setup npm cafile if npm is available
        if self.command_exists('npm'):
            self.setup_npm_cafile()

        # Cleanup stale yarn/pnpm configs that might override NODE_EXTRA_CA_CERTS
        self.cleanup_yarn_cafile()
        self.cleanup_pnpm_cafile()

    def setup_npm_cafile(self):
        """Setup npm cafile."""
        # Check current npm cafile setting
        try:
            result = subprocess.run(
                ['npm', 'config', 'get', 'cafile'],
                capture_output=True, text=True
            )
            current_cafile = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_cafile = ""
        
        # npm needs a full CA bundle, not just a single certificate
        npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
        needs_setup = False
        
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
                    self.safe_append_certificate(self.cert_path, npm_bundle)
                    subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                    self.print_info(f"Migrated npm cafile to: {npm_bundle}")
                return

            if os.path.exists(current_cafile):
                # First check if the existing cafile looks suspiciously small
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
                        self.safe_append_certificate(self.cert_path, npm_bundle)
                        subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                        self.print_info(f"Repointed npm cafile to managed bundle: {npm_bundle}")
                    return

                # Check if the file contains our certificate using normalized comparison
                if not self.certificate_exists_in_file(self.cert_path, current_cafile):
                    needs_setup = True
                    self.print_info("Configuring npm certificate...")
                    self.print_warn("Current npm cafile doesn't contain proxy certificate")
                    
                    # Check if we can write to the npm cafile
                    if not self.is_writable(current_cafile):
                        self.print_error(f"Cannot write to npm cafile: {current_cafile} (permission denied)")
                        self.print_warn(f"Will use alternative path: {npm_bundle}")
                        
                        if not self.is_install_mode():
                            self.print_action(f"Would create directory: {os.path.dirname(npm_bundle)}")
                            self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and proxy certificate")
                            self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                        else:
                            self._safe_makedirs(os.path.dirname(npm_bundle))
                            # Create a full bundle with system certs
                            if not self.create_bundle_with_system_certs(npm_bundle):
                                # Copy existing bundle if available
                                if os.path.exists(current_cafile):
                                    shutil.copy(current_cafile, npm_bundle)
                                    self._fix_ownership(npm_bundle)

                            # Append certificate to bundle
                            self.safe_append_certificate(self.cert_path, npm_bundle)

                            subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                            self.print_info(f"Created new npm cafile at {npm_bundle}")
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would ask to append proxy certificate to {current_cafile}")
                        else:
                            response = input("Do you want to append it to the existing cafile? (y/N) ")
                            if response.lower() == 'y':
                                self.print_info(f"Appending proxy certificate to {current_cafile}")
                                self.safe_append_certificate(self.cert_path, current_cafile)
            else:
                needs_setup = True
                self.print_info("Configuring npm certificate...")
                self.print_warn(f"npm cafile points to non-existent file: {current_cafile}")
                
                if not self.is_install_mode():
                    self.print_action(f"Would create full CA bundle at {npm_bundle}")
                    self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                else:
                    response = input("Do you want to create a new CA bundle for npm? (Y/n) ")
                    if response.lower() != 'n':
                        self._safe_makedirs(os.path.dirname(npm_bundle))
                        self.create_bundle_with_system_certs(npm_bundle)
                        self.safe_append_certificate(self.cert_path, npm_bundle)
                        subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                        self.print_info(f"Created and configured npm cafile at {npm_bundle}")
        else:
            needs_setup = True
            self.print_info("Configuring npm certificate...")
            self.print_info("npm cafile is not configured")
            
            if not self.is_install_mode():
                self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and proxy certificate")
                self.print_action(f"Would run: npm config set cafile {npm_bundle}")
            else:
                response = input("Do you want to configure npm with a CA bundle including proxy certificate? (Y/n) ")
                if response.lower() != 'n':
                    self._safe_makedirs(os.path.dirname(npm_bundle))
                    if not self.create_bundle_with_system_certs(npm_bundle):
                        self.print_warn("Could not find system CA bundle, creating new bundle with only proxy certificate")
                    self.safe_append_certificate(self.cert_path, npm_bundle)
                    subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                    self.print_info(f"Configured npm cafile to: {npm_bundle}")
                    
                    # Verify the setting
                    try:
                        result = subprocess.run(
                            ['npm', 'config', 'get', 'cafile'],
                            capture_output=True, text=True
                        )
                        verify_cafile = result.stdout.strip()
                        if verify_cafile == npm_bundle:
                            self.print_info("npm cafile configured successfully")
                        else:
                            self.print_error("Failed to configure npm cafile")
                    except Exception:
                        pass

    def cleanup_yarn_cafile(self):
        """Check and clean up yarn cafile configuration.

        Yarn respects NODE_EXTRA_CA_CERTS, so explicit cafile configs are
        usually unnecessary and often point to stale/broken paths from
        old scripts (like warp.sh) or manual configuration.
        """
        if not self.command_exists('yarn'):
            return

        try:
            # Detect yarn version (v1 vs Berry/v2+)
            result = subprocess.run(['yarn', '--version'], capture_output=True, text=True)
            yarn_version = result.stdout.strip()
            if not yarn_version:
                return
            is_berry = yarn_version[0] in ('2', '3', '4')

            # Get current cafile setting
            if is_berry:
                config_key = 'httpsCaFilePath'
                delete_cmd = ['yarn', 'config', 'unset', 'httpsCaFilePath']
            else:
                config_key = 'cafile'
                delete_cmd = ['yarn', 'config', 'delete', 'cafile']

            result = subprocess.run(['yarn', 'config', 'get', config_key],
                                   capture_output=True, text=True)
            current_cafile = result.stdout.strip()

            # Check if set to something problematic
            if not current_cafile or current_cafile in ['undefined', '']:
                return  # Not set, nothing to do

            # Check if it points to our managed npm bundle (that's fine)
            npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
            if current_cafile == npm_bundle:
                return  # Points to fumitm-managed bundle, that's OK

            # Check if file exists and contains WARP cert
            if os.path.exists(current_cafile) and self.certificate_exists_in_file(self.cert_path, current_cafile):
                return  # Working config, leave it

            # Problematic config - delete it
            self.print_info("Configuring yarn...")
            if not os.path.exists(current_cafile):
                self.print_warn(f"yarn {config_key} points to non-existent file: {current_cafile}")
            else:
                self.print_warn(f"yarn {config_key} doesn't contain proxy certificate: {current_cafile}")

            if not self.is_install_mode():
                self.print_action(f"Would remove yarn {config_key} config")
                self.print_action("NODE_EXTRA_CA_CERTS will handle certificate trust for yarn")
            else:
                subprocess.run(delete_cmd, capture_output=True)
                self.print_info(f"Removed yarn {config_key} config")
                self.print_info("yarn will now use NODE_EXTRA_CA_CERTS for certificate trust")
        except Exception as e:
            self.print_debug(f"Error checking yarn cafile: {e}")

    def cleanup_pnpm_cafile(self):
        """Check and clean up pnpm cafile configuration.

        pnpm respects NODE_EXTRA_CA_CERTS, so explicit cafile configs are
        usually unnecessary and often point to stale/broken paths.
        """
        if not self.command_exists('pnpm'):
            return

        try:
            result = subprocess.run(['pnpm', 'config', 'get', 'cafile'],
                                   capture_output=True, text=True)
            current_cafile = result.stdout.strip()

            if not current_cafile or current_cafile in ['undefined', '']:
                return  # Not set, nothing to do

            # Check if it points to our managed npm bundle (that's fine)
            npm_bundle = os.path.join(self.bundle_dir, "npm/ca-bundle.pem")
            if current_cafile == npm_bundle:
                return  # Points to fumitm-managed bundle, that's OK

            # Check if file exists and contains WARP cert
            if os.path.exists(current_cafile) and self.certificate_exists_in_file(self.cert_path, current_cafile):
                return  # Working config, leave it

            # Problematic config - delete it
            self.print_info("Configuring pnpm...")
            if not os.path.exists(current_cafile):
                self.print_warn(f"pnpm cafile points to non-existent file: {current_cafile}")
            else:
                self.print_warn(f"pnpm cafile doesn't contain proxy certificate: {current_cafile}")

            if not self.is_install_mode():
                self.print_action("Would remove pnpm cafile config")
                self.print_action("NODE_EXTRA_CA_CERTS will handle certificate trust for pnpm")
            else:
                subprocess.run(['pnpm', 'config', 'delete', 'cafile'], capture_output=True)
                self.print_info("Removed pnpm cafile config")
                self.print_info("pnpm will now use NODE_EXTRA_CA_CERTS for certificate trust")
        except Exception as e:
            self.print_debug(f"Error checking pnpm cafile: {e}")

    def setup_python_cert(self):
        """Setup Python certificate."""
        if not self.command_exists('python3') and not self.command_exists('python'):
            self.print_info("Python not found, skipping Python setup")
            return

        # Note: Unlike gcloud which uses a consistent system trust store, different
        # Python installations (system, Homebrew, venvs) may have different trust
        # configurations. We intentionally do NOT skip based on verify_connection()
        # because environment variables ensure ALL Python environments work, not just
        # the one running this script. Env vars are inherited by venvs and child processes.

        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)

        # Create combined certificate bundle for Python
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        needs_setup = False

        requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
        
        if requests_ca_bundle:
            if os.path.exists(requests_ca_bundle):
                # Check if we can write to the file
                if not self.is_writable(requests_ca_bundle):
                    self.print_error(f"Cannot write to {requests_ca_bundle} (permission denied)")
                    new_path = self.suggest_user_path(requests_ca_bundle, "python")
                    self.print_warn(f"Suggesting alternative path: {new_path}")
                    
                    if not self.is_install_mode():
                        self.print_action(f"Would create directory: {os.path.dirname(new_path)}")
                        self.print_action(f"Would copy {requests_ca_bundle} to {new_path}")
                        self.print_action(f"Would append proxy certificate to {new_path}")
                        self.print_action(f"Would update REQUESTS_CA_BUNDLE to point to {new_path}")
                    else:
                        response = input("Do you want to use this alternative path? (Y/n) ")
                        if response.lower() != 'n':
                            self._safe_makedirs(os.path.dirname(new_path))
                            if os.path.exists(requests_ca_bundle):
                                try:
                                    shutil.copy(requests_ca_bundle, new_path)
                                    self._fix_ownership(new_path)
                                except Exception:
                                    Path(new_path).touch()
                                    self._fix_ownership(new_path)

                            # Append certificate to the new path
                            self.safe_append_certificate(self.cert_path, new_path)

                            needs_setup = True
                            self.print_info("Configuring Python certificate...")
                            self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                            self.add_to_shell_config("REQUESTS_CA_BUNDLE", new_path, shell_config)
                            self.add_to_shell_config("SSL_CERT_FILE", new_path, shell_config)
                            self.add_to_shell_config("CURL_CA_BUNDLE", new_path, shell_config)
                            self.print_info(f"Created new certificate bundle at {new_path}")
                else:
                    # Check if the existing bundle looks suspicious (likely just WARP CA)
                    suspicious, reason = self.is_suspicious_full_bundle(requests_ca_bundle, self.cert_path)
                    if suspicious:
                        needs_setup = True
                        self.print_info("Configuring Python certificate...")
                        self.print_warn(f"REQUESTS_CA_BUNDLE looks suspiciously small ({reason})")
                        if not self.is_install_mode():
                            self.print_action(f"Would create full CA bundle at {python_bundle}")
                            self.print_action(f"Would repoint REQUESTS_CA_BUNDLE to {python_bundle}")
                        else:
                            self.create_bundle_with_system_certs(python_bundle)
                            self.safe_append_certificate(self.cert_path, python_bundle)
                            self.add_to_shell_config("REQUESTS_CA_BUNDLE", python_bundle, shell_config)
                            self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                            self.add_to_shell_config("CURL_CA_BUNDLE", python_bundle, shell_config)
                            self.print_info(f"Repointed REQUESTS_CA_BUNDLE to managed bundle: {python_bundle}")
                        return

                    # Check if the file contains our certificate using normalized comparison
                    if not self.certificate_exists_in_file(self.cert_path, requests_ca_bundle):
                        needs_setup = True
                        self.print_info("Configuring Python certificate...")
                        self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")

                        if not self.is_install_mode():
                            self.print_action(f"Would append proxy certificate to {requests_ca_bundle}")
                        else:
                            self.print_info(f"Appending proxy certificate to {requests_ca_bundle}")
                            self.safe_append_certificate(self.cert_path, requests_ca_bundle)
            else:
                needs_setup = True
                self.print_info("Configuring Python certificate...")
                self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                self.print_warn(f"REQUESTS_CA_BUNDLE points to a non-existent file: {requests_ca_bundle}")
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
                self.safe_append_certificate(self.cert_path, python_bundle)

            self.add_to_shell_config("REQUESTS_CA_BUNDLE", python_bundle, shell_config)
            self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
            self.add_to_shell_config("CURL_CA_BUNDLE", python_bundle, shell_config)

        # Independently check SSL_CERT_FILE for suspicious bundles
        # This handles the case where REQUESTS_CA_BUNDLE is fine but SSL_CERT_FILE is broken
        ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
        if ssl_cert_file and ssl_cert_file != python_bundle:
            if os.path.exists(ssl_cert_file):
                suspicious, reason = self.is_suspicious_full_bundle(ssl_cert_file, self.cert_path)
                if suspicious:
                    self.print_info("Configuring SSL_CERT_FILE...")
                    self.print_warn(f"SSL_CERT_FILE looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                    else:
                        # Ensure the managed bundle exists
                        if not os.path.exists(python_bundle):
                            self.create_bundle_with_system_certs(python_bundle)
                            self.safe_append_certificate(self.cert_path, python_bundle)
                        self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                        self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")
                elif not self.certificate_exists_in_file(self.cert_path, ssl_cert_file):
                    self.print_info("Configuring SSL_CERT_FILE...")
                    self.print_warn("SSL_CERT_FILE doesn't contain proxy certificate")
                    if not self.is_install_mode():
                        self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                    else:
                        if not os.path.exists(python_bundle):
                            self.create_bundle_with_system_certs(python_bundle)
                            self.safe_append_certificate(self.cert_path, python_bundle)
                        self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                        self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")
            else:
                self.print_info("Configuring SSL_CERT_FILE...")
                self.print_warn(f"SSL_CERT_FILE points to non-existent file: {ssl_cert_file}")
                if not self.is_install_mode():
                    self.print_action(f"Would repoint SSL_CERT_FILE to {python_bundle}")
                else:
                    if not os.path.exists(python_bundle):
                        self.create_bundle_with_system_certs(python_bundle)
                        self.safe_append_certificate(self.cert_path, python_bundle)
                    self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
                    self.print_info(f"Repointed SSL_CERT_FILE to managed bundle: {python_bundle}")

    def setup_gcloud_cert(self):
        """Setup gcloud certificate."""
        if not self.command_exists('gcloud'):
            self.print_info("gcloud not found, skipping gcloud setup")
            return

        # First check if gcloud already works (e.g., via system trust store)
        # If it works, don't add unnecessary configuration
        verify_result = self.verify_connection("gcloud")
        if verify_result == "WORKING":
            self.print_debug("gcloud already works via system trust, skipping configuration")
            return

        gcloud_cert_dir = os.path.expanduser("~/.config/gcloud/certs")
        gcloud_bundle = os.path.join(gcloud_cert_dir, "combined-ca-bundle.pem")
        needs_setup = False

        # Check current gcloud custom CA setting
        try:
            result = subprocess.run(
                ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                capture_output=True, text=True
            )
            current_ca_file = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca_file = ""
        
        # Check if gcloud needs configuration
        if not current_ca_file:
            needs_setup = True
        elif os.path.exists(current_ca_file):
            # First check if the existing CA file looks suspiciously small
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
                    self.safe_append_certificate(self.cert_path, gcloud_bundle)
                    subprocess.run(['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_bundle], capture_output=True, timeout=30)
                    self.print_info(f"Repointed gcloud custom CA file to managed bundle: {gcloud_bundle}")
                return

            # Check if current CA file contains our certificate using normalized comparison
            if not self.certificate_exists_in_file(self.cert_path, current_ca_file):
                needs_setup = True
        else:
            needs_setup = True

        if not needs_setup:
            return

        self.print_info("Configuring gcloud certificate...")
        
        # Create directory if it doesn't exist
        if self.is_install_mode():
            self._safe_makedirs(gcloud_cert_dir)
        
        if current_ca_file and current_ca_file != gcloud_bundle:
            self.print_warn(f"gcloud is already configured with custom CA: {current_ca_file}")
            
            # Check if the current CA file is writable
            if os.path.exists(current_ca_file) and not self.is_writable(current_ca_file):
                self.print_error(f"Cannot write to current gcloud CA file: {current_ca_file} (permission denied)")
                self.print_warn(f"Will use alternative path: {gcloud_bundle}")
                if not self.is_install_mode():
                    self.print_action(f"Would create new gcloud CA bundle at {gcloud_bundle}")
                # Continue with the new path
            else:
                if not self.is_install_mode():
                    self.print_action("Would ask to update gcloud CA configuration")
                    return
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() != 'y':
                        return
        
        if not self.is_install_mode():
            self.print_action(f"Would create directory: {gcloud_cert_dir}")
            self.print_action(f"Would create gcloud CA bundle at {gcloud_bundle}")
            self.print_action("Would copy system certificates and append proxy certificate")
            self.print_action(f"Would run: gcloud config set core/custom_ca_certs_file {gcloud_bundle}")
        else:
            # Create combined bundle
            self.print_info(f"Creating gcloud CA bundle at {gcloud_bundle}")
            self.create_bundle_with_system_certs(gcloud_bundle)
            self.safe_append_certificate(self.cert_path, gcloud_bundle)

            # Configure gcloud
            result = subprocess.run(
                ['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_bundle],
                capture_output=True,
                timeout=30  # Add timeout to prevent hanging
            )
            if result.returncode == 0:
                self.print_info("gcloud configured successfully")
                # Skip diagnostics in devcontainers as they can hang
                if needs_setup and not self.is_devcontainer():
                    self.print_info("Running gcloud diagnostics...")
                    try:
                        subprocess.run(['gcloud', 'info', '--run-diagnostics'], timeout=10)
                    except subprocess.TimeoutExpired:
                        self.print_warn("gcloud diagnostics timed out, skipping")
            else:
                self.print_error("Failed to configure gcloud")

    def setup_git_cert(self):
        """Setup Git sslCAInfo to a managed full bundle."""
        if not self.command_exists('git'):
            return
        git_bundle = os.path.join(self.bundle_dir, "git/ca-bundle.pem")
        # Check current setting
        try:
            result = subprocess.run(['git', 'config', '--global', 'http.sslCAInfo'], capture_output=True, text=True)
            current_ca = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca = ""
        # Decide whether to repoint
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
                # Path missing — don't configure by default; Git uses system trust store
                return
        else:
            # Not set — Git uses system trust store when not configured
            return
        if not repoint:
            return
        if not self.is_install_mode():
            self.print_action(f"Would create Git CA bundle at {git_bundle}")
            self.print_action(f"Would run: git config --global http.sslCAInfo {git_bundle}")
            return
        # Build full bundle and configure
        self._safe_makedirs(os.path.dirname(git_bundle))
        self.create_bundle_with_system_certs(git_bundle)
        self.safe_append_certificate(self.cert_path, git_bundle)
        subprocess.run(['git', 'config', '--global', 'http.sslCAInfo', git_bundle], capture_output=True, text=True)
        self.print_info(f"Configured git http.sslCAInfo to: {git_bundle}")

    def setup_curl_cert(self):
        """Setup curl certificate configuration.

        Handles multiple scenarios:
        1. curl works via system trust (SecureTransport on macOS) - skip
        2. CURL_CA_BUNDLE points to suspicious/broken bundle - fix it
        3. CURL_CA_BUNDLE points to non-existent file - fix it
        4. curl fails with no CURL_CA_BUNDLE set - configure it
        """
        if not self.command_exists('curl'):
            return

        # First check if curl already works (e.g., via system trust store)
        # If it works, don't add unnecessary configuration
        verify_result = self.verify_connection("curl")
        if verify_result == "WORKING":
            self.print_debug("curl already works via system trust, skipping configuration")
            return

        curl_bundle = os.path.join(self.bundle_dir, "curl/ca-bundle.pem")
        curl_env = os.environ.get('CURL_CA_BUNDLE', '')

        # Case 1: CURL_CA_BUNDLE is set — check for provider mismatch first
        if curl_env:
            other_provider = self._path_belongs_to_other_provider(curl_env)
            if other_provider:
                self.print_info("Configuring curl certificate bundle...")
                self.print_info(f"CURL_CA_BUNDLE points to previous provider ({other_provider}): {curl_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                    self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                    return
            elif not os.path.exists(curl_env):
                self.print_info("Configuring curl certificate bundle...")
                self.print_warn(f"CURL_CA_BUNDLE points to non-existent file: {curl_env}")
                if not self.is_install_mode():
                    self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                    self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                    return
            else:
                suspicious, reason = self.is_suspicious_full_bundle(curl_env, self.cert_path)
                if suspicious:
                    self.print_info("Configuring curl certificate bundle...")
                    self.print_warn(f"Existing CURL_CA_BUNDLE looks suspiciously small ({reason})")
                    if not self.is_install_mode():
                        self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                        self.print_action(f"Would repoint CURL_CA_BUNDLE to {curl_bundle}")
                        return
                else:
                    # Bundle exists and looks OK but curl still doesn't work
                    # This might be a different issue - don't touch it
                    self.print_warn("curl connection failed but CURL_CA_BUNDLE looks valid")
                    self.print_info("This may require manual investigation")
                    return
        else:
            # Case 2: No CURL_CA_BUNDLE set and curl doesn't work
            self.print_info("Configuring curl certificate bundle...")
            if not self.is_install_mode():
                self.print_action(f"Would create curl CA bundle at {curl_bundle}")
                self.print_action(f"Would set CURL_CA_BUNDLE={curl_bundle}")
                return

        # Create the bundle and configure
        self._safe_makedirs(os.path.dirname(curl_bundle))
        self.create_bundle_with_system_certs(curl_bundle)
        self.safe_append_certificate(self.cert_path, curl_bundle)
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        self.add_to_shell_config("CURL_CA_BUNDLE", curl_bundle, shell_config)
        self.print_info(f"Configured CURL_CA_BUNDLE to: {curl_bundle}")

    def check_git_status(self, temp_warp_cert):
        """Check Git configuration status for http.sslCAInfo."""
        has_issues = False
        if self.command_exists('git'):
            try:
                result = subprocess.run(['git', 'config', '--global', 'http.sslCAInfo'], capture_output=True, text=True)
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
                    self.print_info("  - http.sslCAInfo not configured (uses system trust store)")
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
            # First, verify if curl can actually connect
            verify_result = self.verify_connection("curl")

            if verify_result == "WORKING":
                self.print_info("  ✓ curl can connect through proxy")

                # Check if it's using SecureTransport (macOS system curl)
                try:
                    result = subprocess.run(['curl', '--version'], capture_output=True, text=True)
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
                            # Check if the bundle is suspicious
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
                # curl doesn't work, check configuration
                curl_bundle = os.environ.get('CURL_CA_BUNDLE', '')
                if curl_bundle:
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

    def get_jenv_java_homes(self):
        """Get unique Java home directories from jenv.

        Returns:
            list: List of unique physical JDK installation paths
        """
        if not self.command_exists('jenv'):
            return []

        try:
            result = subprocess.run(
                ['jenv', 'versions', '--verbose'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return []

            java_homes = set()
            for line in result.stdout.splitlines():
                # Look for lines with --> which indicate symlink targets
                if '-->' in line:
                    # Extract path after -->
                    path = line.split('-->')[1].strip()
                    if not path:
                        continue
                    # Validate that this is actually a JDK by checking for
                    # cacerts. The "system" entry often resolves to the CWD
                    # or user home when no system Java is configured.
                    cacerts = os.path.join(path, 'lib', 'security', 'cacerts')
                    jre_cacerts = os.path.join(path, 'jre', 'lib', 'security', 'cacerts')
                    if os.path.exists(cacerts) or os.path.exists(jre_cacerts):
                        java_homes.add(path)

            return sorted(list(java_homes))
        except Exception as e:
            self.print_debug(f"Error getting jenv Java homes: {e}")
            return []

    def setup_java_cert(self):
        """Setup Java certificate for all detected installations."""
        if not self.command_exists('java') and not self.command_exists('keytool'):
            return

        # Find all Java installations
        java_homes = self.find_all_java_homes()

        if not java_homes:
            self.print_warn("No Java installations found")
            return

        # Show count if multiple installations found
        if len(java_homes) > 1:
            self.print_info(f"Found {len(java_homes)} Java installation(s)")

        # Process each Java installation
        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"  ✗ {version_name}: Could not find cacerts file")
                continue

            # Check if certificate already exists
            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True
                )
                if result.returncode == 0 and self.provider['keytool_alias'] in result.stdout.decode():
                    self.print_info(f"  ✓ {version_name}: Certificate already installed")
                    continue
            except Exception:
                pass

            self.print_info(f"  Configuring {version_name}...")

            if not self.is_install_mode():
                self.print_action(f"    Would import certificate to: {cacerts}")
            else:
                result = subprocess.run(
                    ['keytool', '-import', '-trustcacerts', '-alias', self.provider['keytool_alias'],
                     '-file', self.cert_path, '-keystore', cacerts, '-storepass', 'changeit', '-noprompt'],
                    capture_output=True
                )
                if result.returncode == 0:
                    self.print_info(f"    ✓ {version_name}: Certificate added successfully")
                else:
                    self.print_warn(f"    ✗ {version_name}: Failed to add certificate (may require sudo)")
                    self.print_info( "      Fix with:")
                    print(f"        sudo keytool -import -trustcacerts \\")
                    print(f"          -alias {self.provider['keytool_alias']} \\")
                    print(f"          -file {self.cert_path} \\")
                    print(f"          -keystore {cacerts} \\")
                    print( "          -storepass changeit -noprompt")

    def setup_jenv_cert(self):
        """Setup Java certificates for all jenv-managed Java installations."""
        java_homes = self.get_jenv_java_homes()

        if not java_homes:
            return

        if not self.command_exists('keytool'):
            self.print_warn("keytool not found, cannot configure jenv Java installations")
            return

        self.print_info(f"Found {len(java_homes)} jenv-managed Java installation(s)")

        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = os.path.join(java_home, "lib/security/cacerts")
            if not os.path.exists(cacerts):
                cacerts = os.path.join(java_home, "jre/lib/security/cacerts")

            if not os.path.exists(cacerts):
                self.print_warn(f"  Skipping {version_name}: cacerts file not found at {cacerts}")
                continue

            # Check if certificate already exists
            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True
                )
                if result.returncode == 0 and self.provider['keytool_alias'] in result.stdout.decode():
                    # Certificate already exists
                    self.print_info(f"  ✓ {version_name}: Certificate already installed")
                    continue
            except Exception:
                pass

            self.print_info(f"  Installing certificate for {version_name}...")

            if not self.is_install_mode():
                self.print_action(f"    Would import certificate to: {cacerts}")
            else:
                result = subprocess.run(
                    ['keytool', '-import', '-trustcacerts', '-alias', self.provider['keytool_alias'],
                     '-file', self.cert_path, '-keystore', cacerts, '-storepass', 'changeit', '-noprompt'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.print_info(f"    ✓ {version_name}: Certificate added successfully")
                else:
                    self.print_warn(f"    ✗ {version_name}: Failed to add certificate (may require sudo)")
                    self.print_info( "      Fix with:")
                    print(f"        sudo keytool -import -trustcacerts \\")
                    print(f"          -alias {self.provider['keytool_alias']} \\")
                    print(f"          -file {self.cert_path} \\")
                    print(f"          -keystore {cacerts} \\")
                    print( "          -storepass changeit -noprompt")
                    if len(result.stdout) > 0:
                        self.print_warn(f"      Keytool response: {result.stdout}")

    def setup_gradle_cert(self):
        """Setup Gradle certificate configuration."""
        gradle_props = self.get_gradle_properties_path()

        if not self.command_exists('gradle') and not os.path.exists(gradle_props):
            return

        cacerts = self.find_java_cacerts()
        if not cacerts:
            self.print_error("Could not find Java cacerts file for Gradle")
            return

        props_to_set = {
            'systemProp.javax.net.ssl.trustStore': cacerts,
            'systemProp.javax.net.ssl.trustStorePassword': 'changeit',
            'systemProp.https.protocols': 'TLSv1.2'
        }

        self.update_properties_file(gradle_props, props_to_set, "Gradle properties")

    def setup_dbeaver_cert(self):
        """Setup DBeaver certificate."""
        dbeaver_keytool = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/bin/keytool"
        dbeaver_cacerts = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
        
        # Check if DBeaver is installed at the default location
        if not os.path.exists(dbeaver_keytool):
            return
        
        # Check if the cacerts file exists
        if not os.path.exists(dbeaver_cacerts):
            self.print_error(f"DBeaver cacerts file not found at: {dbeaver_cacerts}")
            return
        
        # Check if certificate already exists
        try:
            result = subprocess.run(
                [dbeaver_keytool, '-list', '-alias', self.provider['keytool_alias'], 
                 '-keystore', dbeaver_cacerts, '-storepass', 'changeit'],
                capture_output=True
            )
            if result.returncode == 0 and self.provider['keytool_alias'] in result.stdout.decode():
                # Certificate already exists, nothing to do
                return
        except Exception:
            pass
        
        self.print_info("Configuring DBeaver certificate...")
        self.print_info("Found DBeaver at default install location")
        
        if not self.is_install_mode():
            self.print_action(f"Would import certificate to DBeaver keystore: {dbeaver_cacerts}")
            self.print_action(f"Would run: {dbeaver_keytool} -import -trustcacerts -alias {self.provider['keytool_alias']} -file {self.cert_path} -keystore {dbeaver_cacerts} -storepass changeit -noprompt")
        else:
            self.print_info("Adding certificate to DBeaver keystore...")
            result = subprocess.run(
                [dbeaver_keytool, '-import', '-trustcacerts', '-alias', self.provider['keytool_alias'],
                 '-file', self.cert_path, '-keystore', dbeaver_cacerts, '-storepass', 'changeit', '-noprompt'],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info("Certificate added to DBeaver keystore successfully")
            else:
                self.print_warn("Failed to add certificate to DBeaver keystore (may require sudo)")
                self.print_info( "      Fix with:")
                print(f"        sudo {dbeaver_keytool} -import -trustcacerts \\")
                print(f"          -alias {self.provider['keytool_alias']} \\")
                print(f"          -file {self.cert_path} \\")
                print(f"          -keystore {dbeaver_cacerts} \\")
                print( "          -storepass changeit -noprompt")
                if len(result.stdout) > 0:
                    self.print_warn(f"Keytool response: {result.stdout.decode('utf-8')}")
    
    def setup_wget_cert(self):
        """Setup wget certificate."""
        if not self.command_exists('wget'):
            return

        # First check if wget already works (e.g., via system trust store)
        # If it works, don't add unnecessary configuration
        verify_result = self.verify_connection("wget")
        if verify_result == "WORKING":
            self.print_debug("wget already works via system trust, skipping configuration")
            return

        wgetrc_path = os.path.expanduser("~/.wgetrc")
        config_line = f"ca_certificate={self.cert_path}"

        if os.path.exists(wgetrc_path):
            with open(wgetrc_path, 'r') as f:
                content = f.read()
            
            if "ca_certificate=" in content:
                # Check if it's already set to our certificate
                if self.cert_path in content:
                    return
                
                self.print_info("Configuring wget certificate...")
                self.print_warn(f"wget ca_certificate is already set in {wgetrc_path}")
                
                # Find current setting
                for line in content.splitlines():
                    if line.strip().startswith("ca_certificate="):
                        self.print_info(f"Current setting: {line.strip()}")
                        break
                
                if not self.is_install_mode():
                    self.print_action(f"Would ask to update the ca_certificate in {wgetrc_path}")
                    self.print_action(f"Would set: {config_line}")
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() == 'y':
                        # Comment out old entries
                        lines = content.splitlines()
                        new_lines = []
                        for line in lines:
                            if line.strip().startswith("ca_certificate="):
                                new_lines.append(f"#{line}")
                            else:
                                new_lines.append(line)
                        
                        # Add new entry
                        new_lines.append(config_line)
                        
                        # Write back
                        with open(wgetrc_path + '.bak', 'w') as f:
                            f.write(content)
                        with open(wgetrc_path, 'w') as f:
                            f.write('\n'.join(new_lines) + '\n')
                        
                        self.print_info(f"Updated wget configuration in {wgetrc_path}")
                return
        
        # File doesn't exist or doesn't have ca_certificate
        self.print_info("Configuring wget certificate...")
        
        if not self.is_install_mode():
            self.print_action(f"Would add to {wgetrc_path}: {config_line}")
        else:
            self.print_info(f"Adding configuration to {wgetrc_path}")
            with open(wgetrc_path, 'a') as f:
                f.write(f"\n{config_line}\n")
            self.print_info("Added ca_certificate to wget configuration")
    
    def setup_podman_cert(self):
        """Setup Podman certificate.

        Uses a hybrid approach:
        1. Always installs to ~/.docker/certs.d/ (well-known Docker location)
        2. If Podman machine is running, also installs into VM for immediate effect
        """
        if not self.command_exists('podman'):
            return

        # Primary method: Install to ~/.docker/certs.d/ (shared with other container tools)
        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        # Check if certificate is already installed with correct content
        if os.path.exists(cert_dest) and self.certificate_likely_exists_in_file(self.cert_path, cert_dest):
            self.print_debug("Podman certificate already installed, skipping configuration")
            return

        self.print_info("Configuring Podman certificate...")

        # Check if VM is currently running
        try:
            result = subprocess.run(['podman', 'machine', 'list'], capture_output=True, text=True)
            vm_is_running = 'Currently running' in result.stdout
        except Exception:
            vm_is_running = False

        if not self.is_install_mode():
            self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running:
                self.print_action("Would also install certificate into running Podman VM for immediate effect")
        else:
            # Create directory and copy certificate (persistent location)
            self._safe_makedirs(docker_certs_dir)
            shutil.copy(self.cert_path, cert_dest)
            self._fix_ownership(cert_dest)
            self.print_info(f"Certificate installed to {cert_dest}")

            # If VM is running, also install for immediate effect
            if vm_is_running:
                self.print_info("Podman machine is running - also installing certificate into VM...")

                with open(self.cert_path, 'r') as f:
                    cert_content = f.read()

                result = subprocess.run(
                    ['podman', 'machine', 'ssh', f'sudo tee /etc/pki/ca-trust/source/anchors/{self.provider["container_cert_name"]}.pem'],
                    input=cert_content, text=True, capture_output=True
                )

                if result.returncode == 0:
                    # Update CA trust
                    result = subprocess.run(
                        ['podman', 'machine', 'ssh', 'sudo update-ca-trust'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("Certificate installed in VM - Podman is ready")
                    else:
                        self.print_warn("Certificate copied to VM but failed to update CA trust")
                        self.print_info("Try: podman machine ssh 'sudo update-ca-trust'")
                else:
                    self.print_warn("Failed to install certificate into running VM")
                    self.print_info("Certificate in ~/.docker/certs.d/ will be available for future use")
            else:
                self.print_info("Podman machine is not running")
                self.print_info("Run 'podman machine start' then re-run fumitm to install into VM")
    
    def setup_rancher_cert(self):
        """Setup Rancher Desktop certificate.

        Uses a hybrid approach:
        1. Always installs to ~/.docker/certs.d/ (well-known Docker location)
        2. If Rancher Desktop is running, also installs into VM for immediate effect
        """
        if not self.command_exists('rdctl'):
            return

        # Primary method: Install to ~/.docker/certs.d/ (shared with other container tools)
        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        # Check if certificate is already installed with correct content
        if os.path.exists(cert_dest) and self.certificate_likely_exists_in_file(self.cert_path, cert_dest):
            self.print_debug("Rancher Desktop certificate already installed, skipping configuration")
            return

        self.print_info("Configuring Rancher Desktop certificate...")

        # Check if Rancher Desktop is running
        try:
            result = subprocess.run(['rdctl', 'version'], capture_output=True, text=True)
            vm_is_running = result.returncode == 0
        except Exception:
            vm_is_running = False

        if not self.is_install_mode():
            self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running:
                self.print_action("Would also install certificate into running Rancher Desktop VM for immediate effect")
        else:
            # Create directory and copy certificate (persistent location)
            self._safe_makedirs(docker_certs_dir)
            shutil.copy(self.cert_path, cert_dest)
            self._fix_ownership(cert_dest)
            self.print_info(f"Certificate installed to {cert_dest}")

            # If VM is running, also install for immediate effect
            if vm_is_running:
                self.print_info("Rancher Desktop is running - also installing certificate into VM...")

                with open(self.cert_path, 'r') as f:
                    cert_content = f.read()

                result = subprocess.run(
                    ['rdctl', 'shell', 'sudo', 'tee', f'/usr/local/share/ca-certificates/{self.provider["container_cert_name"]}.pem'],
                    input=cert_content, text=True, capture_output=True
                )

                if result.returncode == 0:
                    # Update CA certificates
                    result = subprocess.run(
                        ['rdctl', 'shell', 'sudo', 'update-ca-certificates'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("Certificate installed in VM - Rancher Desktop is ready")
                    else:
                        self.print_warn("Certificate copied to VM but failed to update CA certificates")
                        self.print_info("Try: rdctl shell sudo update-ca-certificates")
                else:
                    self.print_warn("Failed to install certificate into running VM")
                    self.print_info("Certificate in ~/.docker/certs.d/ will be available for future use")
            else:
                self.print_info("Rancher Desktop is not running")
                self.print_info("Start Rancher Desktop then re-run fumitm to install into VM")
    
    def setup_android_emulator_cert(self):
        """Setup Android Emulator certificate."""
        if not self.command_exists('adb') or not self.command_exists('emulator'):
            self.print_info("Android SDK tools not found, skipping Android Emulator setup")
            return
        
        self.print_info("Checking for Android Emulator setup...")
        
        # Check if any emulator is running
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            running_devices = sum(1 for line in result.stdout.splitlines() if 'emulator-' in line)
            
            if running_devices == 0:
                self.print_info("No Android emulator is currently running")
                self.print_info("Please start an emulator with: emulator -avd <your_avd_id> -writable-system -selinux permissive")
                return
        except Exception:
            return
        
        self.print_warn("Android Emulator certificate installation requires a writable system partition")
        self.print_warn("Make sure your emulator was started with -writable-system flag")
        
        if not self.is_install_mode():
            self.print_action("Would restart ADB with root permissions: adb root")
            self.print_action("Would remount system partition: adb remount")
            self.print_action(f"Would push certificate to emulator: adb push {self.cert_path} /system/etc/security/cacerts/{self.provider['container_cert_name']}.pem")
            self.print_action(f"Would set permissions: adb shell chmod 644 /system/etc/security/cacerts/{self.provider['container_cert_name']}.pem")
            self.print_action("Would reboot emulator: adb reboot")
        else:
            response = input("Do you want to install the certificate on the running Android emulator? (y/N) ")
            if response.lower() == 'y':
                self.print_info("Installing certificate on Android emulator...")
                
                # Restart ADB with root
                result = subprocess.run(['adb', 'root'], capture_output=True)
                if result.returncode != 0:
                    self.print_error("Failed to restart ADB with root permissions")
                    self.print_info("Make sure your emulator doesn't have Google Play Store")
                    return
                
                # Remount system partition
                result = subprocess.run(['adb', 'remount'], capture_output=True)
                if result.returncode != 0:
                    self.print_error("Failed to remount system partition")
                    self.print_info("Make sure emulator was started with -writable-system flag")
                    return
                
                # Push certificate
                result = subprocess.run(
                    ['adb', 'push', self.cert_path, f'/system/etc/security/cacerts/{self.provider["container_cert_name"]}.pem'],
                    capture_output=True
                )
                if result.returncode == 0:
                    # Set permissions
                    subprocess.run(
                        ['adb', 'shell', 'chmod', '644', f'/system/etc/security/cacerts/{self.provider["container_cert_name"]}.pem'],
                        capture_output=True
                    )
                    self.print_info("Certificate installed. Rebooting emulator...")
                    subprocess.run(['adb', 'reboot'], capture_output=True)
                    self.print_info("Android emulator certificate installed successfully")
                else:
                    self.print_error("Failed to push certificate to emulator")
    
    def setup_colima_cert(self):
        """Setup Colima certificate.

        Uses a hybrid approach:
        1. Always installs to ~/.docker/certs.d/ (persistent, works offline)
        2. If Colima is running, also installs into the VM for immediate effect

        The ~/.docker/certs.d/ directory is automatically mounted by Colima
        and certificates there are applied on VM startup.
        """
        if not self.command_exists('colima'):
            return

        # Primary method: Install to ~/.docker/certs.d/ (persistent, works offline)
        # Colima automatically mounts this directory and applies certs on startup
        docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
        cert_dest = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

        # Check if certificate is already installed with correct content
        if os.path.exists(cert_dest) and self.certificate_likely_exists_in_file(self.cert_path, cert_dest):
            self.print_debug("Colima certificate already installed, skipping configuration")
            return

        self.print_info("Configuring Colima certificate...")

        # Check if VM is currently running
        try:
            status_result = subprocess.run(['colima', 'status'], capture_output=True)
            vm_is_running = (status_result.returncode == 0)
        except Exception:
            vm_is_running = False

        if not self.is_install_mode():
            self.print_action(f"Would copy certificate to {cert_dest} (persistent)")
            if vm_is_running:
                self.print_action("Would also install certificate into running VM for immediate effect")
        else:
            # Create directory and copy certificate (persistent location)
            self._safe_makedirs(docker_certs_dir)
            shutil.copy(self.cert_path, cert_dest)
            self._fix_ownership(cert_dest)
            self.print_info(f"Certificate installed to {cert_dest}")
            self.print_info("This certificate will be automatically loaded on Colima start")

            # If VM is running, also install for immediate effect
            if vm_is_running:
                self.print_info("Colima is running - also installing certificate into VM...")

                with open(self.cert_path, 'r') as f:
                    cert_content = f.read()

                result = subprocess.run(
                    ['colima', 'ssh', '--', 'sudo', 'tee', f'/usr/local/share/ca-certificates/{self.provider["container_cert_name"]}.crt'],
                    input=cert_content, text=True, capture_output=True
                )

                if result.returncode == 0:
                    # Update CA certificates
                    result = subprocess.run(
                        ['colima', 'ssh', '--', 'sudo', 'update-ca-certificates'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("Certificate installed in VM. Restarting Docker daemon...")
                        # Restart Docker daemon to pick up new certificates
                        result = subprocess.run(
                            ['colima', 'ssh', '--', 'sudo', 'systemctl', 'restart', 'docker'],
                            capture_output=True
                        )
                        if result.returncode == 0:
                            self.print_info("Docker daemon restarted - certificate is now active")
                        else:
                            self.print_warn("Certificate installed but failed to restart Docker daemon")
                            self.print_info("Restart Colima or run: colima ssh -- sudo systemctl restart docker")
                    else:
                        self.print_warn("Failed to update CA certificates in VM")
                        self.print_info("Certificate in ~/.docker/certs.d/ will be applied on next Colima restart")
                else:
                    self.print_warn("Failed to install certificate into running VM")
                    self.print_info("Certificate in ~/.docker/certs.d/ will be applied on next Colima restart")
            else:
                self.print_info("Colima is not running - certificate will be applied on next start")
    
    def verify_connection(self, tool_name):
        """Verify if a tool can connect through proxy."""
        # Skip verification if requested or in devcontainer
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
                
                # Test SSL connection
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
                        capture_output=True, text=True
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
            # Check if Python trusts the system proxy certificate
            self.print_info("Checking if Python trusts system proxy certificate...")
            
            try:
                # Create a simple HTTPS request
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                
                # Try to open the URL
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.print_debug(f"Success - HTTP {response.code}")
                    result = "WORKING"
                    
                    # Additional validation - check SSL context
                    context = ssl.create_default_context()
                    self.print_debug(f"Python SSL default verify paths: {ssl.get_default_verify_paths()}")
                    self.print_debug("Python successfully trusts the system proxy certificate")
                    
            except urllib.error.HTTPError as e:
                self.print_debug(f"HTTP Error {e.code} - but SSL worked")
                # HTTP errors (like 403) are OK - we're testing SSL
                result = "WORKING"
            except urllib.error.URLError as e:
                self.print_debug(f"URL Error: {e.reason}")
                # SSL errors mean the cert isn't trusted
                result = "FAILED"
                
                # Check if REQUESTS_CA_BUNDLE or SSL_CERT_FILE would help
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
                        capture_output=True, text=True
                    )
                    self.print_debug(f"curl version: {version_result.stdout.splitlines()[0]}")
                    
                    # Test connection
                    if self.is_debug_mode():
                        curl_result = subprocess.run(
                            ['curl', '-v', '-s', '-o', '/dev/null', test_url],
                            capture_output=True, text=True
                        )
                    else:
                        curl_result = subprocess.run(
                            ['curl', '-s', '-o', '/dev/null', test_url],
                            capture_output=True
                        )
                    
                    if curl_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("curl test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"curl test failed with exit code: {curl_result.returncode}")
                    
                    if self.is_debug_mode() and curl_result.stderr:
                        # Show relevant SSL info
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
                            capture_output=True, text=True
                        )
                    else:
                        wget_result = subprocess.run(
                            ['wget', '-q', '-O', '/dev/null', test_url],
                            capture_output=True
                        )
                    
                    if wget_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("wget test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"wget test failed with exit code: {wget_result.returncode}")
                    
                    if self.is_debug_mode() and wget_result.stderr:
                        # Show relevant SSL info
                        for line in wget_result.stderr.splitlines():
                            if any(keyword in line for keyword in ['SSL', 'certificate', 'CA']):
                                self.print_debug(f"wget: {line}")
                except Exception as e:
                    self.print_debug(f"wget test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"

        elif tool_name == "gcloud":
            if self.command_exists('gcloud'):
                self.print_debug(f"gcloud found at: {shutil.which('gcloud')}")

                try:
                    # Use 'gcloud projects list --limit=1' which makes a real HTTPS call
                    # to GCP APIs. This verifies TLS connectivity even if the user lacks
                    # permissions or isn't authenticated - we just need the SSL handshake
                    # to succeed.
                    gcloud_result = subprocess.run(
                        ['gcloud', 'projects', 'list', '--limit=1'],
                        capture_output=True, text=True, timeout=15
                    )

                    # Check for SSL-specific errors in stderr
                    stderr_lower = gcloud_result.stderr.lower()
                    if 'ssl' in stderr_lower or 'certificate' in stderr_lower:
                        result = "FAILED"
                        self.print_debug(f"gcloud SSL error: {gcloud_result.stderr}")
                    else:
                        # Any response (success, permission denied, not authenticated)
                        # means TLS connectivity is working
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
                    if self.certificate_exists_in_file(temp_warp_cert, node_extra_ca_certs):
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
            
            # Check npm
            if self.command_exists('npm'):
                try:
                    result = subprocess.run(['npm', 'config', 'get', 'cafile'], capture_output=True, text=True)
                    npm_cafile = result.stdout.strip() if result.returncode == 0 else ""
                    
                    if npm_cafile and npm_cafile not in ["null", "undefined"]:
                        other_provider = self._path_belongs_to_other_provider(npm_cafile)
                        if other_provider:
                            self.print_warn(f"  ⚠ npm cafile points to a previous provider's path ({other_provider})")
                            self.print_action("    Run with --fix to migrate to the current provider's bundle")
                            has_issues = True
                        elif os.path.exists(npm_cafile):
                            if self.certificate_exists_in_file(temp_warp_cert, npm_cafile):
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

            # Check yarn for stale cafile config
            if self.command_exists('yarn'):
                try:
                    result = subprocess.run(['yarn', '--version'], capture_output=True, text=True)
                    yarn_version = result.stdout.strip()
                    is_berry = yarn_version and yarn_version[0] in ('2', '3', '4')
                    config_key = 'httpsCaFilePath' if is_berry else 'cafile'

                    result = subprocess.run(['yarn', 'config', 'get', config_key],
                                           capture_output=True, text=True)
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
                            if self.certificate_exists_in_file(temp_warp_cert, yarn_cafile):
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

            # Check pnpm for stale cafile config
            if self.command_exists('pnpm'):
                try:
                    result = subprocess.run(['pnpm', 'config', 'get', 'cafile'],
                                           capture_output=True, text=True)
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
                            if self.certificate_exists_in_file(temp_warp_cert, pnpm_cafile):
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
            # First check if Python trusts the system certificate
            python_verify_result = self.verify_connection("python")
            
            if python_verify_result == "WORKING":
                self.print_info("  ✓ Python trusts the system proxy certificate")
                self.print_info("  ✓ Python can connect through proxy without additional configuration")
            else:
                # Python doesn't trust system cert, check environment variables
                python_configured = False
                
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if requests_ca_bundle:
                    self.print_info(f"  REQUESTS_CA_BUNDLE is set to: {requests_ca_bundle}")
                    if os.path.exists(requests_ca_bundle):
                        if self.certificate_exists_in_file(temp_warp_cert, requests_ca_bundle):
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

                # Also check SSL_CERT_FILE if set
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if ssl_cert_file:
                    self.print_info(f"  SSL_CERT_FILE is set to: {ssl_cert_file}")
                    if os.path.exists(ssl_cert_file):
                        if self.certificate_exists_in_file(temp_warp_cert, ssl_cert_file):
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
            # First, verify if gcloud can actually connect
            verify_result = self.verify_connection("gcloud")

            if verify_result == "WORKING":
                self.print_info("  ✓ gcloud can connect through proxy")

                # Check if custom CA is configured (informational only)
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        self.print_info(f"  - Custom CA configured at: {gcloud_ca}")
                        if self.certificate_exists_in_file(temp_warp_cert, gcloud_ca):
                            self.print_info("  ✓ Custom CA contains current certificate")
                    else:
                        self.print_info("  - Using system certificate trust (no custom CA needed)")
                except Exception:
                    self.print_info("  - Using system certificate trust")
            elif verify_result == "SKIPPED":
                # Can't verify, fall back to config check
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        if self.certificate_exists_in_file(temp_warp_cert, gcloud_ca):
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
                # gcloud can't connect - check if custom CA would help
                self.print_warn("  ✗ gcloud connection test failed")
                try:
                    result = subprocess.run(
                        ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                        capture_output=True, text=True
                    )
                    gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                    if gcloud_ca and os.path.exists(gcloud_ca):
                        if self.certificate_exists_in_file(temp_warp_cert, gcloud_ca):
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

        # Find all Java installations
        java_homes = self.find_all_java_homes()

        if not java_homes:
            self.print_warn("  ✗ No Java installations found")
            return True

        # Show count if multiple installations
        if len(java_homes) > 1:
            self.print_info(f"  Checking {len(java_homes)} Java installation(s):")

        # Check each installation
        for java_home in java_homes:
            version_name = self.java_version_label(java_home)

            cacerts = self.find_java_cacerts(java_home)
            if not cacerts:
                self.print_warn(f"  ✗ {version_name}: cacerts file not found")
                has_issues = True
                continue

            # Check if cert exists in keystore
            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True
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

            cacerts = os.path.join(java_home, "lib/security/cacerts")
            if not os.path.exists(cacerts):
                cacerts = os.path.join(java_home, "jre/lib/security/cacerts")

            if not os.path.exists(cacerts):
                self.print_warn(f"    ✗ {version_name}: cacerts file not found")
                has_issues = True
                continue

            # Check if certificate exists
            try:
                result = subprocess.run(
                    ['keytool', '-list', '-alias', self.provider['keytool_alias'],
                     '-keystore', cacerts, '-storepass', 'changeit'],
                    capture_output=True
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
            if os.path.exists(gradle_props):
                current_props = self.read_properties_file(gradle_props)
                cacerts = self.find_java_cacerts()
                expected = {
                    'systemProp.javax.net.ssl.trustStore': cacerts,
                    'systemProp.javax.net.ssl.trustStorePassword': 'changeit',
                    'systemProp.https.protocols': 'TLSv1.2'
                }

                for key, value in expected.items():
                    current = current_props.get(key, '')
                    if current == value and current:
                        self.print_info(f"  ✓ {key} set correctly in Gradle properties")
                    else:
                        self.print_warn(f"  ✗ {key} not set correctly in Gradle properties")
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
                        capture_output=True
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
            # First, verify if wget can actually connect
            verify_result = self.verify_connection("wget")

            if verify_result == "WORKING":
                self.print_info("  ✓ wget can connect through proxy")

                # Check config status (informational only)
                wgetrc_path = os.path.expanduser("~/.wgetrc")
                if os.path.exists(wgetrc_path):
                    with open(wgetrc_path, 'r') as f:
                        content = f.read()
                    if "ca_certificate=" in content and self.cert_path in content:
                        self.print_info("  ✓ wget configured with proxy certificate")
                    else:
                        self.print_info("  - Using system certificate trust (no custom CA needed)")
                else:
                    self.print_info("  - Using system certificate trust (no custom CA needed)")
            else:
                # wget doesn't work, check configuration
                wgetrc_path = os.path.expanduser("~/.wgetrc")
                if os.path.exists(wgetrc_path):
                    with open(wgetrc_path, 'r') as f:
                        content = f.read()
                    if "ca_certificate=" in content and self.cert_path in content:
                        self.print_warn("  ✗ wget configured but connection test failed")
                        has_issues = True
                    else:
                        self.print_warn("  ✗ wget not configured with proxy certificate")
                        has_issues = True
                else:
                    self.print_warn("  ✗ wget not configured")
                    has_issues = True
        else:
            self.print_info("  - wget not installed")
        return has_issues

    def check_podman_status(self, temp_warp_cert):
        """Check Podman configuration status.

        Checks both the persistent ~/.docker/certs.d/ location and the running VM.
        """
        has_issues = False
        if self.command_exists('podman'):
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self.certificate_likely_exists_in_file(temp_warp_cert, cert_path):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            # Check VM status if running
            try:
                result = subprocess.run(['podman', 'machine', 'list'], capture_output=True, text=True)
                if 'Currently running' in result.stdout:
                    # VM is running - also check certificate in VM
                    result = subprocess.run(
                        ['podman', 'machine', 'ssh', f'test -f /etc/pki/ca-trust/source/anchors/{self.provider["container_cert_name"]}.pem'],
                        capture_output=True
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
        """Check Rancher Desktop configuration status.

        Checks both the persistent ~/.docker/certs.d/ location and the running VM.
        """
        has_issues = False
        if self.command_exists('rdctl'):
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self.certificate_likely_exists_in_file(temp_warp_cert, cert_path):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            # Check VM status if running
            try:
                result = subprocess.run(['rdctl', 'version'], capture_output=True, text=True)
                if result.returncode == 0:
                    # VM is running - also check certificate in VM
                    result = subprocess.run(
                        ['rdctl', 'shell', 'test', '-f', f'/usr/local/share/ca-certificates/{self.provider["container_cert_name"]}.pem'],
                        capture_output=True
                    )
                    if result.returncode == 0:
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

    def check_android_status(self, temp_warp_cert):
        """Check Android Emulator configuration status."""
        has_issues = False
        if self.command_exists('adb') and self.command_exists('emulator'):
            try:
                result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
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
        """Check Colima configuration status.

        Checks both the persistent ~/.docker/certs.d/ location and the running VM.
        """
        has_issues = False
        if self.command_exists('colima'):
            # Check persistent certificate location first (primary)
            docker_certs_dir = os.path.expanduser("~/.docker/certs.d")
            cert_path = os.path.join(docker_certs_dir, f"{self.provider['container_cert_name']}.crt")

            if os.path.exists(cert_path):
                if self.certificate_likely_exists_in_file(temp_warp_cert, cert_path):
                    self.print_info("  ✓ Certificate installed in ~/.docker/certs.d/ (persistent)")
                else:
                    self.print_warn("  ✗ Certificate in ~/.docker/certs.d/ is outdated")
                    has_issues = True
            else:
                self.print_warn("  ✗ Certificate not installed in ~/.docker/certs.d/")
                has_issues = True

            # Check VM status if running
            try:
                result = subprocess.run(['colima', 'status'], capture_output=True)
                if result.returncode == 0:
                    # VM is running - also check certificate in VM
                    result = subprocess.run(
                        ['colima', 'ssh', '--', 'test', '-f', f'/usr/local/share/ca-certificates/{self.provider["container_cert_name"]}.crt'],
                        capture_output=True
                    )
                    if result.returncode == 0:
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
        """Retrieve the current provider certificate for status comparisons.

        Returns:
            str or None: Path to a temp file containing the cert, or None on failure.
        """
        provider_name = self.provider['name']

        if self.provider is PROVIDERS['warp']:
            if not self.command_exists('warp-cli'):
                self.print_error(f"warp-cli command not found. Please ensure {provider_name} is installed.")
                return None
            try:
                result = subprocess.run(
                    ['warp-cli', 'certs', '--no-paginate'],
                    capture_output=True, text=True
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
        """Check whether the MITM proxy is connected/running.

        Returns:
            bool: True if issues were detected.
        """
        provider_name = self.provider['name']
        short = self.provider['short_name']

        if self.provider is PROVIDERS['warp']:
            self.print_status(f"{provider_name} Connection:")
            if self.command_exists('warp-cli'):
                try:
                    result = subprocess.run(['warp-cli', 'status'], capture_output=True, text=True)
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
                    capture_output=True, text=True
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

        # Retrieve the current certificate for comparison
        temp_warp_cert = self._get_status_cert()
        if not temp_warp_cert:
            return False

        self.print_debug(f"Retrieved {short} certificate for comparison")
        self.cert_fingerprint = self.get_cert_fingerprint(temp_warp_cert)
        self.print_debug(f"{short} certificate fingerprint: {self.cert_fingerprint}")

        # Check provider connection
        if self._check_provider_connection():
            has_issues = True
        print()
        
        # Check certificate status
        self.print_status("Certificate Status:")
        
        # Check if proxy certificate is valid
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-checkend', '86400', '-in', temp_warp_cert],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info(f"  ✓ {short} certificate is valid")
                
                # Check where the certificate is currently stored
                cert_locations = []
                cert_found = False
                
                # Check common locations
                if os.path.exists(self.cert_path):
                    with open(self.cert_path, 'r') as f:
                        existing_cert = f.read()
                    with open(temp_warp_cert, 'r') as f:
                        warp_cert_content = f.read()
                    if existing_cert == warp_cert_content:
                        cert_locations.append(f"    - {self.cert_path}")
                        cert_found = True
                
                # Check NODE_EXTRA_CA_CERTS
                node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
                if node_extra_ca_certs and os.path.exists(node_extra_ca_certs):
                    if self.certificate_exists_in_file(temp_warp_cert, node_extra_ca_certs):
                        cert_locations.append(f"    - {node_extra_ca_certs} (NODE_EXTRA_CA_CERTS)")
                        cert_found = True
                
                # Check REQUESTS_CA_BUNDLE
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if requests_ca_bundle and os.path.exists(requests_ca_bundle):
                    if self.certificate_exists_in_file(temp_warp_cert, requests_ca_bundle):
                        cert_locations.append(f"    - {requests_ca_bundle} (REQUESTS_CA_BUNDLE)")
                        cert_found = True
                
                # Check SSL_CERT_FILE
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if ssl_cert_file and os.path.exists(ssl_cert_file):
                    if self.certificate_exists_in_file(temp_warp_cert, ssl_cert_file):
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
        
        # Display selected tools info if filtering
        if self.selected_tools:
            selected_tools_info = self.get_selected_tools_info()
            self.print_info(f"Selected tools: {', '.join(selected_tools_info)}")
            print()
        
        # Check each tool
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
                if self.certificate_likely_exists_in_file(temp_warp_cert, cert_path):
                    self.print_info(f"  ✓ Certificate installed in {docker_certs_dir}")
                    self.print_info("    (Used by: Colima, Podman, Rancher Desktop, Lima-based tools)")
                else:
                    self.print_warn(f"  ✗ Certificate in {docker_certs_dir} is outdated")
            else:
                # Only warn if container tools are detected
                has_container_tools = (self.command_exists('docker') or
                                       self.command_exists('colima') or
                                       self.command_exists('podman') or
                                       self.command_exists('rdctl'))
                if has_container_tools:
                    self.print_warn(f"  ✗ Certificate not in {docker_certs_dir}")
                    self.print_action("    Run with --fix to install for container tools")
                else:
                    self.print_info("  - No container runtimes detected")
            print()
        # Show information about additional tools if not filtering
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
        
        # Cleanup
        if temp_warp_cert:
            os.unlink(temp_warp_cert)
    
    def main(self):
        """Main function."""
        try:
            header = f"{self.provider['name']} Certificate Installation Script (Python)"
            self.print_info(header)
            self.print_info("=" * len(header))
            
            if self.is_debug_mode():
                self.print_debug(f"Fumitm version: {VERSION_INFO['version']} (commit: {VERSION_INFO['commit']})")
                self.print_debug(f"Branch: {VERSION_INFO['branch']} | Date: {VERSION_INFO['date']}")
                if VERSION_INFO['dirty']:
                    self.print_debug("Working directory has uncommitted changes")
                self.print_debug(f"Script: Python implementation")
                self.print_debug(f"Running on: {platform.platform()}")
                self.print_debug(f"Python version: {sys.version}")
                self.print_debug(f"Shell: {os.environ.get('SHELL', 'unknown')}")
                self.print_debug(f"PATH: {os.environ.get('PATH', '')}")
                self.print_debug(f"Home directory: {os.path.expanduser('~')}")
                self.print_debug(f"Certificate path: {self.cert_path}")
                if self._is_running_as_sudo():
                    uid, gid = self._get_real_user_ids()
                    self.print_debug(f"Running as sudo (real user UID={uid}, GID={gid})")
                if not self.is_install_mode():
                    self.print_debug("Status mode: Using fast certificate checks")
                else:
                    self.print_debug("Install mode: Using thorough certificate checks")

            # Check for updates (uses unverified SSL since WARP might not be configured)
            self.check_for_updates()

            # Auto-detect devcontainer and adjust behavior
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

            # Check for broken CA environment variables early
            # This catches common issues before they cause confusing errors
            self.check_environment_sanity()

            # Check for root-owned files that would cause PermissionError
            self.check_ownership_sanity()

            # Validate selected tools
            if self.selected_tools:
                invalid_tools = self.validate_selected_tools()
                if invalid_tools:
                    self.print_error(f"Invalid tool selection: {', '.join(invalid_tools)}")
                    self.print_info("Use --list-tools to see available tools and their tags")
                    return 1
                
                # Show which tools will be processed
                selected_info = self.get_selected_tools_info()
                if not selected_info:
                    self.print_warn("No tools match your selection")
                    return 1
            
            if not self.is_install_mode():
                # In status mode, just check current status
                status_ok = self.check_all_status()
                if status_ok is False:
                    return 1
            else:
                self.print_info("Running in FIX mode - changes will be made to your system")
                print()
                
                # Download and verify certificate
                if not self.download_certificate():
                    self.print_error("Failed to download certificate. Exiting.")
                    return 1
                
                # Setup for different environments
                if self.selected_tools:
                    self.print_info(f"Processing selected tools: {', '.join(self.get_selected_tools_info())}")
                    print()
                
                for tool_key, tool_info in self.tools_registry.items():
                    if self.should_process_tool(tool_key):
                        if tool_info.get('setup_func'):
                            tool_info['setup_func']()
                
                # Final message
                print()
                self.print_info("Installation completed!")
                
                if self.shell_modified:
                    self.print_warn("Shell configuration was modified.")
                    self.print_warn("Please reload your shell configuration:")
                    
                    shell_type = self.detect_shell()
                    shell_config = self.get_shell_config(shell_type)
                    
                    if shell_type in ['bash', 'zsh']:
                        self.print_info(f"  source {shell_config}")
                    elif shell_type == 'fish':
                        self.print_info(f"  source {shell_config}")
                    else:
                        self.print_info("  Please restart your shell")
            
            print()
            self.print_info(f"Certificate location: {self.cert_path}")
            self.print_info("For additional applications, please refer to the documentation.")
            
            return 0  # Success
            
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
    parser.add_argument('--debug', '--verbose', action='store_true',
                        help='Show detailed debug information')
    parser.add_argument('--version', '-V', action='store_true',
                        help='Show version information and exit')

    args = parser.parse_args()

    # Handle --version first
    if args.version:
        print(f"fumitm {__version__}")
        version_info = VERSION_INFO
        if version_info['commit'] != 'unknown':
            print(f"  Git commit: {version_info['commit']} ({version_info['date']})")
            print(f"  Branch: {version_info['branch']}")
            if version_info['dirty']:
                print("  (with local modifications)")
        sys.exit(0)

    # Handle --list-tools
    if args.list_tools:
        # Create a temporary instance just to access the registry
        temp_fumitm = FumitmPython()
        print("Available tools:")
        for tool_key, tool_info in temp_fumitm.tools_registry.items():
            tags_str = ', '.join(tool_info['tags'])
            print(f"  {tool_key:<10} - {tool_info['name']:<20} Tags: {tags_str}")
        print("\nExamples: ./fumitm.py --fix --tools node,python  or  ./fumitm.py --fix --tools node-npm --tools gcp")
        sys.exit(0)
    
    # Process --tools argument
    selected_tools = []
    if args.tools:
        for tool_arg in args.tools:
            # Split by comma to allow comma-separated lists
            selected_tools.extend([t.strip() for t in tool_arg.split(',') if t.strip()])
    
    # Determine mode
    mode = 'install' if args.fix else 'status'
    
    # Create and run fumitm instance
    fumitm = FumitmPython(
        mode=mode,
        debug=args.debug,
        selected_tools=selected_tools,
        cert_file=args.cert_file,
        manual_cert=args.manual_cert,
        skip_verify=args.skip_verify,
        provider=args.provider
    )
    exit_code = fumitm.main()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
