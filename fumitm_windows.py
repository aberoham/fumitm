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
import hashlib
import urllib.request
import urllib.error
import winreg
from pathlib import Path
from datetime import datetime

# Version and metadata
__description__ = "MITM Certificate Fixer Upper for Windows"
__author__ = "Ingersoll & Claude"
__version__ = "2026.3.23"  # CalVer: YYYY.MM.DD (auto-updated on release)


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
        "version": "unknown",
        "commit": "unknown",
        "date": "unknown",
        "branch": "unknown",
        "dirty": False,
    }

    try:
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Check if we're in a git repository
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=script_dir,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            # Get commit hash (short)
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=script_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version_info["commit"] = result.stdout.strip()

            # Get commit date
            result = subprocess.run(
                ["git", "log", "-1", "--format=%cd", "--date=short"],
                cwd=script_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version_info["date"] = result.stdout.strip()

            # Get branch name
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=script_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version_info["branch"] = result.stdout.strip()

            # Check if working directory is dirty
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=script_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info["dirty"] = True

            # Get tag if available
            result = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                cwd=script_dir,
                capture_output=True,
                text=True,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info["version"] = result.stdout.strip()
            else:
                # No tags, use commit count as version
                result = subprocess.run(
                    ["git", "rev-list", "--count", "HEAD"],
                    cwd=script_dir,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0 and result.stdout.strip():
                    count = result.stdout.strip()
                    version_info["version"] = f"0.{count}.0"

            # Add dirty flag to version if needed
            if version_info["dirty"] and version_info["version"] != "unknown":
                version_info["version"] += "-dirty"

    except Exception:
        # Git not available or not a git repository
        pass

    return version_info


# Get version info once at module load
VERSION_INFO = get_version_info()

# Colors for output (Windows compatible)
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No Color

# Provider-specific certificate details
PROVIDERS = {
    "warp": {
        "name": "Cloudflare WARP",
        "short_name": "WARP",
        "bundle_dir": "~/.cloudflare-warp",
        "cert_filename": "THG-CloudflareCert.pem",
        "keytool_alias": "cloudflare-zerotrust",
        "container_cert_name": "THG-CloudflareCert.pem",
    },
    "netskope": {
        "name": "Netskope",
        "short_name": "Netskope",
        "bundle_dir": "~/.netskope",
        "cert_filename": "netskope-ca.pem",
        "keytool_alias": "netskope-zerotrust",
        "container_cert_name": "netskope.pem",
        "cert_sources": [
            os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Netskope",
                "stagent",
                "data",
                "nscacert_combined.pem",
            ),
            os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Netskope",
                "stagent",
                "data",
                "nscacert.pem",
            ),
            os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Netskope",
                "STAgent",
                "data",
                "nscacert_combined.pem",
            ),
            os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Netskope",
                "STAgent",
                "data",
                "nscacert.pem",
            ),
        ],
    },
}

# Base directory for tool-specific certificate bundles (defaults to WARP, updated by set_active_provider)
CLOUDFLARE_WARP_DIR = os.path.expanduser(PROVIDERS["warp"]["bundle_dir"])
CERT_PATH = os.path.join(CLOUDFLARE_WARP_DIR, PROVIDERS["warp"]["cert_filename"])


def set_active_provider(provider_key):
    """Update global certificate paths for the selected provider."""
    global CLOUDFLARE_WARP_DIR, CERT_PATH

    if provider_key not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider_key}")

    provider = PROVIDERS[provider_key]
    CLOUDFLARE_WARP_DIR = os.path.expanduser(provider["bundle_dir"])
    CERT_PATH = os.path.join(CLOUDFLARE_WARP_DIR, provider["cert_filename"])


class FumitmWindows:
    def __init__(
        self,
        mode="status",
        debug=False,
        selected_tools=None,
        use_warp_cli=False,
        provider=None,
    ):
        self.debug = debug
        if provider is None:
            provider = self._resolve_provider()
        set_active_provider(provider)
        self.mode = mode
        self.shell_modified = False
        self.cert_fingerprint = ""
        self.selected_tools = selected_tools or []
        self.use_warp_cli = use_warp_cli
        self.provider_key = provider
        self.provider = PROVIDERS[provider]

        # Define tool registry with tags and descriptions
        self.tools_registry = {
            "node": {
                "name": "Node.js",
                "tags": ["node", "nodejs", "node-npm", "javascript", "js"],
                "setup_func": self.setup_node_cert,
                "check_func": self.check_node_status,
                "description": "Node.js runtime and npm package manager",
            },
            "python": {
                "name": "Python",
                "tags": ["python", "python3", "pip", "requests"],
                "setup_func": self.setup_python_cert,
                "check_func": self.check_python_status,
                "description": "Python runtime and pip package manager",
            },
            "gcloud": {
                "name": "Google Cloud SDK",
                "tags": ["gcloud", "google-cloud", "gcp"],
                "setup_func": self.setup_gcloud_cert,
                "check_func": self.check_gcloud_status,
                "description": "Google Cloud SDK (gcloud CLI)",
            },
            "java": {
                "name": "Java/JVM",
                "tags": ["java", "jvm", "keytool", "jdk"],
                "setup_func": self.setup_java_cert,
                "check_func": self.check_java_status,
                "description": "Java runtime and development kit",
            },
            "wget": {
                "name": "wget",
                "tags": ["wget", "download"],
                "setup_func": self.setup_wget_cert,
                "check_func": self.check_wget_status,
                "description": "wget download utility",
            },
            "podman": {
                "name": "Podman",
                "tags": ["podman", "container", "docker-alternative"],
                "setup_func": self.setup_podman_cert,
                "check_func": self.check_podman_status,
                "description": "Podman container runtime",
            },
            "rancher": {
                "name": "Rancher Desktop",
                "tags": ["rancher", "rancher-desktop", "kubernetes", "k8s"],
                "setup_func": self.setup_rancher_cert,
                "check_func": self.check_rancher_status,
                "description": "Rancher Desktop Kubernetes",
            },
            "git": {
                "name": "Git",
                "tags": ["git", "version-control"],
                "setup_func": self.setup_git_cert,
                "check_func": self.check_git_status,
                "description": "Git version control system",
            },
            "system": {
                "name": "Windows Certificate Store",
                "tags": ["system", "windows", "certificate-store"],
                "setup_func": self.setup_system_cert,
                "check_func": self.check_system_status,
                "description": "Windows system certificate store",
            },
        }

        # Add platform check
        if platform.system() != "Windows":
            self.print_warn(
                "This script is designed for Windows. Most features will not work correctly."
            )

    def get_provider_name(self):
        return self.provider["name"]

    def get_provider_short_name(self):
        return self.provider["short_name"]

    def get_keytool_alias(self):
        return self.provider["keytool_alias"]

    def get_container_cert_name(self):
        return self.provider["container_cert_name"]

    def _detect_warp(self):
        """Check if Cloudflare WARP is available."""
        return self.command_exists("warp-cli")

    def _detect_netskope(self):
        """Check if Netskope is available on Windows."""
        # Check for certificate files
        for path in PROVIDERS["netskope"].get("cert_sources", []):
            if os.path.exists(path):
                return True
            # Check for encrypted variant
            if os.path.exists(f"{path}.enc"):
                return True
        # Check for running STAgent process
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq STAgent.exe"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and "STAgent.exe" in result.stdout:
                return True
        except Exception:
            pass
        return False

    def _resolve_provider(self):
        """Auto-detect the MITM proxy provider. Prefers WARP when both are found."""
        if self._detect_warp():
            self.print_debug("Auto-detected Cloudflare WARP")
            return "warp"
        if self._detect_netskope():
            self.print_debug("Auto-detected Netskope")
            return "netskope"
        # Default to WARP if nothing detected
        self.print_debug("No provider detected, defaulting to WARP")
        return "warp"

    def is_install_mode(self):
        return self.mode == "install"

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
            if selection_lower in [tag.lower() for tag in tool_info.get("tags", [])]:
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
                if selection_lower in [
                    tag.lower() for tag in tool_info.get("tags", [])
                ]:
                    found = True
                    break

            if not found:
                invalid_tools.append(selection)

        return invalid_tools

    # Printing functions
    def _safe_console_text(self, msg):
        """Return text that won't crash on legacy Windows console encodings."""
        replacements = {
            "✓": "[OK]",
            "✗": "[X]",
            "⚠": "[!]",
            "—": "-",
            "–": "-",
        }

        safe_msg = msg
        for src, dst in replacements.items():
            safe_msg = safe_msg.replace(src, dst)

        return safe_msg

    def _emit(self, text, stream=None):
        """Print text with a fallback for consoles that reject Unicode."""
        if stream is None:
            stream = sys.stdout

        try:
            print(text, file=stream)
        except UnicodeEncodeError:
            print(self._safe_console_text(text), file=stream)

    def print_info(self, msg):
        self._emit(f"{GREEN}[INFO]{NC} {msg}")

    def print_warn(self, msg):
        self._emit(f"{YELLOW}[WARN]{NC} {msg}")

    def print_error(self, msg):
        self._emit(f"{RED}[ERROR]{NC} {msg}")

    def print_status(self, msg):
        self._emit(f"{BLUE}[STATUS]{NC} {msg}")

    def print_action(self, msg):
        self._emit(f"{YELLOW}[ACTION]{NC} {msg}")

    def print_debug(self, msg):
        if self.is_debug_mode():
            self._emit(f"{BLUE}[DEBUG]{NC} {msg}", stream=sys.stderr)

    def command_exists(self, cmd):
        """Check if a command exists."""
        return shutil.which(cmd) is not None

    def is_admin(self):
        """Check if running with administrator privileges."""
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def run_as_admin(self, command):
        """Run a command with administrator privileges."""
        try:
            import ctypes

            if isinstance(command, list):
                command = " ".join(command)

            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe", f'-Command "{command}"', None, 1
            )
            return result > 32  # Success if result > 32
        except Exception as e:
            self.print_debug(f"Error running as admin: {e}")
            return False

    @staticmethod
    def _ps_escape(path):
        """Escape a path for safe use inside a PowerShell single-quoted string."""
        return str(path).replace("'", "''")

    def get_netskope_cert_sources(self):
        """Return known Windows Netskope certificate locations."""
        return self.provider.get("cert_sources", [])

    def _get_warp_cert(self):
        """Retrieve the active WARP certificate from warp-cli."""
        if not self.command_exists("warp-cli"):
            self.print_error(
                "warp-cli command not found. Please ensure Cloudflare WARP is installed."
            )
            return None

        try:
            if self.use_warp_cli:
                self.print_debug(
                    "Using --use-warp-cli: generating fresh WARP certificate"
                )

            result = subprocess.run(
                ["warp-cli", "certs", "--no-paginate"],
                capture_output=True,
                text=True,
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
        """Retrieve the Netskope CA certificate from known Windows locations."""
        found_encrypted = []

        if os.path.exists(CERT_PATH):
            try:
                with open(CERT_PATH, "r", encoding="utf-8") as f:
                    cert_content = f.read().strip()

                if "-----BEGIN CERTIFICATE-----" in cert_content:
                    self.print_info(f"Using Netskope certificate from {CERT_PATH}")
                    return cert_content
            except Exception as e:
                self.print_debug(
                    f"Could not read manual Netskope certificate at {CERT_PATH}: {e}"
                )

        for path in self.get_netskope_cert_sources():
            if not os.path.exists(path):
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    cert_content = f.read().strip()

                if "-----BEGIN CERTIFICATE-----" in cert_content:
                    self.print_info(f"Using Netskope certificate from {path}")
                    return cert_content
            except Exception as e:
                self.print_debug(f"Could not read Netskope certificate at {path}: {e}")

        for path in self.get_netskope_cert_sources():
            enc_path = f"{path}.enc"
            if os.path.exists(enc_path):
                found_encrypted.append(enc_path)

        if found_encrypted:
            self.print_error("Found encrypted Netskope certificate file(s):")
            for enc_path in found_encrypted:
                self.print_error(f"  {enc_path}")
            self.print_error(
                "Netskope appears to be storing the certificate in encrypted form."
            )
            self.print_error(
                "Export the Netskope root certificate as PEM and place it at:"
            )
            self.print_error(f"  {CERT_PATH}")
            self.print_error(
                "Then rerun fumitm_windows.py with --provider netskope."
            )
            return None

        self.print_error("Could not find Netskope certificate")
        self.print_error("Checked:")
        for path in self.get_netskope_cert_sources():
            self.print_error(f"  {path}")
        return None

    def get_provider_cert(self):
        """Retrieve the current provider certificate as PEM text."""
        if self.provider_key == "netskope":
            return self._get_netskope_cert()
        return self._get_warp_cert()

    def get_status_cert_file(self):
        """Retrieve the current provider certificate into a temporary file."""
        cert_content = self.get_provider_cert()
        if not cert_content:
            return None

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tf:
            tf.write(cert_content)
            return tf.name

    def check_provider_connection(self):
        """Check whether the selected provider is available and connected."""
        provider_name = self.get_provider_name()
        short_name = self.get_provider_short_name()
        self.print_status(f"{provider_name} Connection:")

        if self.provider_key == "warp":
            if self.command_exists("warp-cli"):
                try:
                    result = subprocess.run(
                        ["warp-cli", "status"],
                        capture_output=True,
                        text=True,
                    )
                    warp_status = result.stdout if result.returncode == 0 else "unknown"
                    if "Connected" in warp_status:
                        self.print_info(f"  ✓ {short_name} is connected")
                        return False

                    self.print_warn(f"  ✗ {short_name} is not connected")
                    self.print_action("  Run: warp-cli connect")
                    return True
                except Exception:
                    self.print_error(f"  ✗ Failed to check {short_name} status")
                    return True

            self.print_error("  ✗ warp-cli not found")
            self.print_action(f"  Install {provider_name} client")
            return True

        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq STAgent.exe"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and "STAgent.exe" in result.stdout:
                self.print_info("  ✓ STAgent is running")
                return False
        except Exception as e:
            self.print_debug(f"Failed to query Netskope process status: {e}")

        if any(os.path.exists(path) for path in self.get_netskope_cert_sources()):
            self.print_info("  ✓ Netskope certificate file found")
            return False

        self.print_warn("  ✗ Could not verify Netskope status")
        return True

    def find_certificate_file(self):
        """Find the provider certificate file."""
        # Only use our specific certificate file
        if os.path.exists(CERT_PATH):
            self.print_debug(f"Found {self.get_provider_short_name()} certificate at: {CERT_PATH}")
            return CERT_PATH

        self.print_debug(f"{self.get_provider_short_name()} certificate not found at: {CERT_PATH}")
        return CERT_PATH  # Return path even if not found for creation

    def get_cert_fingerprint(self, cert_path=None):
        """Get certificate fingerprint (cached)."""
        if cert_path is None:
            cert_path = self.find_certificate_file()

        if self.cert_fingerprint and cert_path == CERT_PATH:
            return self.cert_fingerprint

        if os.path.exists(cert_path):
            try:
                # Try openssl first
                result = subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-in",
                        cert_path,
                        "-noout",
                        "-fingerprint",
                        "-sha256",
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    fingerprint = result.stdout.strip().split("=")[1]
                    if cert_path == CERT_PATH:
                        self.cert_fingerprint = fingerprint
                    self.print_debug(
                        f"Cached certificate fingerprint (openssl): {fingerprint}"
                    )
                    return fingerprint
            except Exception as e:
                self.print_debug(
                    f"OpenSSL not available, trying PowerShell method: {e}"
                )

            try:
                # Fallback to PowerShell method
                ps_command = f"""
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{self._ps_escape(cert_path)}')
                $hash = $cert.GetCertHashString('SHA256')
                $formatted = ($hash -replace '(..)','$1:').TrimEnd(':')
                Write-Output $formatted
                """

                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0 and result.stdout.strip():
                    fingerprint = result.stdout.strip()
                    if cert_path == CERT_PATH:
                        self.cert_fingerprint = fingerprint
                    self.print_debug(
                        f"Cached certificate fingerprint (PowerShell): {fingerprint}"
                    )
                    return fingerprint
            except Exception as e:
                self.print_debug(f"Error getting fingerprint with PowerShell: {e}")

        return ""

    def get_tool_bundle_path(self, tool_name):
        """Get the standardized bundle path for a tool."""
        # Use os.path.join consistently and normalize the result
        path = os.path.join(CLOUDFLARE_WARP_DIR, tool_name, "ca-bundle.pem")
        return os.path.normpath(path)

    def find_existing_bundle(self, tool_name):
        """Find existing certificate bundle for a tool in various locations."""
        # Tool-specific locations to check
        locations = {
            "python": [
                os.path.join(os.path.expanduser("~"), ".python-ca-bundle.pem"),
                self.get_environment_variable("REQUESTS_CA_BUNDLE"),
                self.get_environment_variable("SSL_CERT_FILE"),
            ],
            "node": [
                os.environ.get("NODE_EXTRA_CA_CERTS", ""),
            ],
            "npm": [],  # npm config get cafile will be checked separately
            "gcloud": [],  # gcloud config will be checked separately
            "git": [],  # git config will be checked separately
        }

        # Check tool-specific locations
        for location in locations.get(tool_name, []):
            if location and os.path.exists(location):
                # Normalize the path before returning
                return os.path.normpath(location)

        return None

    def setup_consistent_bundle(self, tool_name, env_vars=None):
        """Setup consistent certificate bundle for a tool."""
        bundle_path = self.get_tool_bundle_path(tool_name)
        existing_bundle = self.find_existing_bundle(tool_name)

        # Check if bundle already exists and is current
        if os.path.exists(bundle_path):
            if self.certificate_exists_in_file(CERT_PATH, bundle_path):
                self.print_debug(
                    f"{tool_name} bundle already contains current certificate"
                )
                # Bundle is healthy — still ensure all env vars are set in the registry,
                # since they may have been missed on a previous run.
                if env_vars:
                    for env_var in env_vars:
                        if not self.get_environment_variable(env_var):
                            if not self.is_install_mode():
                                self.print_action(
                                    f"Would set {env_var} to {bundle_path}"
                                )
                            else:
                                self.set_environment_variable(env_var, bundle_path)
                return bundle_path

        # Handle existing bundle
        if existing_bundle:
            if not self.is_install_mode():
                self.print_action(
                    f"Found existing {tool_name} certificate bundle at {existing_bundle}"
                )
                self.print_action(
                    f"Would copy to {bundle_path} and append {self.get_provider_short_name()} cert"
                )
            else:
                response = input(
                    f"Found existing {tool_name} certificate bundle at {existing_bundle}. Copy to {bundle_path} and append {self.get_provider_short_name()} cert? (Y/n) "
                )
                if response.lower() != "n":
                    # Create directory
                    os.makedirs(os.path.dirname(bundle_path), exist_ok=True)

                    # Normalize paths for comparison
                    existing_bundle_normalized = os.path.normpath(os.path.abspath(existing_bundle))
                    bundle_path_normalized = os.path.normpath(os.path.abspath(bundle_path))

                    # Copy existing bundle (only if it's not already at the target location)
                    if existing_bundle_normalized != bundle_path_normalized:
                        shutil.copy(existing_bundle, bundle_path)
                        self.print_info(f"Copied existing bundle to {bundle_path}")
                    else:
                        self.print_info(f"Using existing bundle at {bundle_path}")

                    # Check if the copied bundle already contains the certificate
                    if not self.certificate_exists_in_file(CERT_PATH, bundle_path):
                        # Append provider cert if not already present
                        self.append_certificate_if_missing(CERT_PATH, bundle_path)
                    else:
                        self.print_debug(
                            f"Copied bundle already contains current certificate, skipping append"
                        )
                else:
                    return None
        else:
            # No existing bundle, create new one
            if not self.is_install_mode():
                self.print_action(f"Would create new bundle at {bundle_path}")
            else:
                self.print_info(f"Creating new {tool_name} CA bundle at {bundle_path}")
                os.makedirs(os.path.dirname(bundle_path), exist_ok=True)

                # Get system certificates
                system_certs = self.get_system_ca_bundle()
                if system_certs:
                    with open(bundle_path, "w") as f:
                        f.write(system_certs)
                else:
                    Path(bundle_path).touch()

                # Append provider certificate (with duplicate detection)
                self.append_certificate_if_missing(CERT_PATH, bundle_path)

                self.print_info(
                    f"Created {tool_name} CA bundle with {self.get_provider_short_name()} certificate"
                )

        # Set environment variables if provided
        if env_vars and self.is_install_mode():
            for env_var in env_vars:
                self.set_environment_variable(env_var, bundle_path)

        return bundle_path

    def certificate_exists_in_file(self, cert_file, target_file):
        """Check if a certificate already exists in a file."""
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False

        # In status mode, use the fast check
        if not self.is_install_mode():
            return self.certificate_likely_exists_in_file(cert_file, target_file)

        # Get cached fingerprint
        cert_fingerprint = self.get_cert_fingerprint(cert_file)
        if not cert_fingerprint:
            return False

        # For install mode, do the thorough check
        try:
            with open(target_file, "r") as f:
                content = f.read()

            # Split content into certificates
            certs = []
            current_cert = []
            in_cert = False

            for line in content.splitlines():
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    current_cert = [line]
                elif "-----END CERTIFICATE-----" in line:
                    current_cert.append(line)
                    if in_cert:
                        certs.append("\n".join(current_cert))
                    in_cert = False
                    current_cert = []
                elif in_cert:
                    current_cert.append(line)

            # Check each certificate
            for cert in certs:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pem", delete=False
                ) as tf:
                    tf.write(cert)
                    tf.flush()

                    file_fingerprint = self.get_cert_fingerprint(tf.name)
                    os.unlink(tf.name)

                    if file_fingerprint == cert_fingerprint:
                        self.print_debug(f"Certificate already exists in {target_file}")
                        return True
        except Exception as e:
            self.print_debug(f"Error checking certificate existence: {e}")

        return False

    def append_certificate_if_missing(self, cert_file, target_file):
        """Append certificate to target file only if it doesn't already exist."""
        # Normalize paths for comparison
        cert_file_normalized = os.path.normpath(os.path.abspath(cert_file))
        target_file_normalized = os.path.normpath(os.path.abspath(target_file))

        # Ensure we're not trying to append a file to itself
        if cert_file_normalized == target_file_normalized:
            self.print_debug(f"Skipping append: source and target are the same file ({cert_file})")
            return True

        if self.certificate_exists_in_file(cert_file, target_file):
            self.print_debug(
                f"Certificate already exists in {target_file}, skipping append"
            )
            return True

        try:
            with open(cert_file, "r") as cf:
                cert_content = cf.read()

            # Ensure certificate content ends with newline
            if not cert_content.endswith('\n'):
                cert_content = cert_content + '\n'

            # Check if target file ends with a newline
            needs_leading_newline = False
            if os.path.exists(target_file):
                with open(target_file, 'rb') as tf:
                    tf.seek(0, 2)  # Seek to end
                    if tf.tell() > 0:  # File is not empty
                        tf.seek(-1, 2)  # Seek to last byte
                        last_byte = tf.read(1)
                        # Check for newline (LF) or carriage return (CR for CRLF)
                        if last_byte not in (b'\n', b'\r'):
                            needs_leading_newline = True

            with open(target_file, "a") as f:
                if needs_leading_newline:
                    f.write("\n")
                f.write(cert_content)
            self.print_info(f"Appended {self.get_provider_short_name()} certificate to {target_file}")
            return True
        except Exception as e:
            self.print_error(f"Failed to append certificate to {target_file}: {e}")
            return False

    def certificate_likely_exists_in_file(self, cert_file, target_file):
        """Fast certificate check using content matching (for status mode)."""
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False

        try:
            with open(cert_file, "r") as f:
                cert_lines = []
                in_cert = False
                for line in f:
                    if "-----BEGIN CERTIFICATE-----" in line:
                        in_cert = True
                    elif "-----END CERTIFICATE-----" in line:
                        in_cert = False
                    elif in_cert:
                        cert_lines.append(line.strip())

                if cert_lines:
                    # Get first 100 chars of cert content
                    cert_content = "".join(cert_lines)[:100]

                    with open(target_file, "r") as tf:
                        target_content = tf.read()
                        # Remove all whitespace for comparison
                        target_normalized = "".join(target_content.split())
                        if (
                            cert_content.replace("\n", "").replace(" ", "")
                            in target_normalized
                        ):
                            self.print_debug(
                                f"Certificate likely exists in {target_file} (found matching content)"
                            )
                            return True
        except Exception as e:
            self.print_debug(f"Error checking content: {e}")

        return False

    def set_environment_variable(self, var_name, var_value, user_scope=True):
        """Set environment variable in Windows registry."""
        if not self.is_install_mode():
            scope_str = "user" if user_scope else "system"
            self.print_action(
                f"Would set {scope_str} environment variable: {var_name}={var_value}"
            )
            return

        try:
            if user_scope:
                # Set user environment variable
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE
                )
            else:
                # Set system environment variable (requires admin)
                if not self.is_admin():
                    self.print_error(
                        "Administrator privileges required for system environment variables"
                    )
                    return False
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                    0,
                    winreg.KEY_SET_VALUE,
                )

            winreg.SetValueEx(key, var_name, 0, winreg.REG_EXPAND_SZ, var_value)
            winreg.CloseKey(key)

            # Notify system of environment change
            import ctypes
            from ctypes import wintypes

            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            result = ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                "Environment",
                SMTO_ABORTIFHUNG,
                5000,
                ctypes.byref(wintypes.DWORD()),
            )

            scope_str = "user" if user_scope else "system"
            self.print_info(
                f"Set {scope_str} environment variable: {var_name}={var_value}"
            )
            self.shell_modified = True
            return True

        except Exception as e:
            self.print_error(f"Failed to set environment variable {var_name}: {e}")
            return False

    def get_environment_variable(self, var_name, user_scope=True):
        """Get environment variable from Windows registry."""
        try:
            if user_scope:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ
                )
            else:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                    0,
                    winreg.KEY_READ,
                )

            value, _ = winreg.QueryValueEx(key, var_name)
            winreg.CloseKey(key)
            return value
        except FileNotFoundError:
            return None
        except Exception as e:
            self.print_debug(f"Error reading environment variable {var_name}: {e}")
            return None

    def install_certificate_to_store(self, cert_path, store_name="Root"):
        """Install certificate to Windows certificate store."""
        if not os.path.exists(cert_path):
            self.print_error(f"Certificate file not found: {cert_path}")
            return False

        if not self.is_install_mode():
            self.print_action(
                f"Would install certificate to Windows {store_name} store"
            )
            return True

        try:
            # Use PowerShell to install certificate
            ps_command = f"""
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{self._ps_escape(cert_path)}')
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('{store_name}', 'CurrentUser')
            $store.Open('ReadWrite')
            $store.Add($cert)
            $store.Close()
            Write-Host "Certificate installed successfully"
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command], capture_output=True, text=True
            )

            if result.returncode == 0:
                self.print_info(f"Certificate installed to Windows {store_name} store")
                return True
            else:
                self.print_error(f"Failed to install certificate: {result.stderr}")
                return False

        except Exception as e:
            self.print_error(f"Error installing certificate to store: {e}")
            return False

    def check_certificate_in_store(self, cert_path, store_name="Root"):
        """Check if certificate exists in Windows certificate store."""
        if not os.path.exists(cert_path):
            return False

        try:
            # Get certificate thumbprint
            cert_fingerprint = self.get_cert_fingerprint(cert_path)
            if not cert_fingerprint:
                return False

            # Use PowerShell to check certificate store
            ps_command = f"""
            $thumbprint = '{cert_fingerprint.replace(':', '')}'
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('{store_name}', 'CurrentUser')
            $store.Open('ReadOnly')
            $cert = $store.Certificates | Where-Object {{ $_.Thumbprint -eq $thumbprint }}
            $store.Close()
            if ($cert) {{ Write-Host "Found" }} else {{ Write-Host "NotFound" }}
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command], capture_output=True, text=True
            )

            return result.returncode == 0 and "Found" in result.stdout

        except Exception as e:
            self.print_debug(f"Error checking certificate in store: {e}")
            return False

    def download_certificate(self):
        """Retrieve and verify the selected provider certificate."""
        provider_name = self.get_provider_name()
        short_name = self.get_provider_short_name()

        if self.provider_key == "warp" and self.use_warp_cli:
            self.print_info(
                f"Generating {provider_name} certificate directly from the client..."
            )
        else:
            self.print_info(f"Retrieving {provider_name} certificate...")

        provider_cert = self.get_provider_cert()
        if not provider_cert:
            return False

        # Create a temp file for the provider certificate
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as temp_cert:
            temp_cert.write(provider_cert)
            temp_cert_path = temp_cert.name

        # Verify it's a valid PEM certificate
        try:
            # Try openssl first
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-in", temp_cert_path],
                capture_output=True,
            )
            if result.returncode == 0:
                self.print_debug("Certificate verified with openssl")
            else:
                raise Exception("OpenSSL verification failed")
        except Exception as e:
            self.print_debug(
                f"OpenSSL not available, trying PowerShell verification: {e}"
            )
            try:
                # Fallback to PowerShell verification
                ps_command = f"""
                try {{
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{self._ps_escape(temp_cert_path)}')
                    if ($cert.Subject) {{
                        Write-Output "Valid certificate"
                        exit 0
                    }} else {{
                        Write-Output "Invalid certificate"
                        exit 1
                    }}
                }} catch {{
                    Write-Output "Error loading certificate: $_"
                    exit 1
                }}
                """

                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                )

                if result.returncode != 0:
                    self.print_error("Retrieved file is not a valid PEM certificate")
                    os.unlink(temp_cert_path)
                    return False
                else:
                    self.print_debug("Certificate verified with PowerShell")
            except Exception as ps_e:
                self.print_error(f"Error verifying certificate: {ps_e}")
                os.unlink(temp_cert_path)
                return False

        self.print_info(f"{provider_name} certificate retrieved successfully")

        # Check if certificate needs to be saved to CERT_PATH
        needs_save = False
        if os.path.exists(CERT_PATH):
            # Check if existing cert matches the current provider cert
            with open(CERT_PATH, "r") as f:
                existing_cert = f.read()

            if existing_cert != provider_cert:
                self.print_info(f"{short_name} certificate at {CERT_PATH} needs updating")
                needs_save = True
            else:
                self.print_info(f"{short_name} certificate at {CERT_PATH} is up to date")
        else:
            self.print_info(f"{short_name} certificate will be saved to {CERT_PATH}")
            needs_save = True

        # Save certificate if needed
        if needs_save:
            if not self.is_install_mode():
                self.print_action(f"Would save {short_name} certificate to {CERT_PATH}")
                self.print_action(
                    f"Would create provider bundle directory at {CLOUDFLARE_WARP_DIR}"
                )
            else:
                # Ensure provider bundle directory exists
                os.makedirs(CLOUDFLARE_WARP_DIR, exist_ok=True)
                self.print_info(
                    f"Created provider bundle directory at {CLOUDFLARE_WARP_DIR}"
                )

                # Save certificate
                shutil.copy(temp_cert_path, CERT_PATH)
                self.print_info(f"{provider_name} certificate saved to {CERT_PATH}")
                self.print_info("Certificate is available for custom use by users")

        # Clean up temporary file (but keep the saved certificate)
        os.unlink(temp_cert_path)

        # Cache the fingerprint for later use
        self.get_cert_fingerprint()

        return True

    def get_system_ca_bundle(self):
        """Get system CA bundle content."""
        try:
            # Try to export certificates from Windows certificate store
            ps_command = """
            $certs = Get-ChildItem -Path Cert:\\CurrentUser\\Root
            $output = ""
            foreach ($cert in $certs) {
                $output += "-----BEGIN CERTIFICATE-----`n"
                $output += [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
                $output += "`n-----END CERTIFICATE-----`n"
            }
            Write-Output $output
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command], capture_output=True, text=True
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception as e:
            self.print_debug(f"Error getting system CA bundle: {e}")

        return ""

    def setup_system_cert(self):
        """Setup Windows system certificate store."""
        self.print_info("Setting up Windows system certificate...")

        if not os.path.exists(CERT_PATH):
            self.print_error("Certificate file not found. Run download first.")
            return

        # Install to user certificate store first
        if self.install_certificate_to_store(CERT_PATH, "Root"):
            self.print_info("Certificate installed to user Root store")

        # Optionally install to system store (requires admin)
        if self.is_admin():
            if not self.is_install_mode():
                self.print_action(
                    "Would install certificate to system Root store (admin)"
                )
            else:
                response = input(
                    "Install to system certificate store for all users? (y/N) "
                )
                if response.lower() == "y":
                    try:
                        ps_command = f"""
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{self._ps_escape(CERT_PATH)}')
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
                        $store.Open('ReadWrite')
                        $store.Add($cert)
                        $store.Close()
                        Write-Host "Certificate installed to system store"
                        """

                        result = subprocess.run(
                            ["powershell", "-Command", ps_command],
                            capture_output=True,
                            text=True,
                        )

                        if result.returncode == 0:
                            self.print_info(
                                "Certificate installed to system Root store"
                            )
                        else:
                            self.print_error(
                                f"Failed to install to system store: {result.stderr}"
                            )
                    except Exception as e:
                        self.print_error(f"Error installing to system store: {e}")
        else:
            self.print_info(
                "Administrator privileges required for system-wide installation"
            )

    def setup_node_cert(self):
        """Setup Node.js certificate."""
        if not self.command_exists("node"):
            return

        self.print_info("Setting up Node.js certificate...")

        # Check if NODE_EXTRA_CA_CERTS is already set
        node_extra_ca_certs = os.environ.get("NODE_EXTRA_CA_CERTS", "")
        if node_extra_ca_certs and os.path.exists(node_extra_ca_certs):
            # Use existing file but append certificate if missing
            if not self.certificate_exists_in_file(CERT_PATH, node_extra_ca_certs):
                if not self.is_install_mode():
                    self.print_action(
                        f"Would append {self.get_provider_short_name()} certificate to existing {node_extra_ca_certs}"
                    )
                else:
                    self.append_certificate_if_missing(CERT_PATH, node_extra_ca_certs)
            else:
                self.print_info(
                    f"NODE_EXTRA_CA_CERTS already contains current certificate"
                )
        else:
            # Use consistent bundle management
            bundle_path = self.setup_consistent_bundle(
                "node", env_vars=["NODE_EXTRA_CA_CERTS"]
            )
            if bundle_path:
                self.print_info(f"Node.js configured to use CA bundle: {bundle_path}")

        # Setup npm cafile if npm is available
        if self.command_exists("npm"):
            self.setup_npm_cafile()

    def setup_npm_cafile(self):
        """Setup npm cafile."""
        # Check current npm cafile setting
        try:
            result = subprocess.run(
                ["npm", "config", "get", "cafile"],
                capture_output=True,
                text=True,
            )
            current_cafile = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_cafile = ""

        if current_cafile and current_cafile not in ["null", "undefined"]:
            if os.path.exists(current_cafile):
                # Check if the file contains our certificate
                if not self.certificate_exists_in_file(CERT_PATH, current_cafile):
                    self.print_info("Configuring npm certificate...")

                    if not self.is_install_mode():
                        self.print_action(
                            f"Would append {self.get_provider_short_name()} certificate to {current_cafile}"
                        )
                    else:
                        response = input(
                            f"Found existing npm cafile at {current_cafile}. Append {self.get_provider_short_name()} cert? (Y/n) "
                        )
                        if response.lower() != "n":
                            self.append_certificate_if_missing(
                                CERT_PATH, current_cafile
                            )
            else:
                self.print_warn(
                    f"npm cafile points to non-existent file: {current_cafile}"
                )
        else:
            self.print_info("Configuring npm certificate...")

            # Use consistent bundle management for npm
            bundle_path = self.setup_consistent_bundle("npm")
            if bundle_path and self.is_install_mode():
                try:
                    subprocess.run(
                        ["npm", "config", "set", "cafile", bundle_path],
                        check=True,
                    )
                    self.print_info(f"Configured npm cafile to: {bundle_path}")
                except FileNotFoundError:
                    self.print_warn("npm not found - skipping npm configuration")
                except subprocess.CalledProcessError as e:
                    self.print_error(f"Failed to configure npm: {e}")
            elif not self.is_install_mode():
                npm_bundle = self.get_tool_bundle_path("npm")
                self.print_action(f"Would create npm CA bundle at {npm_bundle}")
                self.print_action(f"Would run: npm config set cafile {npm_bundle}")

    def setup_python_cert(self):
        """Setup Python certificate."""
        if not self.command_exists("python") and not self.command_exists("python3"):
            self.print_info("Python not found, skipping Python setup")
            return

        self.print_info("Setting up Python certificate...")

        # Use consistent bundle management
        bundle_path = self.setup_consistent_bundle(
            "python", env_vars=["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"]
        )

        if bundle_path:
            self.print_info(f"Python configured to use CA bundle: {bundle_path}")

    def setup_gcloud_cert(self):
        """Setup gcloud certificate."""
        if not self.command_exists("gcloud"):
            self.print_info("gcloud not found, skipping gcloud setup")
            return

        self.print_info("Setting up gcloud certificate...")

        # First, try to use Windows certificate store (recommended method)
        self.print_info("gcloud uses Windows certificate store by default")

        # Check if certificate is already in Windows store
        if self.check_certificate_in_store(CERT_PATH, "Root"):
            self.print_info(
                "✓ Certificate already in Windows Root store - gcloud should work"
            )

            # Clear any custom CA file setting to use system store
            try:
                result = subprocess.run(
                    ["gcloud", "config", "get-value", "core/custom_ca_certs_file"],
                    capture_output=True,
                    text=True,
                )
                current_ca_file = (
                    result.stdout.strip() if result.returncode == 0 else ""
                )

                if current_ca_file:
                    if not self.is_install_mode():
                        self.print_action(
                            "Would unset gcloud custom CA to use Windows certificate store"
                        )
                    else:
                        response = input(
                            "Remove custom CA setting to use Windows certificate store? (Y/n) "
                        )
                        if response.lower() != "n":
                            subprocess.run(
                                [
                                    "gcloud",
                                    "config",
                                    "unset",
                                    "core/custom_ca_certs_file",
                                ],
                                capture_output=True,
                            )
                            self.print_info(
                                "Configured gcloud to use Windows certificate store"
                            )
            except Exception:
                pass
            return

        # If certificate not in Windows store, install it there first
        self.print_info("Installing certificate to Windows Root store for gcloud...")
        if self.install_certificate_to_store(CERT_PATH, "Root"):
            self.print_info("✓ Certificate installed to Windows Root store")
            self.print_info("✓ gcloud will now use Windows certificate store")
            return

        # Fallback: If Windows store installation failed, use custom bundle
        self.print_warn(
            "Windows certificate store installation failed, falling back to custom bundle"
        )

        # Check current gcloud custom CA setting
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "core/custom_ca_certs_file"],
                capture_output=True,
                text=True,
            )
            current_ca_file = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca_file = ""

        needs_setup = False
        if not current_ca_file:
            needs_setup = True
        elif os.path.exists(current_ca_file):
            if not self.certificate_exists_in_file(CERT_PATH, current_ca_file):
                needs_setup = True
        else:
            needs_setup = True

        if not needs_setup:
            return

        # Use consistent bundle management as fallback
        bundle_path = self.setup_consistent_bundle("gcloud")
        if bundle_path and self.is_install_mode():
            # Configure gcloud
            result = subprocess.run(
                ["gcloud", "config", "set", "core/custom_ca_certs_file", bundle_path],
                capture_output=True,
            )
            if result.returncode == 0:
                self.print_info(f"gcloud configured to use CA bundle: {bundle_path}")
            else:
                self.print_error("Failed to configure gcloud")
        elif not self.is_install_mode():
            gcloud_bundle = self.get_tool_bundle_path("gcloud")
            self.print_action(f"Would create gcloud CA bundle at {gcloud_bundle}")
            self.print_action(
                f"Would run: gcloud config set core/custom_ca_certs_file {gcloud_bundle}"
            )

    def setup_java_cert(self):
        """Setup Java certificate."""
        if not self.command_exists("java") and not self.command_exists("keytool"):
            return

        # Find JAVA_HOME
        java_home = os.environ.get("JAVA_HOME", "")
        if not java_home and self.command_exists("java"):
            try:
                # Try to find Java installation
                result = subprocess.run(
                    ["where", "java"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    java_path = result.stdout.strip().split("\n")[0]
                    # Navigate up from bin/java.exe to find JAVA_HOME
                    java_home = os.path.dirname(os.path.dirname(java_path))
            except Exception as e:
                self.print_debug(f"Error finding JAVA_HOME: {e}")

        if not java_home:
            self.print_warn("Could not determine JAVA_HOME")
            return

        # Find cacerts file
        cacerts_paths = [
            os.path.join(java_home, "lib", "security", "cacerts"),
            os.path.join(java_home, "jre", "lib", "security", "cacerts"),
        ]

        cacerts = None
        for path in cacerts_paths:
            if os.path.exists(path):
                cacerts = path
                break

        if not cacerts:
            self.print_error("Could not find Java cacerts file")
            return

        # Check if certificate already exists
        try:
            result = subprocess.run(
                [
                    "keytool",
                    "-list",
                    "-alias",
                    self.get_keytool_alias(),
                    "-cacerts",
                    "-storepass",
                    "changeit",
                ],
                capture_output=True,
            )
            if (
                result.returncode == 0
                and self.get_keytool_alias() in result.stdout.decode()
            ):
                # Certificate already exists, nothing to do
                return
        except Exception:
            pass

        self.print_info("Setting up Java certificate...")
        self.print_info(f"Adding certificate to Java keystore: {cacerts}")

        if not self.is_install_mode():
            self.print_action(f"Would import certificate to Java keystore: {cacerts}")
            self.print_action(
                f"Would run: keytool -import -trustcacerts -alias {self.get_keytool_alias()} -file {CERT_PATH} -cacerts -storepass changeit -noprompt"
            )
        else:
            result = subprocess.run(
                [
                    "keytool",
                    "-import",
                    "-trustcacerts",
                    "-alias",
                    self.get_keytool_alias(),
                    "-file",
                    CERT_PATH,
                    "-cacerts",
                    "-storepass",
                    "changeit",
                    "-noprompt",
                ],
                capture_output=True,
            )
            if result.returncode == 0:
                self.print_info("Certificate added to Java keystore successfully")
            else:
                self.print_warn(
                    "Failed to add certificate to Java keystore (may require admin)"
                )

    def setup_wget_cert(self):
        """Setup wget certificate."""
        if not self.command_exists("wget"):
            return

        wgetrc_path = os.path.join(os.path.expanduser("~"), ".wgetrc")
        config_line = f"ca_certificate={CERT_PATH}"

        if os.path.exists(wgetrc_path):
            with open(wgetrc_path, "r") as f:
                content = f.read()

            if "ca_certificate=" in content:
                # Check if it's already set to our certificate
                if CERT_PATH in content:
                    return

                self.print_info("Setting up wget certificate...")
                self.print_warn(f"wget ca_certificate is already set in {wgetrc_path}")

                if not self.is_install_mode():
                    self.print_action(
                        f"Would ask to update the ca_certificate in {wgetrc_path}"
                    )
                    self.print_action(f"Would set: {config_line}")
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() == "y":
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
                        with open(wgetrc_path + ".bak", "w") as f:
                            f.write(content)
                        with open(wgetrc_path, "w") as f:
                            f.write("\n".join(new_lines) + "\n")

                        self.print_info(f"Updated wget configuration in {wgetrc_path}")
                return

        # File doesn't exist or doesn't have ca_certificate
        self.print_info("Setting up wget certificate...")

        if not self.is_install_mode():
            self.print_action(f"Would add to {wgetrc_path}: {config_line}")
        else:
            self.print_info(f"Adding configuration to {wgetrc_path}")
            # Check if configuration already exists to avoid duplicates
            if os.path.exists(wgetrc_path):
                with open(wgetrc_path, "r") as f:
                    existing_content = f.read()
                if config_line in existing_content:
                    self.print_info(
                        "ca_certificate configuration already exists in wget"
                    )
                    return

            with open(wgetrc_path, "a") as f:
                f.write(f"\n{config_line}\n")
            self.print_info("Added ca_certificate to wget configuration")

    def setup_podman_cert(self):
        """Setup Podman certificate."""
        if not self.command_exists("podman"):
            return

        self.print_info("Setting up Podman certificate...")

        # Check if podman machine exists
        try:
            result = subprocess.run(
                ["podman", "machine", "list"],
                capture_output=True,
                text=True,
            )
            if "Currently running" not in result.stdout:
                self.print_warn("No Podman machine is currently running")
                self.print_info(
                    "Please start a Podman machine first with: podman machine start"
                )
                return
        except Exception:
            return

        if not self.is_install_mode():
            self.print_action("Would copy certificate to Podman VM")
            self.print_action(
                f"Would run: podman machine ssh 'sudo tee /etc/pki/ca-trust/source/anchors/{self.get_container_cert_name()}' < {CERT_PATH}"
            )
            self.print_action("Would run: podman machine ssh 'sudo update-ca-trust'")
        else:
            self.print_info(f"Copying {self.get_provider_short_name()} certificate to Podman VM...")

            # Copy certificate into Podman VM
            with open(CERT_PATH, "r") as f:
                cert_content = f.read()

            result = subprocess.run(
                [
                    "podman",
                    "machine",
                    "ssh",
                    f"sudo tee /etc/pki/ca-trust/source/anchors/{self.get_container_cert_name()}",
                ],
                input=cert_content,
                text=True,
                capture_output=True,
            )

            if result.returncode == 0:
                # Update CA trust
                result = subprocess.run(
                    ["podman", "machine", "ssh", "sudo update-ca-trust"],
                    capture_output=True,
                )
                if result.returncode == 0:
                    self.print_info("Podman certificate installed successfully")
                else:
                    self.print_error("Failed to update CA trust in Podman VM")
            else:
                self.print_error("Failed to copy certificate to Podman VM")

    def setup_rancher_cert(self):
        """Setup Rancher certificate."""
        if not self.command_exists("rdctl"):
            return

        self.print_info("Setting up Rancher certificate...")

        if not self.is_install_mode():
            self.print_action("Would copy certificate to Rancher VM")
            self.print_action(
                f"Would run: rdctl shell sudo tee /usr/local/share/ca-certificates/{self.get_container_cert_name()} < {CERT_PATH}"
            )
            self.print_action("Would run: rdctl shell sudo update-ca-certificates")
        else:
            self.print_info(f"Copying {self.get_provider_short_name()} certificate to Rancher VM...")

            # Copy certificate into Rancher VM
            with open(CERT_PATH, "r") as f:
                cert_content = f.read()

            result = subprocess.run(
                [
                    "rdctl",
                    "shell",
                    f"sudo tee /usr/local/share/ca-certificates/{self.get_container_cert_name()}",
                ],
                input=cert_content,
                text=True,
                capture_output=True,
            )

            if result.returncode == 0:
                # Update CA certificates
                result = subprocess.run(
                    ["rdctl", "shell", "sudo update-ca-certificates"],
                    capture_output=True,
                )
                if result.returncode == 0:
                    self.print_info("Rancher certificate installed successfully")
                else:
                    self.print_error("Failed to update CA certificates in Rancher VM")
            else:
                self.print_error("Failed to copy certificate to Rancher VM")

    def setup_git_cert(self):
        """Setup Git certificate."""
        if not self.command_exists("git"):
            return

        self.print_info("Setting up Git certificate...")

        # Check current git SSL CA info setting
        try:
            result = subprocess.run(
                ["git", "config", "--global", "--get", "http.sslCAInfo"],
                capture_output=True,
                text=True,
            )
            current_ca_info = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            current_ca_info = ""

        if current_ca_info:
            # Custom CA file is already configured
            if os.path.exists(current_ca_info):
                if not self.certificate_exists_in_file(CERT_PATH, current_ca_info):
                    if not self.is_install_mode():
                        self.print_action(
                            f"Would append {self.get_provider_short_name()} certificate to {current_ca_info}"
                        )
                    else:
                        response = input(
                            f"Found existing Git CA file at {current_ca_info}. Append {self.get_provider_short_name()} cert? (Y/n) "
                        )
                        if response.lower() != "n":
                            self.append_certificate_if_missing(
                                CERT_PATH, current_ca_info
                            )
            else:
                self.print_warn(
                    f"Git http.sslCAInfo points to non-existent file: {current_ca_info}"
                )

                # Try to create the missing file and directory structure.
                if not self.is_install_mode():
                    self.print_action(
                        f"Would create missing Git CA bundle at {current_ca_info}"
                    )
                    self.print_action(
                        f"Would create directory structure for {os.path.dirname(current_ca_info)}"
                    )
                else:
                    try:
                        # Create the directory structure
                        os.makedirs(os.path.dirname(current_ca_info), exist_ok=True)
                        self.print_info(
                            f"Created directory structure for {current_ca_info}"
                        )

                        # Get system certificates
                        system_certs = self.get_system_ca_bundle()
                        if system_certs:
                            with open(current_ca_info, "w") as f:
                                f.write(system_certs)
                        else:
                            # Create empty file if no system certs available
                            Path(current_ca_info).touch()

                        # Append provider certificate (with duplicate detection)
                        self.append_certificate_if_missing(CERT_PATH, current_ca_info)

                        self.print_info(
                            f"Created Git CA bundle with {self.get_provider_short_name()} certificate at {current_ca_info}"
                        )

                    except Exception as e:
                        self.print_error(f"Failed to create Git CA bundle: {e}")
                        self.print_info("Falling back to creating new bundle...")

                        # Fallback: Use consistent bundle management
                        bundle_path = self.setup_consistent_bundle("git")
                        if bundle_path and self.is_install_mode():
                            # Configure git to use the new bundle
                            result = subprocess.run(
                                [
                                    "git",
                                    "config",
                                    "--global",
                                    "http.sslCAInfo",
                                    bundle_path,
                                ],
                                capture_output=True,
                            )
                            if result.returncode == 0:
                                self.print_info(
                                    f"Git reconfigured to use CA bundle: {bundle_path}"
                                )
                            else:
                                self.print_error("Failed to reconfigure Git")
        else:
            # No custom CA configured - try Windows certificate store first (recommended)
            self.print_info("Git uses Windows certificate store by default")

            # Check if certificate is already in Windows store
            if self.check_certificate_in_store(CERT_PATH, "Root"):
                self.print_info(
                    "✓ Certificate already in Windows Root store - Git should work"
                )
                return

            # If certificate not in Windows store, install it there first
            self.print_info("Installing certificate to Windows Root store for Git...")
            if self.install_certificate_to_store(CERT_PATH, "Root"):
                self.print_info("✓ Certificate installed to Windows Root store")
                self.print_info("✓ Git will now use Windows certificate store")
                return

            # Fallback: If Windows store installation failed, use custom bundle
            self.print_warn(
                "Windows certificate store installation failed, falling back to custom bundle"
            )

            # Use consistent bundle management as fallback
            bundle_path = self.setup_consistent_bundle("git")
            if bundle_path and self.is_install_mode():
                # Configure git
                result = subprocess.run(
                    ["git", "config", "--global", "http.sslCAInfo", bundle_path],
                    capture_output=True,
                )
                if result.returncode == 0:
                    self.print_info(f"Git configured to use CA bundle: {bundle_path}")
                else:
                    self.print_error("Failed to configure Git")
            elif not self.is_install_mode():
                git_bundle = self.get_tool_bundle_path("git")
                self.print_action(f"Would create Git CA bundle at {git_bundle}")
                self.print_action(
                    f"Would run: git config --global http.sslCAInfo {git_bundle}"
                )

    def verify_connection(self, tool_name):
        """Verify if a tool can connect through the proxy."""
        test_url = "https://www.cloudflare.com"
        result = "UNKNOWN"

        self.print_debug(f"Testing {tool_name} connection to {test_url}")

        if tool_name == "node":
            if self.command_exists("node"):
                self.print_debug(f"Node.js found at: {shutil.which('node')}")
                self.print_debug(
                    f"NODE_EXTRA_CA_CERTS: {os.environ.get('NODE_EXTRA_CA_CERTS', 'not set')}"
                )

                # Test SSL connection
                node_script = f"""
const https = require('https');
https.get('{test_url}', {{headers: {{'User-Agent': 'Mozilla/5.0'}}}}, (res) => {{
    console.error('HTTP Status:', res.statusCode);
    console.error('SSL authorized:', res.socket.authorized);
    process.exit(0);
}}).on('error', (err) => {{
    console.error('Error:', err.message);
    console.error('Error code:', err.code);
    process.exit(err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'CERT_HAS_EXPIRED' ? 1 : 0);
}});
"""

                try:
                    proc_result = subprocess.run(
                        ["node", "-e", node_script],
                        capture_output=True,
                        text=True,
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
            # Check if Python trusts the system certificate
            self.print_info(
                f"Checking if Python trusts system {self.get_provider_short_name()} certificate..."
            )

            try:
                # Create a simple HTTPS request
                req = urllib.request.Request(
                    test_url, headers={"User-Agent": "Mozilla/5.0"}
                )

                # Try to open the URL
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.print_debug(f"Success - HTTP {response.code}")
                    result = "WORKING"

                    # Additional validation - check SSL context
                    context = ssl.create_default_context()
                    self.print_debug(
                        f"Python SSL default verify paths: {ssl.get_default_verify_paths()}"
                    )
                    self.print_debug(
                        f"Python successfully trusts the system {self.get_provider_short_name()} certificate"
                    )

            except urllib.error.HTTPError as e:
                self.print_debug(f"HTTP Error {e.code} - but SSL worked")
                # HTTP errors (like 403) are OK - we're testing SSL
                result = "WORKING"
            except urllib.error.URLError as e:
                self.print_debug(f"URL Error: {e.reason}")
                # SSL errors mean the cert isn't trusted
                result = "FAILED"

                # Check if REQUESTS_CA_BUNDLE or SSL_CERT_FILE would help
                if os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get(
                    "SSL_CERT_FILE"
                ):
                    self.print_debug(
                        "Python needs environment variables set for certificate trust"
                    )
                else:
                    self.print_debug(
                        "Python does not trust the system certificate by default"
                    )
            except ssl.SSLError as e:
                self.print_debug(f"SSL Error: {e}")
                result = "FAILED"
            except Exception as e:
                self.print_debug(f"Unexpected error: {type(e).__name__}: {e}")
                result = "FAILED"

        elif tool_name == "curl":
            if self.command_exists("curl"):
                self.print_debug(f"curl found at: {shutil.which('curl')}")

                try:
                    # Test connection
                    if self.is_debug_mode():
                        curl_result = subprocess.run(
                            ["curl", "-v", "-s", "-o", "nul", test_url],
                            capture_output=True,
                            text=True,
                        )
                    else:
                        curl_result = subprocess.run(
                            ["curl", "-s", "-o", "nul", test_url],
                            capture_output=True,
                        )

                    if curl_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("curl test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(
                            f"curl test failed with exit code: {curl_result.returncode}"
                        )

                    if self.is_debug_mode() and curl_result.stderr:
                        # Show relevant SSL info
                        for line in curl_result.stderr.splitlines():
                            if any(
                                keyword in line
                                for keyword in ["SSL", "certificate", "TLS"]
                            ):
                                self.print_debug(f"curl: {line}")
                except Exception as e:
                    self.print_debug(f"curl test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"

        self.print_debug(f"Test result for {tool_name}: {result}")
        return result

    # Status checking functions
    def check_system_status(self, temp_warp_cert):
        """Check Windows certificate store status."""
        has_issues = False

        if self.check_certificate_in_store(temp_warp_cert, "Root"):
            self.print_info("  ✓ Certificate found in Windows Root certificate store")
        else:
            self.print_warn(
                "  ✗ Certificate not found in Windows Root certificate store"
            )
            has_issues = True

        return has_issues

    def check_node_status(self, temp_warp_cert):
        """Check Node.js configuration status."""
        has_issues = False
        if self.command_exists("node"):
            node_extra_ca_certs = os.environ.get("NODE_EXTRA_CA_CERTS", "")
            if node_extra_ca_certs:
                self.print_info(
                    f"  NODE_EXTRA_CA_CERTS is set to: {node_extra_ca_certs}"
                )
                if os.path.exists(node_extra_ca_certs):
                    if self.certificate_exists_in_file(
                        temp_warp_cert, node_extra_ca_certs
                    ):
                        self.print_info(
                            f"  ✓ NODE_EXTRA_CA_CERTS contains current {self.get_provider_short_name()} certificate"
                        )
                        verify_result = self.verify_connection("node")
                        if verify_result == "WORKING":
                            self.print_info(f"  ✓ Node.js can connect through {self.get_provider_short_name()}")
                        else:
                            self.print_warn("  ✗ Node.js connection test failed")
                            has_issues = True
                    else:
                        self.print_warn(
                            f"  ✗ NODE_EXTRA_CA_CERTS file exists but doesn't contain current {self.get_provider_short_name()} certificate"
                        )
                        self.print_action(
                            "    Run with --fix to append the certificate to this file"
                        )
                        has_issues = True
                else:
                    self.print_warn(
                        f"  ✗ NODE_EXTRA_CA_CERTS points to non-existent file: {node_extra_ca_certs}"
                    )
                    has_issues = True
            else:
                self.print_warn("  ✗ NODE_EXTRA_CA_CERTS not configured")
                self.print_info(
                    "    Node.js needs this environment variable to trust additional certificates"
                )
                self.print_action(
                    "    Fix: Run with --fix --tools node to create and configure certificate bundle"
                )
                has_issues = True

            # Check npm
            if self.command_exists("npm"):
                try:
                    result = subprocess.run(
                        ["npm", "config", "get", "cafile"],
                        capture_output=True,
                        text=True,
                    )
                    npm_cafile = result.stdout.strip() if result.returncode == 0 else ""

                    if npm_cafile and npm_cafile not in ["null", "undefined"]:
                        if os.path.exists(npm_cafile):
                            if self.certificate_exists_in_file(
                                temp_warp_cert, npm_cafile
                            ):
                                self.print_info(
                                    f"  ✓ npm cafile contains current {self.get_provider_short_name()} certificate"
                                )
                            else:
                                self.print_warn(
                                    f"  ✗ npm cafile doesn't contain current {self.get_provider_short_name()} certificate"
                                )
                                has_issues = True
                        else:
                            self.print_warn(
                                "  ✗ npm cafile points to non-existent file"
                            )
                            has_issues = True
                    else:
                        self.print_warn("  ✗ npm cafile not configured")
                        has_issues = True
                except Exception:
                    pass
        else:
            self.print_info("  - Node.js not installed")
        return has_issues

    def check_python_status(self, temp_warp_cert):
        """Check Python configuration status."""
        has_issues = False
        if self.command_exists("python") or self.command_exists("python3"):
            # First check if Python trusts the system certificate
            python_verify_result = self.verify_connection("python")

            if python_verify_result == "WORKING":
                self.print_info(
                    f"  ✓ Python trusts the system {self.get_provider_short_name()} certificate"
                )
                self.print_info(
                    f"  ✓ Python can connect through {self.get_provider_short_name()} without additional configuration"
                )

                # Even if system trust works, check if environment variables are set
                # and validate their completeness
                env_vars_set = False
                for env_var in ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]:
                    env_value = self.get_environment_variable(env_var)
                    if env_value:
                        env_vars_set = True
                        if os.path.exists(env_value):
                            if not self.certificate_exists_in_file(
                                temp_warp_cert, env_value
                            ):
                                self.print_warn(
                                    f"  ⚠ {env_var} is set but doesn't contain current {self.get_provider_short_name()} certificate"
                                )
                                self.print_action(
                                    f"    Consider updating {env_value} or unsetting {env_var}"
                                )
                        else:
                            self.print_warn(
                                f"  ⚠ {env_var} points to non-existent file: {env_value}"
                            )
                            has_issues = True

                if not env_vars_set:
                    self.print_info(
                        "  ✓ Using system certificate trust (no custom bundle needed)"
                    )
            else:
                # Python doesn't trust system cert, check environment variables
                python_configured = False

                requests_ca_bundle = self.get_environment_variable("REQUESTS_CA_BUNDLE")
                if requests_ca_bundle:
                    self.print_info(
                        f"  REQUESTS_CA_BUNDLE is set to: {requests_ca_bundle}"
                    )
                    if os.path.exists(requests_ca_bundle):
                        if self.certificate_exists_in_file(
                            temp_warp_cert, requests_ca_bundle
                        ):
                            self.print_info(
                                f"  ✓ REQUESTS_CA_BUNDLE contains current {self.get_provider_short_name()} certificate"
                            )
                            python_configured = True
                        else:
                            self.print_warn(
                                f"  ✗ REQUESTS_CA_BUNDLE file exists but doesn't contain current {self.get_provider_short_name()} certificate"
                            )
                            self.print_action(
                                "    Run with --fix to update the bundle with current certificate"
                            )
                            has_issues = True
                    else:
                        self.print_warn(
                            f"  ✗ REQUESTS_CA_BUNDLE points to non-existent file: {requests_ca_bundle}"
                        )
                        has_issues = True

                # Also check SSL_CERT_FILE if set
                ssl_cert_file = self.get_environment_variable("SSL_CERT_FILE")
                if ssl_cert_file:
                    self.print_info(f"  SSL_CERT_FILE is set to: {ssl_cert_file}")
                    if os.path.exists(ssl_cert_file):
                        if self.certificate_exists_in_file(
                            temp_warp_cert, ssl_cert_file
                        ):
                            self.print_info(
                                f"  ✓ SSL_CERT_FILE contains current {self.get_provider_short_name()} certificate"
                            )
                            python_configured = True
                        else:
                            self.print_warn(
                                f"  ✗ SSL_CERT_FILE file exists but doesn't contain current {self.get_provider_short_name()} certificate"
                            )
                            has_issues = True
                    else:
                        self.print_warn(
                            f"  ✗ SSL_CERT_FILE points to non-existent file: {ssl_cert_file}"
                        )
                        has_issues = True

                if not python_configured:
                    if not requests_ca_bundle and not ssl_cert_file:
                        self.print_warn(
                            "  ✗ Python does not trust system certificate by default"
                        )
                        self.print_warn(
                            "  ✗ No Python certificate environment variables configured"
                        )
                        self.print_action(
                            "    Run with --fix --tools python to configure certificate bundle"
                        )
                        has_issues = True
        else:
            self.print_info("  - Python not installed")
        return has_issues

    def check_gcloud_status(self, temp_warp_cert):
        """Check gcloud configuration status."""
        has_issues = False
        if self.command_exists("gcloud"):
            try:
                result = subprocess.run(
                    ["gcloud", "config", "get-value", "core/custom_ca_certs_file"],
                    capture_output=True,
                    text=True,
                )
                gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""

                if gcloud_ca and os.path.exists(gcloud_ca):
                    # Custom CA file is configured
                    if self.certificate_exists_in_file(temp_warp_cert, gcloud_ca):
                        self.print_info(
                            f"  ✓ gcloud configured with current {self.get_provider_short_name()} certificate (custom bundle)"
                        )
                    else:
                        self.print_warn(
                            f"  ✗ gcloud CA file doesn't contain current {self.get_provider_short_name()} certificate"
                        )
                        has_issues = True
                else:
                    # No custom CA configured - check Windows certificate store (preferred)
                    if self.check_certificate_in_store(temp_warp_cert, "Root"):
                        self.print_info("  ✓ Certificate found in Windows Root store")
                        self.print_info(
                            "  ✓ gcloud using Windows certificate store (recommended)"
                        )
                    else:
                        self.print_warn(
                            "  ✗ Certificate not in Windows store and no custom CA configured"
                        )
                        self.print_action(
                            "    Fix: Run with --fix --tools gcloud to install certificate"
                        )
                        has_issues = True
            except Exception:
                self.print_warn("  ✗ Failed to check gcloud configuration")
                has_issues = True
        else:
            self.print_info("  - gcloud not installed (would configure if present)")
        return has_issues

    def check_java_status(self, temp_warp_cert):
        """Check Java configuration status."""
        has_issues = False
        if self.command_exists("java") or self.command_exists("keytool"):
            if self.command_exists("keytool"):
                try:
                    result = subprocess.run(
                        [
                            "keytool",
                            "-list",
                            "-alias",
                            self.get_keytool_alias(),
                            "-cacerts",
                            "-storepass",
                            "changeit",
                        ],
                        capture_output=True,
                    )
                    if (
                        result.returncode == 0
                        and self.get_keytool_alias() in result.stdout.decode()
                    ):
                        self.print_info(
                            f"  ✓ Java keystore contains {self.get_provider_short_name()} certificate"
                        )
                    else:
                        self.print_warn(
                            f"  ✗ Java keystore missing {self.get_provider_short_name()} certificate"
                        )
                        has_issues = True
                except Exception:
                    self.print_warn("  ✗ Failed to check Java keystore")
                    has_issues = True
            else:
                self.print_warn("  ✗ keytool not found")
                has_issues = True
        else:
            self.print_info("  - Java not installed (would configure if present)")
        return has_issues

    def check_wget_status(self, temp_warp_cert):
        """Check wget configuration status."""
        has_issues = False
        if self.command_exists("wget"):
            wgetrc_path = os.path.join(os.path.expanduser("~"), ".wgetrc")
            if os.path.exists(wgetrc_path):
                with open(wgetrc_path, "r") as f:
                    content = f.read()
                if "ca_certificate=" in content and CERT_PATH in content:
                    self.print_info(f"  ✓ wget configured with {self.get_provider_short_name()} certificate")
                else:
                    self.print_warn(
                        f"  ✗ wget not configured with {self.get_provider_short_name()} certificate"
                    )
                    has_issues = True
            else:
                self.print_warn("  ✗ wget not configured")
                has_issues = True
        else:
            self.print_info("  - wget not installed")
        return has_issues

    def check_podman_status(self, temp_warp_cert):
        """Check Podman configuration status."""
        has_issues = False
        if self.command_exists("podman"):
            try:
                result = subprocess.run(
                    ["podman", "machine", "list"],
                    capture_output=True,
                    text=True,
                )
                if "Currently running" in result.stdout:
                    # Check if certificate exists in Podman VM
                    result = subprocess.run(
                        [
                            "podman",
                            "machine",
                            "ssh",
                            f"test -f /etc/pki/ca-trust/source/anchors/{self.get_container_cert_name()}",
                        ],
                        capture_output=True,
                    )
                    if result.returncode == 0:
                        self.print_info(
                            f"  ✓ Podman VM has {self.get_provider_short_name()} certificate installed"
                        )
                    else:
                        self.print_warn(f"  ✗ Podman VM missing {self.get_provider_short_name()} certificate")
                        has_issues = True
                else:
                    self.print_info("  - Podman installed but no machine is running")
                    self.print_info("    Start a machine with: podman machine start")
            except Exception:
                self.print_info("  - Failed to check Podman status")
        else:
            self.print_info("  - Podman not installed (would configure VM if present)")
        return has_issues

    def check_rancher_status(self, temp_warp_cert):
        """Check Rancher Desktop configuration status."""
        has_issues = False
        if self.command_exists("rdctl"):
            try:
                # Try to check if Rancher is running
                result = subprocess.run(
                    ["rdctl", "version"], capture_output=True, text=True
                )
                if "rdctl" in result.stdout:
                    # Check if certificate exists in Rancher VM
                    result = subprocess.run(
                        [
                            "rdctl",
                            "shell",
                            f"test -f /usr/local/share/ca-certificates/{self.get_container_cert_name()}",
                        ],
                        capture_output=True,
                    )
                    if result.returncode == 0:
                        self.print_info(
                            f"  ✓ Rancher Desktop VM has {self.get_provider_short_name()} certificate installed"
                        )
                    else:
                        self.print_warn(
                            f"  ✗ Rancher Desktop VM missing {self.get_provider_short_name()} certificate"
                        )
                        has_issues = True
                else:
                    self.print_info("  - Rancher Desktop installed but not running")
            except Exception:
                self.print_info("  - Rancher Desktop installed but not running")
        else:
            self.print_info(
                "  - Rancher Desktop not installed (would configure if present)"
            )
        return has_issues

    def check_git_status(self, temp_warp_cert):
        """Check Git configuration status."""
        has_issues = False
        if self.command_exists("git"):
            try:
                result = subprocess.run(
                    ["git", "config", "--global", "--get", "http.sslCAInfo"],
                    capture_output=True,
                    text=True,
                )
                git_ca_info = result.stdout.strip() if result.returncode == 0 else ""

                if git_ca_info and os.path.exists(git_ca_info):
                    # Custom CA file is configured
                    if self.certificate_exists_in_file(temp_warp_cert, git_ca_info):
                        self.print_info(
                            f"  ✓ Git configured with current {self.get_provider_short_name()} certificate (custom bundle)"
                        )
                    else:
                        self.print_warn(
                            f"  ✗ Git CA file doesn't contain current {self.get_provider_short_name()} certificate"
                        )
                        has_issues = True
                else:
                    # No custom CA configured - check Windows certificate store (preferred)
                    if self.check_certificate_in_store(temp_warp_cert, "Root"):
                        self.print_info("  ✓ Certificate found in Windows Root store")
                        self.print_info(
                            "  ✓ Git using Windows certificate store (recommended)"
                        )
                    else:
                        self.print_warn(
                            "  ✗ Certificate not in Windows store and no custom CA configured"
                        )
                        self.print_action(
                            "    Fix: Run with --fix --tools git to install certificate"
                        )
                        has_issues = True
            except Exception:
                self.print_warn("  ✗ Failed to check Git configuration")
                has_issues = True
        else:
            self.print_info("  - Git not installed")
        return has_issues

    def check_all_status(self):
        """Check status of all configurations."""
        has_issues = False
        temp_warp_cert = None
        provider_name = self.get_provider_name()
        short_name = self.get_provider_short_name()

        self.print_info(f"Checking {provider_name} Certificate Status")
        self.print_info("=" * len(f"Checking {provider_name} Certificate Status"))
        print()

        temp_warp_cert = self.get_status_cert_file()
        if not temp_warp_cert:
            return

        self.print_debug(f"Retrieved {short_name} certificate for comparison")
        self.cert_fingerprint = self.get_cert_fingerprint(temp_warp_cert)
        self.print_debug(
            f"{short_name} certificate fingerprint: {self.cert_fingerprint}"
        )

        if self.check_provider_connection():
            has_issues = True
        print()

        self.print_status("Certificate Status:")

        try:
            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-noout",
                    "-checkend",
                    "86400",
                    "-in",
                    temp_warp_cert,
                ],
                capture_output=True,
            )
            if result.returncode == 0:
                self.print_info(f"  ✓ {short_name} certificate is valid")
            else:
                raise Exception("OpenSSL validation failed")
        except Exception as e:
            self.print_debug(
                f"OpenSSL not available, trying PowerShell validation: {e}"
            )
            try:
                ps_command = f"""
                try {{
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{self._ps_escape(temp_warp_cert)}')
                    $now = Get-Date
                    $expiry = $cert.NotAfter
                    $daysUntilExpiry = ($expiry - $now).Days

                    if ($daysUntilExpiry -gt 1) {{
                        Write-Output "Valid"
                        exit 0
                    }} else {{
                        Write-Output "Expiring"
                        exit 1
                    }}
                }} catch {{
                    Write-Output "Invalid"
                    exit 2
                }}
                """

                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    self.print_info(f"  ✓ {short_name} certificate is valid")
                elif result.returncode == 1:
                    self.print_warn(
                        f"  ✗ {short_name} certificate is expired or expiring soon"
                    )
                    has_issues = True
                else:
                    self.print_error(f"  ✗ {short_name} certificate is invalid")
                    has_issues = True
            except Exception as ps_e:
                self.print_error("  ✗ Failed to check certificate validity")
                self.print_debug(f"PowerShell validation error: {ps_e}")
                has_issues = True

        cert_locations = []
        cert_found = False

        if os.path.exists(CERT_PATH):
            with open(CERT_PATH, "r") as f:
                existing_cert = f.read()
            with open(temp_warp_cert, "r") as f:
                current_cert_content = f.read()
            if existing_cert == current_cert_content:
                cert_locations.append(f"    - {CERT_PATH}")
                cert_found = True

        if self.check_certificate_in_store(temp_warp_cert, "Root"):
            cert_locations.append("    - Windows Root certificate store")
            cert_found = True

        for env_var in [
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
        ]:
            env_value = self.get_environment_variable(env_var)
            if env_value and os.path.exists(env_value):
                if self.certificate_exists_in_file(temp_warp_cert, env_value):
                    cert_locations.append(f"    - {env_value} ({env_var})")
                    cert_found = True

        if cert_found:
            self.print_info(f"  ✓ {short_name} certificate found in:")
            for loc in cert_locations:
                print(loc)
        else:
            self.print_warn(
                f"  ✗ {short_name} certificate not found in any configured location"
            )
            self.print_action("    Run with --fix to install the certificate")
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
            if tool_info.get("check_func"):
                tool_has_issues = tool_info["check_func"](temp_warp_cert)
                if tool_has_issues:
                    has_issues = True
            print()

        if not self.selected_tools:
            self.print_status("curl Configuration:")
            if self.command_exists("curl"):
                verify_result = self.verify_connection("curl")
                if verify_result == "WORKING":
                    self.print_info(f"  ✓ curl can connect through {short_name}")
                    if os.environ.get("CURL_CA_BUNDLE"):
                        self.print_info(
                            f"  ✓ CURL_CA_BUNDLE is set to: {os.environ['CURL_CA_BUNDLE']}"
                        )
                    else:
                        self.print_info("  ✓ Using Windows certificate store")
                else:
                    if os.environ.get("CURL_CA_BUNDLE"):
                        self.print_info("  ✓ CURL_CA_BUNDLE is set")
                    else:
                        self.print_warn(
                            "  ✗ curl failed due to Windows certificate revocation check issue"
                        )
                        self.print_info(
                            "    This is a common Windows networking issue, not a certificate problem"
                        )
                        self.print_action(
                            "    Fix: Run with --fix to set CURL_CA_BUNDLE environment variable"
                        )
                        has_issues = True
            else:
                self.print_info("  - curl not installed")
            print()

        self.print_info("Summary:")
        self.print_info("========")
        if has_issues:
            self.print_warn("Some configurations need attention.")
            self.print_action("Run 'python fumitm_windows.py --fix' to fix the issues")
        else:
            self.print_info(f"✓ All configured tools are properly set up for {provider_name}")
        print()

        if temp_warp_cert:
            os.unlink(temp_warp_cert)

    def main(self):
        """Main function."""
        try:
            header = f"{self.get_provider_name()} Certificate Installation Script (Windows)"
            self.print_info(header)
            self.print_info("=" * len(header))

            if self.is_debug_mode():
                self.print_debug(
                    f"Fumitm version: {VERSION_INFO['version']} (commit: {VERSION_INFO['commit']})"
                )
                self.print_debug(
                    f"Branch: {VERSION_INFO['branch']} | Date: {VERSION_INFO['date']}"
                )
                if VERSION_INFO["dirty"]:
                    self.print_debug("Working directory has uncommitted changes")
                self.print_debug(f"Script: Windows implementation")
                self.print_debug(f"Running on: {platform.platform()}")
                self.print_debug(f"Python version: {sys.version}")
                self.print_debug(f"Home directory: {os.path.expanduser('~')}")
                self.print_debug(f"Certificate path: {CERT_PATH}")
                self.print_debug(f"Administrator: {self.is_admin()}")
                if not self.is_install_mode():
                    self.print_debug("Status mode: Using fast certificate checks")
                else:
                    self.print_debug("Install mode: Using thorough certificate checks")
                if self.selected_tools:
                    self.print_debug(
                        f"Selected tools: {', '.join(self.selected_tools)}"
                    )
                print()

            # Validate selected tools
            if self.selected_tools:
                invalid_tools = self.validate_selected_tools()
                if invalid_tools:
                    self.print_error(
                        f"Invalid tool selection: {', '.join(invalid_tools)}"
                    )
                    self.print_info(
                        "Use --list-tools to see available tools and their tags"
                    )
                    return 1

                # Show which tools will be processed
                selected_info = self.get_selected_tools_info()
                if not selected_info:
                    self.print_warn("No tools match your selection")
                    return 1

            if not self.is_install_mode():
                # In status mode, just check current status
                self.check_all_status()
            else:
                self.print_info(
                    "Running in FIX mode - changes will be made to your system"
                )
                print()

                # Download and verify certificate
                if not self.download_certificate():
                    self.print_error("Failed to download certificate. Exiting.")
                    return 1

                # Setup for different environments
                if self.selected_tools:
                    self.print_info(
                        f"Processing selected tools: {', '.join(self.get_selected_tools_info())}"
                    )
                    print()

                for tool_key, tool_info in self.tools_registry.items():
                    if self.should_process_tool(tool_key):
                        if tool_info.get("setup_func"):
                            tool_info["setup_func"]()

                # Final message
                print()
                self.print_info("Installation completed!")

                if self.shell_modified:
                    self.print_warn("Environment variables were modified.")
                    self.print_warn(
                        "Please restart your command prompt or PowerShell session"
                    )
                    self.print_warn("Or run: refreshenv (if using Chocolatey)")

            print()
            self.print_info(f"Certificate location: {CERT_PATH}")
            self.print_info(
                "For additional applications, please refer to the documentation."
            )

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
    # Build version string
    version_str = f"Version: {VERSION_INFO['version']}"
    if VERSION_INFO["commit"] != "unknown":
        version_str += f" (commit: {VERSION_INFO['commit']})"
    if VERSION_INFO["dirty"]:
        version_str += " [modified]"

    parser = argparse.ArgumentParser(
        description="MITM Certificate Fixer Upper for Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python fumitm_windows.py                    # Check status of all tools
  python fumitm_windows.py --fix              # Fix all detected issues
  python fumitm_windows.py --provider netskope --fix
  python fumitm_windows.py --tools node       # Check only Node.js
  python fumitm_windows.py --fix --tools python,git  # Fix Python and Git only
  python fumitm_windows.py --list-tools       # Show available tools

{version_str} | Default: status check only (use --fix to make changes)
        """,
    )

    # Main operation modes
    mode_group = parser.add_argument_group("Operation Modes")
    mode_group.add_argument(
        "--fix",
        action="store_true",
        help="Apply fixes to certificate configurations (default: status check only)",
    )
    mode_group.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available tools and their tags, then exit",
    )

    # Tool selection
    tool_group = parser.add_argument_group("Tool Selection")
    tool_group.add_argument(
        "--tools",
        "--tool",
        action="append",
        dest="tools",
        metavar="TOOL",
        help="Select specific tools to process (can be used multiple times)\n"
        "Use tool names or tags. Examples: node, python, gcloud, node-npm",
    )

    # Certificate options
    cert_group = parser.add_argument_group("Certificate Options")
    cert_group.add_argument(
        "--provider",
        choices=list(PROVIDERS.keys()),
        default=None,
        help="MITM proxy provider to use (default: auto-detect)",
    )
    cert_group.add_argument(
        "--use-warp-cli",
        action="store_true",
        help="Force fresh certificate generation from WARP client\n"
        "(bypasses cached certificates)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--debug",
        "--verbose",
        action="store_true",
        help="Show detailed debug information and verbose output",
    )

    args = parser.parse_args()

    # Handle --list-tools first
    if args.list_tools:
        # Create a temporary instance just to access the registry
        temp_fumitm = FumitmWindows()
        print("Available tools:")
        for tool_key, tool_info in temp_fumitm.tools_registry.items():
            tags_str = ", ".join(tool_info["tags"])
            print(f"  {tool_key:<10} - {tool_info['name']:<25} Tags: {tags_str}")
        print("\nExamples: python fumitm_windows.py --fix --tools node,python")
        print(
            "          python fumitm_windows.py --fix --tools node-npm --tools podman"
        )
        sys.exit(0)

    # Process --tools argument
    selected_tools = []
    if args.tools:
        for tool_arg in args.tools:
            # Split by comma to allow comma-separated lists
            selected_tools.extend([t.strip() for t in tool_arg.split(",") if t.strip()])

    # Determine mode
    mode = "install" if args.fix else "status"

    # Create and run fumitm instance
    fumitm = FumitmWindows(
        mode=mode,
        debug=args.debug,
        selected_tools=selected_tools,
        use_warp_cli=args.use_warp_cli,
        provider=args.provider,
    )
    exit_code = fumitm.main()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
