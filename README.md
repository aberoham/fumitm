# fumitm (MITM Certificate .. Fixer Upper)

Script to automatically verify and fix MITM TLS distrust issues commonly afflicting corporate device users who are subject to traffic inspection via agents such as Cloudflare Warp, Netskope or ZScaler.

## Usage

### Linux/macOS

```bash
# Download the script
curl -LsSf https://raw.githubusercontent.com/aberoham/fumitm/main/fumitm.py -o fumitm.py
chmod +x ./fumitm.py

# Check status (no changes made)
./fumitm.py

# Apply fixes
./fumitm.py --fix

# Run with detailed debug output (useful for troubleshooting)
./fumitm.py --debug
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
- Cloudflare WARP or Netskope Client must be installed and connected
- `warp-cli` or `nsdiag` command must be available 
- Python 3 (macOS, Windows/WSL)

### Windows-Specific
- `warp-cli.exe` or `nsdiag.exe` command must be available 
- Administrator privileges may be required for some fixes

## Contribute

Something amiss or not quite right? Please post the full output of a run to an issue or simply submit a PR

## List of supported fixes

### Linux/macOS
- **Node.js/npm**: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm
- **Python**: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables
- **gcloud**: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI
- **Git**: configures Git to use the custom certificate bundle via `http.sslCAInfo`
- **curl**: configures `CURL_CA_BUNDLE` environment variable for curl
- **Java/JVM**: adds the Cloudflare certificate to any found Java keystore (cacerts)
- **jenv**: adds the Cloudflare certificate to all jenv-managed Java installations
- **DBeaver**: targets the bundled JRE and adds the certificate to its keystore
- **wget**: configures the `ca_certificate` in the `.wgetrc` file
- **Podman**: installs certificate in `~/.docker/certs.d/` (persistent) and Podman VM's trust store (if running)
- **Rancher Desktop**: installs certificate in `~/.docker/certs.d/` (persistent) and Rancher VM's trust store (if running)
- **Colima**: installs certificate in `~/.docker/certs.d/` (persistent, applied on start) and Colima VM's trust store (if running)
- **Android Emulator**: helps install certificate on running Android emulators
- **Gradle**: sets `systemProp` entries in `gradle.properties` (respecting `GRADLE_USER_HOME`) for the WARP certificate.
 
### Windows
- **Node.js/npm**: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm
- **Python**: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables
- **Google Cloud SDK (gcloud)**: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI
- **Java/JVM**: adds the Cloudflare certificate to any found Java keystore (cacerts)
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

Fumitm should auto-detect VS Code devcontainers and WSL environments where `warp-cli`/`nsdiag` is only available on the underlying host. Within these environments, fumitm will guide the user where to obtain their MITM cert and will skip slow verification tests.

## Troubleshooting

If you encounter issues:

1. Ensure your MITM is connected: `warp-cli status`, `nsdiag -f`
2. Run with debug output: `./fumitm.py --debug` (Linux/macOS) or `python fumitm_windows.py --debug` (Windows)
3. Check that Python 3 is properly installed and in your PATH
4. Verify you have appropriate permissions for the tools you're trying to fix

