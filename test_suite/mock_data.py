"""
Centralized mock data for fumitm tests.

This module contains all mock responses and test data used across the test suite.
"""

# Certificate mock data
MOCK_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIEjTCCA3WgAwIBAgISA2Q1Q5XQHgYE8xhA9PkyCgypMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA4MTUwODEwMDBaFw0yMzExMTMwODA5NTlaMB8xHTAbBgNVBAMT
FGNsb3VkZmxhcmUtd2FycC10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwgHpYxGNaDbTlLGmq3tJmKPa3LX9ZbN1kJ4YPYa+LK5XQYQ7Q4J8F9GV
C0TpCcCfKm2s3q6pYKQQdJzQ4LKx8s5DKP2Q7s8F4qJ6YZ8dP3fE4qK9w2nRX6yY
XmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvJ4qJ6YZ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2nRX6yYXmGF7aP4n5wvYJ8dP3fE4qK9w2n
RX6yYXmGF7aP4n5wvQIDAQABo4IBYjCCAV4wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBRfON9UGKLKczKsQF9JKJzS8e1F3jAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDm
H6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5v
LmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAf
BgNVHREEGDAWghRjbG91ZGZsYXJlLXdhcnAtdGVzdDBMBgNVHSAERTBDMAgGBmeB
DAECATAXBgsrBgEEAYKkTgIBAQQIMAYGBFUdIAAwHgYLKwYBBAGCpE4CAQIEDzAN
BgRVHSAAMAUGA1UdIAAwDQYJKoZIhvcNAQELBQADggEBAHZ2qgK7ZxQwQXhY4jFH
CcT9lk8Sy9fQHXvYf4N1lQqB4hKZHF8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9fQHXv
Yf4N1lQqB4hKZHF8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9fQHXvYf4N1lQqB4hKZHF
8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9fQHXvYf4N1lQqB4hKZHF8nZ2qG7ZxQwQXhY
4jFHCcT9lk8Sy9fQHXvYf4N1lQqB4hKZHF8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9f
QHXvYf4N1lQqB4hKZHF8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9fQHXvYf4N1lQqB4h
KZHF8nZ2qG7ZxQwQXhY4jFHCcT9lk8Sy9fQHXvYf4N1lQqB4hKZHF8nZ2qG=
-----END CERTIFICATE-----"""

MOCK_INVALID_CERTIFICATE = """-----BEGIN CERTIFICATE-----
INVALID_CERT_DATA_HERE
-----END CERTIFICATE-----"""

# Warp CLI mock responses
WARP_STATUS_CONNECTED = """Status update: Connected
Success"""

WARP_STATUS_DISCONNECTED = """Status update: Disconnected
Success"""

WARP_STATUS_ERROR = """Error: Unable to connect to daemon"""

# Tool command outputs
NODE_VERSION = "v18.17.0"
NPM_VERSION = "9.6.7"
PYTHON_VERSION = "Python 3.11.5"
JAVA_VERSION = """openjdk version "17.0.8" 2023-07-18
OpenJDK Runtime Environment (build 17.0.8+7)
OpenJDK 64-Bit Server VM (build 17.0.8+7, mixed mode, sharing)"""

# NPM config outputs
NPM_CONFIG_CAFILE_NULL = "null"
NPM_CONFIG_CAFILE_SET = "/Users/test/.npm/ca-bundle.pem"

# Certificate verification outputs
OPENSSL_VERIFY_SUCCESS = "verify return:1"
OPENSSL_VERIFY_FAILURE = "verify error:num=20:unable to get local issuer certificate"

OPENSSL_FINGERPRINT = "SHA256 Fingerprint=AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78"

# Python certifi paths
CERTIFI_PATH_MACOS = "/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages/certifi/cacert.pem"
CERTIFI_PATH_LINUX = "/usr/local/lib/python3.11/site-packages/certifi/cacert.pem"

# Java cacerts paths
JAVA_CACERTS_MACOS = "/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home/lib/security/cacerts"
JAVA_CACERTS_LINUX = "/usr/lib/jvm/java-17-openjdk/lib/security/cacerts"

# Error messages
PERMISSION_DENIED_ERROR = "Permission denied"
NETWORK_ERROR = "Network is unreachable"
FILE_NOT_FOUND_ERROR = "No such file or directory"

# Sample CA bundle content (for testing certificate appending)
SAMPLE_CA_BUNDLE = """# Mozilla CA Bundle
# This is a bundle of X.509 certificates of public Certificate Authorities

-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
"""

# Sample CA bundle WITHOUT trailing newline (edge case for issue #13)
# This simulates files created by editors that don't add trailing newlines
SAMPLE_CA_BUNDLE_NO_NEWLINE = """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
-----END CERTIFICATE-----"""

# Certificate content WITHOUT trailing newline (edge case)
MOCK_CERTIFICATE_NO_NEWLINE = """-----BEGIN CERTIFICATE-----
MIIEjTCCA3WgAwIBAgISA2Q1Q5XQHgYE8xhA9PkyCgypMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA4MTUwODEwMDBaFw0yMzExMTMwODA5NTlaMB8xHTAbBgNVBAMT
FGNsb3VkZmxhcmUtd2FycC10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
-----END CERTIFICATE-----"""

# Network test URLs
TEST_HTTPS_URL = "https://cloudflare.com"
TEST_HTTPS_RESPONSE = """<!DOCTYPE html>
<html>
<head><title>Cloudflare</title></head>
<body>Test response</body>
</html>"""

# Tool binary paths
TOOL_PATHS = {
    'warp-cli': '/usr/local/bin/warp-cli',
    'node': '/usr/local/bin/node',
    'npm': '/usr/local/bin/npm',
    'python3': '/usr/bin/python3',
    'java': '/usr/bin/java',
    'gcloud': '/usr/local/bin/gcloud',
    'curl': '/usr/bin/curl',
    'git': '/usr/bin/git',
    'wget': '/usr/bin/wget',
    'podman': '/usr/local/bin/podman',
    'rancher': '/usr/local/bin/rancher',
    'emulator': '/Users/test/Library/Android/sdk/emulator/emulator',
    'dbeaver': '/Applications/DBeaver.app/Contents/MacOS/dbeaver',
    'openssl': '/usr/bin/openssl',
}

# Netskope certificate paths
NETSKOPE_CERT_PATHS_MACOS = [
    '/Library/Application Support/Netskope/STAgent/data/nscacert_combined.pem',
    '/Library/Application Support/Netskope/STAgent/data/nscacert.pem',
]
NETSKOPE_CERT_PATHS_LINUX = ['/opt/netskope/stagent/data/nscacert.pem']

# Netskope mock certificate (reuses the same cert format for testing)
MOCK_NETSKOPE_CERTIFICATE = MOCK_CERTIFICATE

# Shell detection outputs
SHELL_PS_BASH = "/bin/bash"
SHELL_PS_ZSH = "/bin/zsh"
SHELL_PS_FISH = "/usr/local/bin/fish"

# Home directory paths
HOME_DIR = "/Users/test"
TEMP_DIR = "/tmp"
