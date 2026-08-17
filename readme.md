# Python Network Security Scanner

**Author:** Maram Bellili
**Version:** 9.0

A Python-based network security scanner developed to understand network reconnaissance, socket programming, service detection, banner grabbing, service fingerprinting, and basic vulnerability mapping.

The project evolved from a simple TCP port scanner into a more complete educational network security tool.

## Features

* TCP port scanning
* Optional UDP scanning
* IPv4 / IPv6 support
* Host discovery
* Configurable port ranges
* Quick and full scan modes
* Multithreaded scanning
* Protocol-specific probes
* Banner grabbing
* Service fingerprinting
* Application detection
* Version detection
* Regex-based signatures
* Confidence scoring
* TLS / HTTPS analysis
* Educational CVE reference lookup
* Risk summary
* TXT report generation
* Optional JSON report generation
* Quiet mode

## Technologies

* Python
* Socket programming
* TCP/IP
* UDP
* IPv4 / IPv6
* TLS / SSL
* Regular expressions
* ThreadPoolExecutor

## Detection Workflow

```text
Target
  ↓
Hostname / IP resolution
  ↓
Host discovery (optional)
  ↓
TCP / UDP port scanning
  ↓
Protocol-specific probe
  ↓
Banner / response
  ↓
Fingerprinting
  ├── Service
  ├── Application
  ├── Version
  └── Confidence
  ↓
Educational CVE lookup
  ↓
Risk summary
  ↓
TXT / JSON report
```

## Fingerprinting

A port number is only a hint.

For example:

```text
22  → probably SSH
80  → probably HTTP
443 → probably HTTPS
```

The scanner analyzes the service response to improve identification.

Example:

```text
Banner:
SSH-2.0-OpenSSH_8.9p1

Result:
Service      : SSH
Application  : OpenSSH
Version      : 8.9p1
Confidence   : HIGH
```

### Confidence Levels

| Level    | Meaning                                                       |
| -------- | ------------------------------------------------------------- |
| `HIGH`   | Service, application and version identified                   |
| `MEDIUM` | Service identified, but application and/or version is missing |
| `LOW`    | No matching signature; identification is uncertain            |

## TCP and UDP

### TCP

The scanner attempts a TCP connection to the selected ports. Open ports can then be analyzed through banner grabbing and fingerprinting.

### UDP

The scanner sends protocol-specific probes when available.

Examples:

```text
UDP 53  → DNS probe
UDP 123 → NTP probe
```

UDP results may include:

```text
OPEN
OPEN|FILTERED
```

`OPEN|FILTERED` means that no response was received, so the scanner cannot determine the exact state.

## TLS / HTTPS

Ports such as `443` and `8443` receive special TLS handling.

The scanner performs a TLS handshake before sending an HTTP request.

```text
TCP
 ↓
TLS handshake
 ↓
TLS version / Cipher
 ↓
HTTP request
 ↓
HTTP response
 ↓
Fingerprinting
```

## Host Discovery

The scanner provides a lightweight host-discovery mode:

```bash
python scanner.py 192.168.1.0/24 --discover
```

The discovery process checks a small set of common TCP ports to determine whether an IP appears to be active.

This method does not use ICMP ping and may miss hosts that block all tested ports.

## Educational CVE Mapping

The project includes a small local reference table linking selected application/version pairs to known CVEs.

Example:

```text
vsFTPd 2.3.4
    ↓
CVE-2011-2523
    ↓
Critical
```

This is an **educational reference lookup**, not a real vulnerability scanner.

A CVE match does not prove that a target is exploitable because the system may be patched, backported, mitigated, or configured differently.

No exploit payloads are sent.

## Project Evolution

```text
V1 — Basic TCP Port Scanner
V2 — Service Identification
V3 — Improved Output
V4 — Report Generation
V5 — Banner Grabbing
V6 — Multithreaded Scanning
V7 — Scanner Architecture Improvements
V8 — Multi-Protocol Banner Probing
V9 — Service Fingerprinting
     + UDP
     + IPv4 / IPv6
     + TLS / HTTPS
     + Host Discovery
     + Educational CVE Mapping
```

## Usage

### Basic scan

```bash
python scanner.py 127.0.0.1
```

### Quick scan

```bash
python scanner.py 127.0.0.1 --quick
```

### Custom port range

```bash
python scanner.py 192.168.1.10 -p 1-1024
```

### Full scan

```bash
python scanner.py 192.168.1.10 --full
```

### TCP + UDP

```bash
python scanner.py 192.168.1.10 -p 1-200 --udp
```

### JSON report

```bash
python scanner.py 192.168.1.10 -p 1-1000 --json
```

### Host discovery

```bash
python scanner.py 192.168.1.0/24 --discover
```

### Quiet mode

```bash
python scanner.py 127.0.0.1 -p 1-1000 -q
```

## Command-Line Options

| Option            | Description                                   | Default  |
| ----------------- | --------------------------------------------- | -------- |
| `-p`, `--ports`   | Port range                                    | `1-1024` |
| `--quick`         | Scan common ports                             | Off      |
| `--full`          | Scan all 65535 ports                          | Off      |
| `--discover`      | Discover active-looking hosts in a CIDR range | Off      |
| `-t`, `--threads` | Number of worker threads                      | `50`     |
| `--timeout`       | Per-port timeout                              | `0.7s`   |
| `--udp`           | Enable UDP scanning                           | Off      |
| `--json`          | Generate JSON report                          | Off      |
| `-o`, `--output`  | Report filename base                          | `report` |
| `-q`, `--quiet`   | Suppress per-port output                      | Off      |
| `--version`       | Show scanner version                          | `9.0`    |

## Example Output

```text
Port 21   /tcp  OPEN
Detected service : FTP
Application      : vsFTPd
Version          : 2.3.4
Confidence       : HIGH
Banner           : 220 (vsFTPd 2.3.4)

! CVE-2011-2523 (Critical)
```

## Known Limitations

* Host discovery can miss systems that block all tested TCP ports.
* UDP results can be ambiguous when no response is received.
* Fingerprinting depends on the information returned by the target.
* The CVE database is intentionally small and educational.
* TLS analysis does not perform full X.509 certificate-chain analysis.

## What I Learned

This project helped me understand:

* Python socket programming
* TCP vs UDP
* Port scanning
* Protocol-specific probing
* Banner grabbing
* Regex-based fingerprinting
* Service and version detection
* Confidence scoring
* TLS / HTTPS
* IPv4 and IPv6 networking
* Multithreaded scanning
* Host discovery
* Basic CVE mapping
* Security report generation

## Disclaimer

This project is intended for **educational purposes and authorized security testing only**.

Use it only on your own systems, laboratory environments, or targets for which you have explicit permission to test.

Do not scan systems or networks without permission.
