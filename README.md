# ReconForge

ReconForge is an initial development milestone for authorized network reconnaissance and security learning in environments you own or have explicit permission to assess. It uses Nmap to collect observations, then parses, classifies, stores, and reports that evidence.

## Safety and scope

Use ReconForge only on authorized systems and networks. ReconForge does not implement exploitation, credential attacks, stealth or evasion, persistence, malware, destructive testing, or log deletion. Reports describe observed evidence; OS scores are heuristic evidence totals, not probabilities or vulnerability assessments.

## Current capabilities

The current CLI supports:

```text
reconforge scan <CIDR>
reconforge scans
reconforge hosts <scan-id>
reconforge services <scan-id>
reconforge show <scan-id>
reconforge resume <scan-id>
reconforge attack-surface <scan-id>
reconforge diff <baseline-scan-id> <current-scan-id>
reconforge coverage <scan-id>
reconforge version
```

Commands that operate on stored data accept `--data-dir <path>` to select a data directory. `scan` also accepts `--timeout <seconds>`. Attack-surface, diff, and coverage reports default to terminal output and support `--format json` and `--output <path>` for JSON files.

`hosts` lists persisted host observations for one scan. `services` lists the persisted service observations for a scan, grouped by host. `show` displays a scan's phase history, artifact presence, and host/service summary. `resume` plans and performs recovery for eligible incomplete scans.

## Scan workflow

```text
CIDR
  ↓
scope validation
  ↓
Nmap profiles
  ├── discovery
  ├── ports
  ├── services
  └── os
  ↓
XML artifacts
  ↓
parsing
  ↓
OS classification
  ↓
SQLite persistence
  ↓
reporting
```

Each phase writes an XML artifact in its scan directory. ReconForge parses those artifacts into typed host, service, and raw OS fingerprint observations, merges observations across phases, classifies OS evidence, and persists results. If collection is interrupted or fails in a recoverable state, `resume` uses the manifest and phase dependencies to determine what needs to run again, retaining successful artifacts.

Nmap profiles are defined in `reconforge/nmap/profiles.py`; `reconforge/nmap/runner.py` is the only component that invokes Nmap. The runner uses an argument list without shell interpretation. Targets are restricted to IPv4 addresses/networks.

## Service metadata collection

After Nmap service detection, the enumeration engine selects bounded modules using service metadata:

- **HTTP:** requests a bounded page response and records status, server, content type, and a simple page title. It does not store the page body.
- **TLS:** connects to matching TLS/HTTPS services and records certificate subject, issuer, negotiated TLS protocol, and up to eight DNS subject alternative names.
- **SSH:** reads the server banner without authentication and records the banner, recognized SSH protocol version, and OpenSSH identification when present.

These modules use short timeouts and return structured evidence. They do not authenticate to services. Unsupported service metadata does not select a module.

## Architecture

- `reconforge/cli.py` parses commands and delegates work.
- `reconforge/core/controller.py` coordinates scan phases, recovery, persistence calls, and read-only report workflows.
- `reconforge/nmap/profiles.py` defines the discovery, ports, services, and OS argument profiles.
- `reconforge/nmap/runner.py` validates and invokes Nmap, capturing execution results and XML artifact paths.
- `reconforge/parsers/nmap_xml.py` parses existing Nmap XML into typed models in `reconforge/core/models.py`.
- `reconforge/core/classifier.py` classifies OS families from Nmap fingerprints and configured service/product indicators in `reconforge/signatures/os_indicators.json`.
- `reconforge/enumeration/engine.py` and `modules.py` select and run the bounded HTTP, TLS, and SSH metadata collectors.
- `reconforge/core/repository.py` owns SQLite schema initialization and SQL persistence/retrieval.
- `reconforge/correlation/engine.py`, `diff/engine.py`, and `coverage/engine.py` derive read-only attack-surface, change, and evidence-coverage models.
- `reconforge/reports/terminal.py` renders terminal summaries; `reports/structured.py` serializes supported models to deterministic JSON.

## Data and storage

By default, the SQLite database is `data/reconforge.db`. Per-scan manifests and generated Nmap XML artifacts are stored under `data/scans/<scan-id>/`. The manifest records workflow and phase execution history; SQLite stores parsed scan, host, service, OS fingerprint, and enumeration evidence.

The database and generated scan artifacts are runtime data and are excluded from Git by default. This avoids committing local scan results. `data/scans/.gitkeep` preserves the empty directory in a checkout. Test fixtures under `tests/fixtures/` are source-controlled examples, not runtime scan output.

SQLite schema migrations are deferred; the repository currently creates its schema when initialized.

## Installation and usage

Requirements: Python 3.11 or newer and Nmap installed separately and available as `nmap` on `PATH`. OS fingerprinting may require privileges supported by the local Nmap installation.

From the repository root, install the project in editable mode and run the CLI:

The `192.0.2.0/24` target below is a documentation-only placeholder. Substitute a target you are authorized to scan before running the command.

```bash
python -m pip install -e .
reconforge version
reconforge scan 192.0.2.0/24
reconforge scans
reconforge hosts <scan-id>
reconforge show <scan-id>
reconforge attack-surface <scan-id> --format json
```

The same CLI is available without installing the console script using `python -m reconforge <command>`. Only scan networks for which you have explicit authorization.

## Tests

Run the test suite from the repository root:

```bash
pytest -q
```

The suite covers target validation, models, Nmap profile/runner contracts, XML parsing, classification, SQLite persistence, scan orchestration and recovery, enumeration, correlation, diffing, coverage, CLI behavior, and reports. The full suite was run during this cleanup: **186 tests passed**.

## Current limitations and development status

ReconForge is under active development and is not presented as a finished production product.

- `reconforge show <scan-id>` displays scan phase history, artifact presence, and host/service summary. The planned `reconforge host <scan-id> <IP>` detail command is not yet implemented.
- SQLite migrations are deferred.
- The scan target interface currently supports IPv4 addresses and networks.

The current implementation is intended as a foundation for authorized reconnaissance and learning, with observable evidence and collection limits represented explicitly.
