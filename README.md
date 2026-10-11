# ShadowBox-Sec

**ShadowBox-Sec** is an offline, non-destructive simulation framework designed to validate detection engineering and log-correlation pipelines against MITRE ATT&CK® techniques. 

Much like shadowboxing in combat sports, this tool executes sophisticated defensive and offensive scenarios in a controlled, sandboxed environment without interacting with real network endpoints, enterprise directory services, or production infrastructure.

## 🎯 Key Design Principles

* **Zero Footprint:** All integration adapters default to reading synthetic, in-memory offline fixtures. No active network sockets, radio protocols, or CI/CD systems are contacted.
* **Synthetic Credential Baseline:** Leverages exclusively mock identities, RFC 5737 documentation IP ranges, and `.invalid` domains. 
* **Self-Contained Persistence:** File operations are strictly isolated to the tool's local state and audit configurations within the `airgap_redteam_state/` directory.
* **Tamper-Evident Auditing:** Every simulation event is recursively sanitized and chained chronologically using HMAC-SHA256 signatures to preserve non-repudiation.

## 🏗️ Supported Capabilities & Integrations

### Simulation Scenarios
* **T1078 / T1087:** Identity & Access Telemetry Calibration
* **T1190 / T1573:** Wireless Observation & Policy Drift Modeling
* **T1053 / T1547:** Simulated CI/CD Pipeline & Dependency Hardening
* **T1021 / T1550:** Alternate Authentication Material (Lateral Pathways)
* **T1003 / T1110:** LSASS/Memory Credential Dumping & Brute Force Timing
* **T1071 / T1571 / T1572:** C2 Protocol Tunneling & Beacon Jitter Profiling

### External Adapters (Read-Only Live Option)
When explicitly flipped to `live` mode, the engine shifts from synthetic data to local read-only execution adapters for verifying real-time access configurations:
* **RFID/NFC:** Device and reader capability tracking via vendor SDK plugins or PC/SC smartcard bridging.
* **Wireless:** Cisco Meraki/Catalyst, Aruba Central, and LoRaWAN API endpoints.
* **Directories:** Pure-Python secure LDAPS (Microsoft Active Directory, OpenLDAP) and Microsoft Graph integrations.
* **CI/CD Build Pipelines:** Read-only health metadata extraction from GitHub Actions, GitLab CI/CD, and Jenkins REST endpoints.

## 🚀 Getting Started

### Prerequisites
* Python 3.8 or higher.
* *(Optional)* Third-party libraries like `pyscard` or `ldap3` only if using live read-only system connectors.

### Usage
Run the main script framework directly from your terminal:
```bash
python3 main.py
```

To enable full cryptographic security for the local transaction log, set the required secret key length in your terminal environment before boot:
```bash
export AIRGAP_AUDIT_KEY="your-random-32-byte-secret-key-goes-here"
python3 main.py
```

## ⚖️ Safety & Non-Destruction Guardrails

To protect isolated system boundaries, this framework implements strict confirmation barriers. In the event an engineer explicitly configures a live connector, **no network frames, directory requests, or file lookups are initiated** until the system operator provides deliberate, text-based validation:

```text
Contact this external system now? Type YES to continue: 
```
If anything other than `YES` is supplied, or if the process exits abruptly, the execution immediately defaults back to a safe `OFFLINE` status.
## 📄 License
This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.
