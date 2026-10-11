#!/usr/bin/env python3
"""ShadowBox-Sec Non-Destructive Red Team — offline, non-destructive red team security validation.

Why this red team tool is non-destructive:
- No network or hardware access: All integration adapters read synthetic, in-memory
  offline fixtures. No network socket, radio/NFC reader, directory service, or CI/CD
  system is contacted unless the operator explicitly switches to live mode and types
  YES for each individual connection.
- No real credentials: All usernames, badge UIDs, tokens, and IP addresses are
  synthetic values from RFC 5737 documentation ranges or .invalid domains. No real
  secret is requested, stored, or transmitted.
- No writes outside this tool: All file writes are restricted to this tool's own
  state, backup, and audit directories under shadowbox_sec_redteam_state/. No user file,
  system file, or configuration outside this directory is created, modified, or
  deleted.
- No destructive rollback: Rollback restores only this tool's own session file from
  a snapshot. It never deletes files, overwrites user data, or reverses changes
  outside its state directory.
- No process or container execution: Pipeline and container scenarios are simulated
  entirely in code. No subprocess is spawned, no container is launched, and no shell
  command is executed.
- Tamper-evident audit trail: Events are recursively sanitized and chained with
  HMAC-SHA256. Set SHADOWBOX_SEC_AUDIT_KEY to a random secret of at least 32 bytes. The
  machine-ID fallback is compatibility-only and does not defend against a local attacker.
  Legacy unkeyed SHA-256 entries are identified during verification.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import re
import uuid
import json
import os
import platform
import getpass
import importlib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import sys
import time
from typing import Any

APP_NAME = "ShadowBox-Sec Non-Destructive Red Team"
ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / "shadowbox_sec_redteam_state"
SESSION_FILE = STATE_DIR / "session.json"
BACKUP_FILE = STATE_DIR / "session.rollback.json"
AUDIT_FILE = STATE_DIR / "audit.jsonl"
INTEGRITY_FILE = STATE_DIR / "integrity_manifest.json"
OPERATOR_FILE = STATE_DIR / "operator.json"
REPORT_FILE = STATE_DIR / "engagement_report.json"

MITRE_ATTACK = {
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access", "platforms": ["Windows", "Linux", "Network"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "platforms": ["Windows", "Linux", "Network"]},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "platforms": ["Windows", "Linux", "Network"]},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation", "platforms": ["Windows", "Linux", "Cloud"]},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "platforms": ["Windows", "Linux"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "platforms": ["Windows", "Linux"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "platforms": ["Windows", "Linux", "macOS"]},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Defense Evasion, Lateral Movement", "platforms": ["Windows", "Cloud"]},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control", "platforms": ["Windows", "Linux", "Network"]},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control", "platforms": ["Windows", "Linux", "Network"]},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control", "platforms": ["Windows", "Linux", "Network"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "platforms": ["Windows", "Linux", "macOS"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "platforms": ["Windows", "Linux", "macOS"]},
    "T1485": {"name": "Data Destruction", "tactic": "Impact", "platforms": ["Windows", "Linux", "macOS"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "platforms": ["Windows", "Linux", "Network"]},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "platforms": ["Windows", "Linux", "Cloud"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution, Persistence, Privilege Escalation", "platforms": ["Windows", "Linux", "macOS"]},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence, Privilege Escalation", "platforms": ["Windows", "Linux", "macOS"]},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery", "platforms": ["Windows", "Linux", "Cloud"]},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery", "platforms": ["Windows", "Linux", "Cloud"]},
}

# Synthetic values only. Never replace these with production identities or secrets.
FIXTURES = {
    "username": "demo.user@assessment.invalid",
    "dn": "CN=Demo User,OU=Assessment,DC=assessment,DC=invalid",
    "groups": ["Assessment-Auditors", "Pipeline-Reviewers"],
    "badge_uid": "assessment-tag-042",
    "gateway": "192.0.2.1",  # RFC 5737 documentation range
    "token_marker": "SIMULATED-TOKEN-NOT-A-CREDENTIAL",
}

COLORS = {
    "green": "\033[92m", "cyan": "\033[96m",
    "yellow": "\033[93m", "red": "\033[91m", "reset": "\033[0m",
}
# Many Windows consoles do not interpret ANSI escapes and print them literally.
# Prefer clean plain text on Windows; honor NO_COLOR on other terminals as well.
USE_COLOR = (
    os.name != "nt"
    and "NO_COLOR" not in os.environ
    and bool(getattr(sys.stdout, "isatty", lambda: False)())
)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def paint(text: str, color: str) -> str:
    return f"{COLORS[color]}{text}{COLORS['reset']}" if USE_COLOR else text


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def state_hash(state: dict[str, Any]) -> str:
    payload = dict(state)
    payload.pop("integrity_hash", None)
    return sha256_bytes(canonical_json(payload))


def blank_session() -> dict[str, Any]:
    data = {"username_b64": None, "pivot_ip": None, "updated_at": now_iso()}
    data["integrity_hash"] = state_hash(data)
    return data


def validate_session(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("integrity_hash"), str)
        and data["integrity_hash"] == state_hash(data)
    )


def atomic_write_json(path: Path, value: Any) -> None:
    """Write JSON through a temporary sibling file and atomic replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except OSError:
            # Cleanup must not mask the original write/replace exception.
            pass


def load_session() -> tuple[dict[str, Any], bool]:
    if not SESSION_FILE.exists():
        data = blank_session()
        atomic_write_json(SESSION_FILE, data)
        return data, True
    try:
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}, False
    return data, validate_session(data)


def save_session(data: dict[str, Any]) -> None:
    payload = dict(data)
    payload.pop("integrity_hash", None)
    payload["updated_at"] = now_iso()
    payload["integrity_hash"] = state_hash(payload)
    atomic_write_json(SESSION_FILE, payload)


_SECRET_KEY_NAMES = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"authorization|cookie|session[_-]?id|client[_-]?secret|credential|bind[_-]?dn_password)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(\b(?:password|passwd|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
]


def _sanitize_string(value: str) -> str:
    cleaned = value
    for pattern in _SECRET_VALUE_PATTERNS:
        cleaned = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", cleaned)
    return cleaned


def _sanitize_record(value: Any, key: str = "") -> Any:
    """Recursively redact sensitive fields and common inline secret formats before audit."""
    if key and _SECRET_KEY_NAMES.search(key):
        return "[REDACTED]" if value is not None else None
    if isinstance(value, dict):
        return {str(k): _sanitize_record(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_record(item) for item in value]
    if isinstance(value, str):
        return _sanitize_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize_string(str(value))


def _audit_key() -> tuple[bytes, str]:
    """Use a deployment-provided secret; hardware-derived fallback is compatibility only."""
    configured = os.environ.get("SHADOWBOX_SEC_AUDIT_KEY", "")
    if configured:
        if len(configured.encode("utf-8")) < 32:
            raise RuntimeError("SHADOWBOX_SEC_AUDIT_KEY must contain at least 32 UTF-8 bytes.")
        return configured.encode("utf-8"), "hmac-sha256-env"
    # uuid.getnode() is observable/predictable and is NOT a secret. This fallback
    # preserves standalone usability but does not protect against a local attacker.
    anchor = f"shadowbox_sec-audit-weak-machine-anchor:{uuid.getnode():012x}".encode("ascii")
    return hashlib.sha256(anchor).digest(), "hmac-sha256-machine-fallback-weak"


def _event_mac(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


def audit(event: str, details: dict[str, Any] | None = None) -> None:
    """Append a sanitized HMAC-SHA256 chain event (legacy SHA-256 entries remain verifiable)."""
    key, algorithm = _audit_key()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ok, _, message = verify_audit_chain()
    if not ok:
        raise RuntimeError(f"Refusing to append to invalid audit trail: {message}")
    previous = "GENESIS"
    if AUDIT_FILE.exists():
        with AUDIT_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    previous = json.loads(line)["event_hash"]
    record = {
        "timestamp": now_iso(),
        "event": _sanitize_string(str(event)),
        "details": _sanitize_record(details or {}),
        "previous_hash": previous,
        "signature_alg": algorithm,
    }
    record["event_hash"] = _event_mac(record, key)
    # Restrictive permissions on POSIX; Windows ACLs remain governed by the parent directory.
    fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def verify_audit_chain() -> tuple[bool, int, str]:
    if not AUDIT_FILE.exists():
        return True, 0, "No audit events yet."
    previous = "GENESIS"
    count = 0
    legacy_count = 0
    try:
        key, _ = _audit_key()
        with AUDIT_FILE.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    return False, count, f"Invalid audit record at line {line_no}."
                expected_previous = record.get("previous_hash")
                supplied_hash = record.get("event_hash")
                payload = dict(record)
                payload.pop("event_hash", None)
                if expected_previous != previous:
                    return False, count, f"Audit chain mismatch at line {line_no}."
                algorithm = record.get("signature_alg")
                if algorithm in {"hmac-sha256-env", "hmac-sha256-machine-fallback-weak"}:
                    expected_hash = _event_mac(payload, key)
                elif algorithm is None:  # legacy unkeyed SHA-256 entry; report as legacy below
                    expected_hash = sha256_bytes(canonical_json(payload))
                    legacy_count += 1
                else:
                    return False, count, f"Unknown audit signature algorithm at line {line_no}."
                if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
                    return False, count, f"Audit signature mismatch at line {line_no}."
                previous = supplied_hash
                count += 1
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return False, count, "Audit log could not be parsed or the audit key is invalid."
    if legacy_count:
        return True, count, f"Verified {count} events; WARNING: {legacy_count} legacy events use unkeyed SHA-256."
    return True, count, f"Verified {count} HMAC-chained audit events."


def emit(module: str, message: str, color: str = "cyan", delay: float = 0.12) -> None:
    audit("simulation.step", {"module": module, "message": message})
    print(paint(f"[*] {message}", color))
    if delay:
        time.sleep(delay)


def take_rollback_snapshot() -> None:
    """Snapshot only this tool's session file; no other paths are touched."""
    session, valid = load_session()
    if not valid:
        raise ValueError("Session integrity failed; refusing to snapshot invalid state.")
    atomic_write_json(BACKUP_FILE, session)
    audit("rollback.snapshot_created", {"path": BACKUP_FILE.name})
    print(paint("[+] Rollback snapshot saved for this tool's session.", "green"))


def rollback_session() -> None:
    """Restore the tool's session from its snapshot without deleting any files."""
    if not BACKUP_FILE.exists():
        print(paint("[-] No rollback snapshot exists yet. Create one first.", "yellow"))
        audit("rollback.unavailable", {})
        return
    try:
        backup = json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print(paint("[-] Rollback snapshot is unreadable; no changes made.", "red"))
        audit("rollback.failed", {"reason": "snapshot_unreadable"})
        return
    if not validate_session(backup):
        print(paint("[-] Rollback snapshot integrity failed; no changes made.", "red"))
        audit("rollback.failed", {"reason": "snapshot_integrity_failed"})
        return
    save_session(backup)
    audit("rollback.completed", {"target": "tool_session_only"})
    print(paint("[+] Session restored. No other files were changed or deleted.", "green"))


# Read-only adapters deliberately consume only in-memory synthetic fixtures.
# They perform no I/O, authenticate to no services, and expose no write operations.
# Provider choices are configuration metadata only. Selecting a live provider does not
# enable a network connection; a provider-specific backend must be implemented and reviewed.
INTEGRATION_OPTIONS = {
    "rfid_nfc": [
        "USB NFC reader", "PC/SC smart-card reader",
        "Zebra RFID SDK", "Impinj Octane SDK", "ThingMagic Mercury API",
        "Nordic ID SDK", "Chainway RFID SDK", "FEIG RFID SDK",
        "HID RFID SDK", "Generic vendor SDK plugin", "Not selected yet",
    ],
    "wireless": [
        "Cisco Catalyst/Meraki wireless", "Aruba (HPE) wireless", "Ubiquiti UniFi",
        "Ruckus (CommScope) wireless", "ChirpStack LoRaWAN server", "The Things Network (TTN)",
        "Generic Wi-Fi controller API", "Local wireless monitoring export", "Not selected yet",
    ],
    "active_directory": ["Microsoft Active Directory", "Microsoft Entra ID", "OpenLDAP", "Not selected yet"],
    "cicd": ["GitHub Actions", "GitLab CI/CD", "Jenkins", "Other or undecided", "Not selected yet"],
}
CONFIG_FILE = STATE_DIR / "integration_config.json"
DEFAULT_INTEGRATION_CONFIG = {
    "mode": "offline",
    "providers": {
        "rfid_nfc": "Not selected yet",
        "wireless": "Not selected yet",
        "active_directory": "Not selected yet",
        "cicd": "Not selected yet",
    },
}
INTEGRATION_LABELS = {
    "rfid_nfc": "RFID/NFC",
    "wireless": "Wireless",
    "active_directory": "Active Directory / Entra ID / OpenLDAP",
    "cicd": "CI/CD",
}


def load_integration_config() -> dict[str, Any]:
    """Load non-secret integration choices; credentials are never stored here."""
    if not CONFIG_FILE.exists():
        return json.loads(json.dumps(DEFAULT_INTEGRATION_CONFIG))
    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return json.loads(json.dumps(DEFAULT_INTEGRATION_CONFIG))
    if not isinstance(config, dict) or config.get("mode") not in {"offline", "live"}:
        return json.loads(json.dumps(DEFAULT_INTEGRATION_CONFIG))
    providers = config.get("providers")
    if not isinstance(providers, dict):
        return json.loads(json.dumps(DEFAULT_INTEGRATION_CONFIG))
    safe = {"mode": config["mode"], "providers": {}}
    for key, choices in INTEGRATION_OPTIONS.items():
        choice = providers.get(key, DEFAULT_INTEGRATION_CONFIG["providers"][key])
        safe["providers"][key] = choice if choice in choices else DEFAULT_INTEGRATION_CONFIG["providers"][key]
    return safe


def save_integration_config(config: dict[str, Any]) -> None:
    """Persist provider names and mode only; reject any unexpected fields."""
    mode = config.get("mode")
    providers = config.get("providers", {})
    if mode not in {"offline", "live"}:
        raise ValueError("Mode must be offline or live.")
    clean = {"mode": mode, "providers": {}}
    for key, choices in INTEGRATION_OPTIONS.items():
        choice = providers.get(key, DEFAULT_INTEGRATION_CONFIG["providers"][key])
        if choice not in choices:
            raise ValueError(f"Invalid provider choice for {key}.")
        clean["providers"][key] = choice
    atomic_write_json(CONFIG_FILE, clean)
    audit("integration.configuration_updated", {"mode": mode, "providers": clean["providers"]})


def print_connection_requirements(config: dict[str, Any]) -> None:
    """Show live connector input requirements without collecting or transmitting data."""
    print("\nLIVE MODE REQUIREMENTS — guide only; nothing is requested, saved, or sent here.")
    print("Offline mode itself needs no endpoints, accounts, credentials, hardware, or color settings; it uses synthetic fixtures.")
    print("The examples below are placeholders. Replace them with values from systems you are authorized to access.")
    for key in INTEGRATION_OPTIONS:
        label = INTEGRATION_LABELS.get(key, key.replace("_", " ").title())
        print(f"\n{label}")
        if key == "rfid_nfc":
            print("  USB NFC / PC/SC: connect the reader and install its OS driver/service; no host/token value is asked.")
            print("  Vendor SDK: install the vendor SDK and bridge; connection example: COM3, /dev/ttyUSB0, or 192.0.2.25:5084.")
            print("  Reader ID example: assessment-reader-01. Generic plugin module example: shadowbox_sec_rfid_vendors.my_reader.")
        elif key == "wireless":
            print("  Controller/LoRaWAN: HTTPS base URL (example https://controller.example.test), endpoint path (example /api/devices),")
            print("    and a read-only bearer token (entered hidden; do not type the words 'your token').")
            print(r"  Local wireless export: authorized JSON file path (example C:\exports\wireless.json; maximum 2 MB); no token.")
        elif key == "active_directory":
            print("  Active Directory / OpenLDAP: LDAPS host (example dc.example.test, port 636), read-only bind DN/account,")
            print("    password (entered hidden), and search base (example DC=example,DC=test).")
            print("  Entra ID: Graph endpoint (default https://graph.microsoft.com/v1.0/users?$top=20) and a pre-issued access token (hidden).")
        elif key == "cicd":
            print("  GitHub Actions: owner/org (example acme-demo), repository (example app), and fine-grained read-only token (hidden).")
            print("  GitLab CI/CD: HTTPS base URL (default https://gitlab.com), project ID/path (example group%2Fapp), read_api token (hidden).")
            print("  Jenkins: HTTPS base URL (example https://jenkins.example.test), job name (example nightly-build), username, API token (hidden).")
            print("  Other or undecided is simulated only; it has no live detail prompts.")
    print("To enter these values: if mode is OFF, select 6 to enable Live; then select 1-4 and a provider.")
    print("The adapter asks for all required details first. Afterward it shows: Contact this external system now? Type YES to continue:")
    print("No network request, reader enumeration, or local file-content read occurs until you type exactly YES.")
    print("Secret values are hidden and held in memory only; they are never saved.")


def configure_integration_providers(config: dict[str, Any]) -> None:
    """Configure providers by first selecting an integration category."""
    providers_changed = False
    original_providers = dict(config["providers"])

    def save_provider_changes() -> None:
        nonlocal providers_changed
        if providers_changed:
            save_integration_config(config)
            audit("integration.vendors_selected", {"providers": config["providers"]})
            providers_changed = False

    print("\nChoose an integration category to see its provider choices.")
    print("Provider selections save names only; connection details are entered when a live adapter is run.")
    print("Provider changes are saved when you finish with Enter or 0; interrupting setup discards them.")
    while True:
        print("\nIntegration categories:")
        for index, key in enumerate(INTEGRATION_OPTIONS, 1):
            label = INTEGRATION_LABELS.get(key, key.replace("_", " ").title())
            print(f"  {index}) {label}")
        reset_index = len(INTEGRATION_OPTIONS) + 1
        print(f"  {reset_index}) Reset all provider selections")
        answer = input("Choose category number (Enter/0 returns): ").strip()
        if not answer or answer == "0":
            save_provider_changes()
            return
        try:
            category_index = int(answer)
            if not 1 <= category_index <= reset_index:
                raise ValueError
        except ValueError:
            print("Invalid choice. Choose a category, reset, or 0 to return.")
            continue
        if category_index == reset_index:
            confirm_reset = input("Type RESET to clear all four provider selections: ").strip()
            if confirm_reset.upper() != "RESET":
                print("Reset cancelled; provider selections are unchanged.")
                continue
            for key in INTEGRATION_OPTIONS:
                config["providers"][key] = DEFAULT_INTEGRATION_CONFIG["providers"][key]
            providers_changed = config["providers"] != original_providers
            print("Reset staged. Finish setup with Enter or 0 to save; interrupting discards it.")
            continue

        key = list(INTEGRATION_OPTIONS)[category_index - 1]
        label = INTEGRATION_LABELS.get(key, key.replace("_", " ").title())
        choices = INTEGRATION_OPTIONS[key]
        print(f"\n{label} providers:")
        for index, choice in enumerate(choices, 1):
            print(f"  {index}) {choice}")
        answer = input("Choose provider number (Enter returns to categories): ").strip()
        if not answer:
            continue
        try:
            index = int(answer)
            if not 1 <= index <= len(choices):
                raise ValueError
        except ValueError:
            print("Invalid provider choice; no change made.")
            continue

        selected_provider = choices[index - 1]
        if selected_provider == config["providers"][key]:
            print("That provider is already selected.")
        else:
            config["providers"][key] = selected_provider
            providers_changed = config["providers"] != original_providers
            print(paint(f"[+] {label} provider set to: {selected_provider}", "green"))
        if (selected_provider in INTEGRATION_PROFILES.get(key, {})
                and not (key == "cicd" and selected_provider == "Other or undecided")):
            if config["mode"] == "live":
                run_now = input(
                    "Run this read-only adapter now to enter connection details? "
                    "It will ask for a separate YES before contacting the system [y/N]: "
                ).strip().lower()
                if run_now in {"y", "yes"}:
                    save_provider_changes()
                    adapter_labels = {
                        "rfid_nfc": "RFID/NFC",
                        "wireless": "Wireless",
                        "active_directory": "Active Directory",
                        "cicd": "CI/CD",
                    }
                    _display_adapter(key, f"{adapter_labels[key]} adapter")
                    return
                else:
                    print("To enter details later, run this adapter from the main menu.")
            else:
                print("Offline mode does not request connection details. Select 6 to enable Live mode, then choose this adapter.")


def configure_integrations() -> None:
    """Interactive configuration for every supported provider choice."""
    config = load_integration_config()
    print("\nIntegration configuration (provider selections only; no secrets).")
    print("  1) Offline mode (default; no live connections)")
    print("  2) Live mode (connectors prompt for endpoint details and credentials when invoked)")
    mode_choice = input(f"Select mode [current: {config['mode']}, Enter keeps current]: ").strip()
    if mode_choice == "1":
        config["mode"] = "offline"
    elif mode_choice == "2":
        config["mode"] = "live"
    elif mode_choice:
        print("Unknown mode; keeping current mode.")
    save_integration_config(config)
    configure_integration_providers(config)
    print("\n[+] Configuration saved (provider names only; no credentials stored).")
    if config["mode"] == "live":
        print(paint("[!] Live mode is enabled. Each adapter prompts for connection details and asks for explicit confirmation before contacting a service.", "yellow"))
        print("    Secrets are entered hidden and held in memory only; they are not saved to config or audit logs.")
    print("    RFID vendor SDK choices use a vendor bridge module; install the official SDK and its bridge before connecting.")


INTEGRATION_FIXTURES: dict[str, dict[str, Any]] = {
    "rfid_nfc": {
        "source": "synthetic RFID/NFC event feed",
        "events": [{"tag_uid": FIXTURES["badge_uid"], "reader": "assessment-reader-01", "result": "unknown_tag"}],
    },
    "wireless": {
        "source": "synthetic wireless observation feed",
        "observations": [
            {"technology": "LoRaWAN", "device": "assessment-node-07", "status": "unapproved_join"},
            {"technology": "Wi-Fi", "device": "assessment-ap-02", "status": "policy_review"},
        ],
    },
    "active_directory": {
        "source": "synthetic Active Directory snapshot",
        "users": [{"username": FIXTURES["username"], "dn": FIXTURES["dn"], "groups": list(FIXTURES["groups"])}],
    },
    "cicd": {
        "source": "synthetic CI/CD metadata snapshot",
        "pipelines": [{"name": "assessment-build", "branch_protection": "review_required", "dependency_pinning": "needs_review"}],
    },
}


def read_only_adapter(adapter_name: str, provider_override: str | None = None) -> dict[str, Any]:
    """Return a defensive copy of a known offline fixture; never performs I/O."""
    if adapter_name not in INTEGRATION_FIXTURES:
        raise ValueError(f"Unknown integration adapter: {adapter_name}")
    provider = provider_override or load_integration_config()["providers"][adapter_name]
    builders = {"rfid_nfc": _rfid_fixture, "wireless": _wireless_fixture,
                "active_directory": _directory_fixture, "cicd": _cicd_fixture}
    return builders[adapter_name](provider)


def _prompt(label: str, default: str = "", secret: bool = False, required: bool = True) -> str:
    """Prompt at use time; secrets are returned to memory only and never persisted."""
    suffix = f" [{default}]" if default else ""
    while True:
        raw = getpass.getpass(f"{label}{suffix}: ") if secret else input(f"{label}{suffix}: ")
        value = raw.strip() or default
        if value or not required:
            return value
        print("A value is required.")


def _https_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use an HTTPS URL with a hostname; credentials must not be embedded in URLs.")
    return url


def _http_get_json(url: str, token: str = "", username: str = "", password: str = "", token_header: str = "Authorization") -> Any:
    """Perform a bounded HTTPS GET only; no writes, redirects to HTTP, or disabled TLS checks."""
    _https_url(url)
    headers = {"Accept": "application/json", "User-Agent": "ShadowBox-Sec-RedTeam-ReadOnly/1.0"}
    if token:
        headers[token_header] = f"Bearer {token}" if token_header == "Authorization" else token
    elif username:
        import base64 as _b64
        headers["Authorization"] = "Basic " + _b64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    request = urllib.request.Request(url, headers=headers, method="GET")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(req.full_url, code, "Redirect refused for credential safety", headers, fp)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect()
    )
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP service returned status {response.status}.")
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise RuntimeError("Response exceeded the 2 MB safety limit.")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTPS request failed with HTTP {exc.code}.") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach HTTPS service: {exc.reason}") from None


RFID_VENDOR_PLUGINS = {
    "Zebra RFID SDK": "shadowbox_sec_rfid_vendors.zebra",
    "Impinj Octane SDK": "shadowbox_sec_rfid_vendors.impinj",
    "ThingMagic Mercury API": "shadowbox_sec_rfid_vendors.thingmagic",
    "Nordic ID SDK": "shadowbox_sec_rfid_vendors.nordicid",
    "Chainway RFID SDK": "shadowbox_sec_rfid_vendors.chainway",
    "FEIG RFID SDK": "shadowbox_sec_rfid_vendors.feig",
    "HID RFID SDK": "shadowbox_sec_rfid_vendors.hid",
}


# Per-vendor RFID profiles. Hardware and SDKs differ by manufacturer, so this tool
# keys every RFID/NFC behavior off the selected vendor. Values are descriptive
# metadata only; selecting a profile never opens a device or radio.
RFID_VENDOR_PROFILES: dict[str, dict[str, str]] = {
    "USB NFC reader": {"family": "nfc", "tag_format": "ISO14443-A UID (4/7-byte hex)",
                       "connection_hint": "USB port with OS NFC/PC/SC driver"},
    "PC/SC smart-card reader": {"family": "pcsc", "tag_format": "ISO14443 ATR + UID",
                                "connection_hint": "PC/SC service (pcscd) with vendor driver"},
    "Zebra RFID SDK": {"family": "uhf", "tag_format": "EPC Gen2 (96-bit hex)",
                       "connection_hint": "Reader IP:port or USB via Zebra RFID SDK"},
    "Impinj Octane SDK": {"family": "uhf", "tag_format": "EPC Gen2 (96-bit hex)",
                          "connection_hint": "Reader hostname/IP, LLRP port 5084"},
    "ThingMagic Mercury API": {"family": "uhf", "tag_format": "EPC Gen2 (96-bit hex)",
                               "connection_hint": "Serial port or tcp://host:port via Mercury API"},
    "Nordic ID SDK": {"family": "uhf", "tag_format": "EPC Gen2 (96-bit hex)",
                      "connection_hint": "USB/serial via Nordic ID NUR API"},
    "Chainway RFID SDK": {"family": "uhf", "tag_format": "EPC Gen2 (96-bit hex)",
                          "connection_hint": "Android handheld via Chainway SDK service"},
    "FEIG RFID SDK": {"family": "hf_uhf", "tag_format": "ISO15693 / EPC Gen2",
                      "connection_hint": "TCP/IP or serial via FEIG ISOStart/SDK"},
    "HID RFID SDK": {"family": "hf", "tag_format": "iCLASS/SEOS credential UID",
                     "connection_hint": "USB via HID OMNIKEY driver"},
    "Generic vendor SDK plugin": {"family": "generic", "tag_format": "vendor-defined",
                                  "connection_hint": "Defined by the custom bridge module"},
}


def _rfid_fixture(provider: str) -> dict[str, Any]:
    """Build the offline RFID fixture for the configured vendor, or skip cleanly."""
    profile = RFID_VENDOR_PROFILES.get(provider)
    if profile is None:
        return {
            "source": "no RFID vendor configured",
            "events": [{"status": "skipped",
                        "reason": "No RFID vendor selected. Choose one from the RFID/NFC menu option; checks are simulated until hardware is connected."}],
        }
    return {
        "source": f"synthetic RFID/NFC event feed ({provider})",
        "events": [{"tag_uid": FIXTURES["badge_uid"], "reader": f"assessment-{profile['family']}-reader-01",
                    "tag_format": profile["tag_format"], "result": "unknown_tag"}],
        "vendor": {"provider": provider, "connection_hint": profile["connection_hint"],
                   "note": "Simulated; no reader hardware was opened."},
    }


# Vendor profiles for the remaining integrations. Like the RFID profiles, these
# are descriptive metadata only; selecting one never contacts a live system.
WIRELESS_VENDOR_PROFILES: dict[str, dict[str, str]] = {
    "Cisco Catalyst/Meraki wireless": {"family": "wifi", "hint": "Catalyst Center API or Meraki Dashboard API"},
    "Aruba (HPE) wireless": {"family": "wifi", "hint": "Aruba Central API or controller AirWave export"},
    "Ubiquiti UniFi": {"family": "wifi", "hint": "UniFi Network Application API (local controller)"},
    "Ruckus (CommScope) wireless": {"family": "wifi", "hint": "SmartZone API or ZoneDirector export"},
    "ChirpStack LoRaWAN server": {"family": "lorawan", "hint": "ChirpStack gRPC/REST API"},
    "The Things Network (TTN)": {"family": "lorawan", "hint": "TTN v3 API (The Things Stack)"},
    "Generic Wi-Fi controller API": {"family": "wifi", "hint": "Vendor-neutral HTTPS controller API"},
    "Local wireless monitoring export": {"family": "export", "hint": "Authorized JSON export file, read locally"},
}

def host_os() -> str:
    """Return 'windows', 'linux', or the lowercase platform name."""
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "linux":
        return "linux"
    return system or "unknown"


# Directory connectors run on both Windows and Linux: ldap3 is pure Python and
# needs no OS-specific driver; the Graph connector is plain HTTPS. The per-OS
# notes below only describe what must exist on the host (e.g. domain reachability).
DIRECTORY_PROFILES: dict[str, dict[str, str]] = {
    "Microsoft Active Directory": {
        "family": "ad",
        "hint": "LDAPS on port 636, read-only bind",
        "windows": "Works domain-joined or standalone; only network access to a DC on 636 is needed.",
        "linux": "Works from any Linux host that can reach a DC on 636; no SSSD/domain join required.",
    },
    "Microsoft Entra ID": {
        "family": "entra",
        "hint": "Microsoft Graph API with pre-issued token",
        "windows": "HTTPS only; no local components needed.",
        "linux": "HTTPS only; no local components needed.",
    },
    "OpenLDAP": {
        "family": "ldap",
        "hint": "LDAPS on port 636, read-only bind",
        "windows": "Works from Windows hosts that can reach the LDAP server on 636.",
        "linux": "Works alongside SSSD/sssd-tools or standalone; only 636 access is needed.",
    },
}

CICD_PROFILES: dict[str, dict[str, str]] = {
    "GitHub Actions": {"family": "github", "hint": "GitHub REST API with fine-grained read-only token"},
    "GitLab CI/CD": {"family": "gitlab", "hint": "GitLab REST API with read_api token"},
    "Jenkins": {"family": "jenkins", "hint": "Jenkins REST API with user API token"},
    "Other or undecided": {"family": "generic", "hint": "Simulated only until a platform is chosen"},
}

INTEGRATION_PROFILES: dict[str, dict[str, dict[str, str]]] = {
    "rfid_nfc": RFID_VENDOR_PROFILES,
    "wireless": WIRELESS_VENDOR_PROFILES,
    "active_directory": DIRECTORY_PROFILES,
    "cicd": CICD_PROFILES,
}


def _wireless_fixture(provider: str) -> dict[str, Any]:
    profile = WIRELESS_VENDOR_PROFILES.get(provider)
    if profile is None:
        return {"source": "no wireless provider configured",
                "observations": [{"status": "skipped",
                                  "reason": "No wireless provider selected. Choose one from the Wireless menu option."}]}
    if profile["family"] == "lorawan":
        observations = [{"technology": "LoRaWAN", "device": "assessment-node-07", "status": "unapproved_join"}]
    elif profile["family"] == "export":
        observations = [{"technology": "export", "device": "assessment-export", "status": "awaiting_file"}]
    else:
        observations = [{"technology": "Wi-Fi", "device": "assessment-ap-02", "status": "policy_review"}]
    return {"source": f"synthetic wireless observation feed ({provider})",
            "observations": observations,
            "vendor": {"provider": provider, "connection_hint": profile["hint"],
                       "note": "Simulated; no controller or network server was contacted."}}


def _directory_fixture(provider: str) -> dict[str, Any]:
    profile = DIRECTORY_PROFILES.get(provider)
    if profile is None:
        return {"source": "no directory provider configured",
                "users": [{"status": "skipped",
                           "reason": "No directory provider selected. Choose one from the Directory menu option."}]}
    os_name = host_os()
    return {"source": f"synthetic directory snapshot ({provider})",
            "users": [{"username": FIXTURES["username"], "dn": FIXTURES["dn"], "groups": list(FIXTURES["groups"])}],
            "vendor": {"provider": provider, "connection_hint": profile["hint"],
                       "host_os": os_name, "host_note": profile.get(os_name, "Cross-platform connector."),
                       "note": "Simulated; no directory was queried."}}


def _cicd_fixture(provider: str) -> dict[str, Any]:
    profile = CICD_PROFILES.get(provider)
    if profile is None:
        return {"source": "no CI/CD platform configured",
                "pipelines": [{"status": "skipped",
                               "reason": "No CI/CD platform selected. Choose one from the CI/CD menu option."}]}
    checks = {
        "github": ["branch_protection", "required_reviews", "actions_pinning"],
        "gitlab": ["protected_branches", "merge_approvals", "dependency_pinning"],
        "jenkins": ["job_permissions", "credential_scoping", "plugin_audit"],
        "generic": ["branch_protection", "dependency_pinning"],
    }[profile["family"]]
    return {"source": f"synthetic CI/CD metadata snapshot ({provider})",
            "pipelines": [{"name": "assessment-build", "checks": checks, "status": "needs_review"}],
            "vendor": {"provider": provider, "connection_hint": profile["hint"],
                       "note": "Simulated; no CI/CD service was contacted."}}


def prompt_integration_vendors() -> None:
    """Show integration categories, then the provider choices for the selected one."""
    config = load_integration_config()
    print("\nIntegration setup")
    configure_integration_providers(config)


def _collect_live_details(adapter_name: str, provider: str) -> dict[str, Any]:
    """Prompt for live inputs without opening hardware, reading files, or contacting services."""
    if provider not in INTEGRATION_PROFILES.get(adapter_name, {}):
        raise RuntimeError(f"No live connector is available for {provider}; choose a supported provider.")

    if adapter_name == "rfid_nfc":
        if provider in RFID_VENDOR_PLUGINS or provider == "Generic vendor SDK plugin":
            module_name = RFID_VENDOR_PLUGINS.get(provider)
            if provider == "Generic vendor SDK plugin":
                module_name = _prompt("Python bridge module (e.g. shadowbox_sec_rfid_vendors.my_reader)")
                if not all(part.isidentifier() for part in module_name.split(".")):
                    raise RuntimeError("Enter a valid dotted Python module name.")
            return {
                "module_name": module_name,
                "connection": _prompt(
                    "Reader connection (serial port, IP:port, or SDK-specific identifier; blank if unused)", ""
                ),
                "reader_id": _prompt("Reader ID / serial number (optional)", "", required=False),
            }
        if provider in {"USB NFC reader", "PC/SC smart-card reader"}:
            print("No text credentials are required; the reader will only be enumerated after confirmation.")
            return {}
        raise RuntimeError("Choose a listed RFID reader provider from menu option 1.")

    if adapter_name == "wireless":
        if provider == "Local wireless monitoring export":
            return {"path": Path(_prompt("Path to authorized JSON export")).expanduser().resolve()}
        base = _https_url(_prompt("Wireless/LoRaWAN API HTTPS base URL"))
        endpoint = _prompt("Read-only JSON endpoint path", "/api/devices")
        url = urllib.parse.urljoin(base.rstrip("/") + "/", endpoint.lstrip("/"))
        _https_url(url)
        token = _prompt("API bearer token (input hidden)", secret=True)
        return {"url": url, "token": token}

    if adapter_name == "active_directory":
        os_name = host_os()
        profile = DIRECTORY_PROFILES[provider]
        print(f"Host OS: {os_name}. {profile.get(os_name, 'This connector is cross-platform.')}")
        if provider == "Microsoft Entra ID":
            endpoint = _https_url(_prompt(
                "Microsoft Graph HTTPS endpoint", "https://graph.microsoft.com/v1.0/users?$top=20"
            ))
            token = _prompt("Pre-issued Microsoft Graph access token (input hidden)", secret=True)
            return {"endpoint": endpoint, "token": token}
        return {
            "host": _prompt("LDAPS server hostname (port 636)"),
            "bind_dn": _prompt("Read-only bind DN / account"),
            "password": _prompt("Directory password (input hidden)", secret=True),
            "base_dn": _prompt("Search base DN, e.g. DC=example,DC=com"),
        }

    if adapter_name == "cicd":
        if provider == "GitHub Actions":
            owner = _prompt("GitHub repository owner or organization")
            repo = _prompt("GitHub repository name")
            token = _prompt("GitHub fine-grained read-only token (input hidden)", secret=True)
            url = (
                "https://api.github.com/repos/"
                f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
                "/actions/runs?per_page=20"
            )
            return {"url": url, "token": token}
        if provider == "GitLab CI/CD":
            base = _https_url(_prompt("GitLab HTTPS base URL", "https://gitlab.com"))
            project = _prompt("GitLab project ID or URL-encoded path")
            token = _prompt("GitLab read_api token (input hidden)", secret=True)
            url = urllib.parse.urljoin(
                base.rstrip("/") + "/",
                f"api/v4/projects/{urllib.parse.quote(project, safe='')}/pipelines?per_page=20",
            )
            _https_url(url)
            return {"url": url, "token": token}
        if provider == "Jenkins":
            base = _https_url(_prompt("Jenkins HTTPS base URL"))
            job = _prompt("Jenkins job name (single job, not a folder path)")
            username = _prompt("Jenkins username")
            token = _prompt("Jenkins API token (input hidden)", secret=True)
            url = urllib.parse.urljoin(
                base.rstrip("/") + "/",
                f"job/{urllib.parse.quote(job, safe='')}/api/json"
                "?tree=name,color,lastBuild[number,result,timestamp,url]",
            )
            _https_url(url)
            return {"url": url, "username": username, "token": token}
        raise RuntimeError("Choose GitHub Actions, GitLab CI/CD, or Jenkins for a supported live connector.")

    raise ValueError(f"Unknown integration adapter: {adapter_name}")


def _live_rfid_vendor_sdk(provider: str, details: dict[str, Any]) -> dict[str, Any]:
    """Load a manufacturer bridge only after the final consent prompt."""
    module_name = details["module_name"]
    try:
        bridge = importlib.import_module(module_name)
    except Exception as exc:
        raise RuntimeError(
            f"Vendor bridge '{module_name}' failed while loading ({type(exc).__name__}). "
            "Check that the manufacturer's SDK and bridge dependencies are installed and compatible."
        ) from None
    connector = getattr(bridge, "connect_readonly", None)
    if not callable(connector):
        raise RuntimeError(f"Vendor bridge '{module_name}' must expose connect_readonly(config).")
    try:
        result = connector({
            "provider": provider,
            "connection": details["connection"],
            "reader_id": details["reader_id"],
            "read_only": True,
            "timeout_seconds": 10,
        })
    except Exception as exc:
        raise RuntimeError(
            f"Vendor SDK connection failed ({type(exc).__name__}). "
            "Check SDK install, device connection, and read permissions."
        ) from None
    if not isinstance(result, dict):
        raise RuntimeError("Vendor bridge must return a dictionary of reader status/metadata.")
    result.setdefault("source", provider)
    result.setdefault("note", "Vendor bridge result; confirm the bridge uses read-only operations.")
    return result


def _live_rfid(provider: str, details: dict[str, Any]) -> dict[str, Any]:
    if provider in RFID_VENDOR_PLUGINS or provider == "Generic vendor SDK plugin":
        return _live_rfid_vendor_sdk(provider, details)
    try:
        from smartcard.System import readers
    except ImportError:
        raise RuntimeError("PC/SC support is not installed. Install pyscard and the reader's OS driver, then retry.") from None
    found = [str(reader) for reader in readers()]
    return {
        "source": "local PC/SC reader enumeration",
        "readers": found,
        "count": len(found),
        "note": "Only reader availability was enumerated; no card was read or modified.",
    }


def _live_wireless(provider: str, details: dict[str, Any]) -> dict[str, Any]:
    if provider == "Local wireless monitoring export":
        path = details["path"]
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise RuntimeError("Export file is missing or exceeds 2 MB.")
        data = json.loads(path.read_text(encoding="utf-8"))
        return {"source": "local wireless monitoring export", "data": data}
    return {
        "source": provider,
        "endpoint": details["url"],
        "data": _http_get_json(details["url"], token=details["token"]),
    }


def _live_directory(provider: str, details: dict[str, Any]) -> dict[str, Any]:
    if provider == "Microsoft Entra ID":
        return {"source": provider, "data": _http_get_json(details["endpoint"], token=details["token"])}
    try:
        from ldap3 import Server, Connection, Tls, SUBTREE, SIMPLE
    except ImportError:
        raise RuntimeError("LDAP support is not installed. Install ldap3, then retry.") from None
    tls = Tls(validate=ssl.CERT_REQUIRED)
    server = Server(details["host"], port=636, use_ssl=True, tls=tls, connect_timeout=5)
    try:
        with Connection(
            server,
            user=details["bind_dn"],
            password=details["password"],
            authentication=SIMPLE,
            auto_bind=True,
            read_only=True,
            receive_timeout=10,
        ) as conn:
            conn.search(
                details["base_dn"],
                "(objectCategory=person)" if provider == "Microsoft Active Directory" else "(objectClass=person)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "uid", "cn", "distinguishedName", "memberOf"],
                size_limit=100,
            )
            entries = [{"dn": entry.entry_dn, "attributes": entry.entry_attributes_as_dict} for entry in conn.entries]
            return {"source": provider, "users": entries, "count": len(entries), "host_os": host_os()}
    except Exception as exc:
        raise RuntimeError(
            f"Directory query failed ({type(exc).__name__}). "
            "Verify host, certificate, credentials, and read permissions."
        ) from None


def _live_cicd(provider: str, details: dict[str, Any]) -> dict[str, Any]:
    if provider == "GitLab CI/CD":
        data = _http_get_json(details["url"], token=details["token"], token_header="PRIVATE-TOKEN")
    elif provider == "Jenkins":
        data = _http_get_json(details["url"], username=details["username"], password=details["token"])
    else:
        data = _http_get_json(details["url"], token=details["token"])
    return {"source": provider, "data": data}


def reset_live_mode_to_offline(reason: str) -> bool:
    """Persist OFFLINE while retaining provider selections; return whether mode changed."""
    config = load_integration_config()
    if config["mode"] != "live":
        return False
    config["mode"] = "offline"
    save_integration_config(config)
    audit("integration.live_mode_reset_offline", {"reason": reason, "provider_choices_preserved": True})
    return True


def live_adapter(adapter_name: str, provider: str) -> dict[str, Any]:
    """Collect inputs first, then require explicit consent before any live operation."""
    if provider not in INTEGRATION_PROFILES.get(adapter_name, {}):
        raise RuntimeError(f"No live connector is available for {provider}; choose a supported provider.")
    print(paint(f"\nLIVE READ-ONLY CONNECTOR: {provider}", "yellow"))
    print("Enter the required details first. They remain in memory and are not saved.")
    details = _collect_live_details(adapter_name, provider)
    print("\nAll required details are entered. Nothing has been sent or read yet.")
    if provider == "Local wireless monitoring export":
        print("For this provider, YES authorizes reading the selected local JSON file; no remote service is contacted.")
    confirm = input("Contact this external system now? Type YES to continue: ").strip()
    if confirm != "YES":
        audit("integration.live_cancelled", {"adapter": adapter_name, "provider": provider})
        mode_was_live = reset_live_mode_to_offline("live_confirmation_declined")
        print("Cancelled; no connection or file read was attempted.")
        if mode_was_live:
            print("Live mode switched OFF; provider selections were preserved.")
        return {"cancelled": True}
    if adapter_name == "rfid_nfc":
        result = _live_rfid(provider, details)
    elif adapter_name == "wireless":
        result = _live_wireless(provider, details)
    elif adapter_name == "active_directory":
        result = _live_directory(provider, details)
    elif adapter_name == "cicd":
        result = _live_cicd(provider, details)
    else:
        raise ValueError(f"Unknown integration adapter: {adapter_name}")
    audit("integration.live_read_succeeded", {"adapter": adapter_name, "provider": provider,
                                                "record_count": result.get("count")})
    return result


def _display_adapter(adapter_name: str, label: str, provider_override: str | None = None) -> None:
    config = load_integration_config()
    provider = provider_override or config["providers"][adapter_name]
    if config["mode"] == "live":
        try:
            snapshot = live_adapter(adapter_name, provider)
            print(f"\n{label} — LIVE READ-ONLY RESULT")
            print(json.dumps(snapshot, indent=2, sort_keys=True, default=str)[:20000])
        except Exception as exc:
            # Do not print raw exception text: third-party libraries may include URLs or secrets.
            try:
                audit("integration.live_read_failed", {"adapter": adapter_name, "provider": provider,
                                                        "error_type": type(exc).__name__})
            except Exception as audit_exc:
                print(f"[-] Audit write failed ({type(audit_exc).__name__}); preserve local evidence.", file=sys.stderr)
            print(paint(f"[-] Live connector failed ({type(exc).__name__}). Check configuration and permissions; sensitive details were suppressed.", "red"))
        return
    snapshot = read_only_adapter(adapter_name, provider_override=provider)
    audit("integration.snapshot_read", {"adapter": adapter_name, "mode": "offline_fixture", "provider": provider})
    print(f"\n{label} — READ-ONLY OFFLINE SNAPSHOT")
    print(f"  Source: {snapshot['source']}")
    for key, value in snapshot.items():
        if key != "source":
            print(f"  {key.replace('_', ' ').title()}:")
            if isinstance(value, dict):
                print("    " + json.dumps(value, sort_keys=True))
            else:
                for item in value:
                    print("    " + json.dumps(item, sort_keys=True))
    print("  No external system was contacted.")


def adapter_rfid_nfc() -> None:
    _display_adapter("rfid_nfc", "RFID/NFC adapter")


def adapter_wireless() -> None:
    _display_adapter("wireless", "Wireless adapter")


def adapter_active_directory() -> None:
    _display_adapter("active_directory", "Active Directory adapter")


def adapter_cicd() -> None:
    _display_adapter("cicd", "CI/CD adapter")


def choose_provider_and_run(adapter_name: str) -> None:
    """Select a provider for one category and run its offline/live adapter."""
    if adapter_name not in INTEGRATION_OPTIONS:
        raise ValueError(f"Unknown integration category: {adapter_name}")
    config = load_integration_config()
    label = INTEGRATION_LABELS.get(adapter_name, adapter_name.replace("_", " ").title())
    choices = INTEGRATION_OPTIONS[adapter_name]
    print(f"\n{label} provider choices (mode: {config['mode'].upper()}):")
    for index, provider in enumerate(choices, 1):
        print(f"  {index}) {provider}")
    answer = input("Choose provider number [0=back, R=reset all]: ").strip()

    if answer.lower() == "r":
        if input("Type RESET to clear all four provider selections: ").strip().upper() != "RESET":
            print("Reset cancelled; selections unchanged.")
            return
        for key in INTEGRATION_OPTIONS:
            config["providers"][key] = DEFAULT_INTEGRATION_CONFIG["providers"][key]
        save_integration_config(config)
        audit("integration.providers_reset", {"mode": config["mode"]})
        print("All provider selections cleared. The current mode was preserved.")
        return
    if answer == "0":
        return
    if not answer:
        print("No provider chosen; select a number or enter 0 to return.")
        return
    else:
        try:
            index = int(answer)
            if not 1 <= index <= len(choices):
                raise ValueError
        except ValueError:
            print("Invalid provider choice; returning to the main menu.")
            return
        selected_provider = choices[index - 1]

    if selected_provider == "Not selected yet":
        if config["providers"][adapter_name] != selected_provider:
            config["providers"][adapter_name] = selected_provider
            save_integration_config(config)
            audit("integration.vendor_cleared", {"integration": adapter_name})
        print(f"{label} provider cleared.")
        return

    provider_changed = config["providers"][adapter_name] != selected_provider
    if provider_changed:
        print(f"Selected {selected_provider}; running the {config['mode']} adapter.")
    _display_adapter(adapter_name, f"{label} adapter", provider_override=selected_provider)
    if provider_changed:
        latest_config = load_integration_config()
        latest_config["providers"][adapter_name] = selected_provider
        save_integration_config(latest_config)
        audit("integration.vendor_selected", {"integration": adapter_name, "provider": selected_provider})


def toggle_live_mode() -> None:
    """Toggle between offline fixtures and explicitly-confirmed live adapters."""
    config = load_integration_config()
    config["mode"] = "live" if config["mode"] == "offline" else "offline"
    save_integration_config(config)
    if config["mode"] == "live":
        print("Live mode enabled. Select options 1-4 to choose a provider and run its adapter.")
        print("Each live read asks for its details and a separate YES before contacting a system.")
        print("Secrets are entered hidden and are not saved.")
        print("Live mode automatically resets to OFFLINE when you quit, interrupt, or decline a live confirmation.")
    else:
        print("Offline mode enabled. Adapter options use synthetic fixtures only.")


def coverage_summary() -> None:
    """Show which integrations are configured, simulated, or skipped."""
    config = load_integration_config()
    print("\nIntegration coverage summary")
    print(f"  Mode: {config['mode'].upper()} (offline = simulated fixtures)")
    for key in INTEGRATION_OPTIONS:
        provider = config["providers"][key]
        label = key.replace("_", " ").title()
        if provider in INTEGRATION_PROFILES.get(key, {}):
            hint = INTEGRATION_PROFILES[key][provider]["hint"] if "hint" in INTEGRATION_PROFILES[key][provider] else INTEGRATION_PROFILES[key][provider]["connection_hint"]
            status = "CONFIGURED (simulated)" if config["mode"] == "offline" else "CONFIGURED (live read-only)"
            print(paint(f"  [+] {label:<18} {provider} — {status}", "green"))
            print(f"      {hint}")
        else:
            print(paint(f"  [-] {label:<18} not configured — checks skipped", "yellow"))
    audit("integration.coverage_viewed", {"providers": config["providers"], "mode": config["mode"]})


def print_startup_status() -> None:
    print(paint(f"\n{APP_NAME} — startup checks", "cyan"))
    config = load_integration_config()
    print(f"  Mode: {config['mode'].upper()}")
    print("  Read-only adapters: RFID/NFC, Wireless, Active Directory/Entra ID/OpenLDAP, CI/CD")
    print("  Choose a category and provider from the main menu; saved provider names are not shown here.")
    print("  Backend: synthetic fixtures offline; configured read-only live connectors available when live mode is enabled")
    print("  Credential persistence: disabled")
    print(f"  Host OS: {host_os()} (directory and CI/CD connectors run on both Windows and Linux)")


def scenario_identity() -> None:
    audit("scenario.started", {"name": "synthetic_identity"})
    emit("identity", "Detection exercise: a mock badge UID appears in assessment telemetry.")
    emit("identity", f"Fixture UID={FIXTURES['badge_uid']}; no reader or radio hardware opened.")
    emit("identity", f"Mock directory identity={FIXTURES['username']}; no directory queried.")
    emit("identity", f"Mock DN={FIXTURES['dn']}; groups={', '.join(FIXTURES['groups'])}.")
    print(paint("[DETECTION] Expected: flag unknown badge UID and correlate with access logs.", "yellow"))
    session, valid = load_session()
    if valid:
        session["username_b64"] = base64.b64encode(FIXTURES["username"].encode()).decode("ascii")
        save_session(session)
        audit("session.updated", {"key": "username_b64", "source": "synthetic_fixture"})
    else:
        print(paint("[-] Session integrity failed; session was not changed.", "red"))
    audit("scenario.completed", {"name": "synthetic_identity"})


def scenario_wireless() -> None:
    audit("scenario.started", {"name": "synthetic_wireless"})
    emit("wireless", "Detection exercise: reviewing canned 868 MHz / 915 MHz observations.")
    emit("wireless", "Zigbee/LoRaWAN labels are synthetic fixtures; no radio is accessed.")
    emit("wireless", "No keys are guessed, captured, or transmitted.")
    emit("wireless", f"Documentation-only gateway marker={FIXTURES['gateway']}.")
    print(paint("[DETECTION] Expected: alert on unapproved device joins and policy drift.", "yellow"))
    session, valid = load_session()
    if valid:
        session["pivot_ip"] = FIXTURES["gateway"]
        save_session(session)
        audit("session.updated", {"key": "pivot_ip", "source": "synthetic_fixture"})
    else:
        print(paint("[-] Session integrity failed; session was not changed.", "red"))
    audit("scenario.completed", {"name": "synthetic_wireless"})


def scenario_pipeline() -> None:
    audit("scenario.started", {"name": "synthetic_pipeline"})
    session, valid = load_session()
    if valid:
        username = base64.b64decode(session["username_b64"]).decode() if session.get("username_b64") else "(unset)"
        pivot = session.get("pivot_ip") or "(unset)"
        emit("pipeline", f"Context loaded from local synthetic state: username={username}; pivot={pivot}.")
    else:
        emit("pipeline", "Session invalid; contextual simulation skipped.", "yellow", 0)
    emit("pipeline", "Simulating a proposed dependency change; no repository or pipeline is modified.")
    emit("pipeline", "Simulating container-policy review; no container or process is launched.")
    emit("pipeline", f"Credential-handling marker={FIXTURES['token_marker']}; no secret is accessed.")
    print(paint("[DETECTION] Expected: require protected branches, pinned dependencies, least privilege.", "yellow"))
    audit("scenario.completed", {"name": "synthetic_pipeline"})


def detection_test() -> None:
    """Evaluate fixed mock events against transparent, local detection rules."""
    mock_events = [
        {"id": "EVT-001", "type": "unknown_badge_uid", "approved": False, "mitre": "T1078"},
        {"id": "EVT-002", "type": "pipeline_dependency_unpinned", "approved": False, "mitre": "T1190"},
        {"id": "EVT-003", "type": "wireless_device_join", "approved": True, "mitre": "T1190"},
        {"id": "EVT-004", "type": "secret_access_attempt", "simulated": True, "mitre": "T1557"},
        {"id": "EVT-005", "type": "lateral_movement_rdp", "approved": False, "mitre": "T1021"},
        {"id": "EVT-006", "type": "credential_dump_lsass", "simulated": True, "mitre": "T1003"},
        {"id": "EVT-007", "type": "c2_beacon_periodic", "simulated": True, "mitre": "T1071"},
        {"id": "EVT-008", "type": "c2_non_standard_port", "simulated": True, "mitre": "T1571"},
    ]
    rules = {
        "unknown_badge_uid": lambda e: not e.get("approved", False),
        "pipeline_dependency_unpinned": lambda e: not e.get("approved", False),
        "wireless_device_join": lambda e: not e.get("approved", False),
        "secret_access_attempt": lambda e: bool(e.get("simulated", False)),
        "lateral_movement_rdp": lambda e: not e.get("approved", False),
        "credential_dump_lsass": lambda e: bool(e.get("simulated", False)),
        "c2_beacon_periodic": lambda e: bool(e.get("simulated", False)),
        "c2_non_standard_port": lambda e: bool(e.get("simulated", False)),
    }
    print("\nDetection test (synthetic events only)")
    alerts = 0
    for event in mock_events:
        matched = rules.get(event["type"], lambda _: False)(event)
        status = "ALERT" if matched else "no alert"
        alerts += int(matched)
        mitre_id = event.get("mitre", "")
        mitre_name = MITRE_ATTACK.get(mitre_id, {}).get("name", "")
        mitre_label = f"  {mitre_id} {mitre_name}" if mitre_id else ""
        print(f"  {event['id']}  {event['type']:<32} {status}{mitre_label}")
        audit("detection.result", {"event_id": event["id"], "type": event["type"], "alert": matched, "mitre": mitre_id})
    print(paint(f"[+] Detection rules generated {alerts} alert(s) from {len(mock_events)} mock events.", "green"))
    audit("detection.completed", {"events": len(mock_events), "alerts": alerts})


# ---------------------------------------------------------------------------
#  Multi-operator audit attribution
# ---------------------------------------------------------------------------

def load_operator() -> dict[str, Any] | None:
    if not OPERATOR_FILE.exists():
        return None
    try:
        return json.loads(OPERATOR_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def save_operator(name: str, engagement_id: str, authorization: str) -> None:
    data = {"operator": name, "engagement_id": engagement_id,
            "authorization": authorization, "set_at": now_iso()}
    atomic_write_json(OPERATOR_FILE, data)
    audit("operator.registered", {"operator": name, "engagement_id": engagement_id})


def get_operator_label() -> str:
    op = load_operator()
    if op and isinstance(op.get("operator"), str):
        return op["operator"]
    return "unregistered"


def register_operator() -> None:
    print("\nOperator registration (recorded in audit trail for attribution)")
    print("All engagement actions are attributed to this operator identity.")
    existing = load_operator()
    if existing:
        print(f"  Current operator: {existing.get('operator', '?')}")
        print(f"  Engagement ID:    {existing.get('engagement_id', '?')}")
        change = input("Change operator? Type YES to re-register: ").strip()
        if change != "YES":
            print("Operator unchanged.")
            return
    name = _prompt("Operator name or handle")
    engagement_id = _prompt("Engagement ID or ticket reference")
    authorization = _prompt("Authorization scope (e.g. 'RoE v1.2, scope: corp-net')")
    save_operator(name, engagement_id, authorization)
    print(paint(f"[+] Operator registered: {name} (engagement {engagement_id})", "green"))
    print("    All subsequent audit events include this operator identity.")


def operator_audit(event: str, details: dict[str, Any] | None = None) -> None:
    """Wrapper around audit() that injects the current operator identity."""
    op = load_operator()
    enriched = dict(details or {})
    if op:
        enriched["_operator"] = op.get("operator", "unregistered")
        enriched["_engagement_id"] = op.get("engagement_id", "unknown")
    audit(event, enriched)


# ---------------------------------------------------------------------------
#  Lateral movement scenario (T1021 / T1550 / T1087)
# ---------------------------------------------------------------------------

LATERAL_FIXTURES = {
    "hosts": [
        {"hostname": "WS-ASSessment-01", "os": "Windows 10", "ip": "192.0.2.10",
         "sessions": [{"user": FIXTURES["username"], "source": "interactive", "logon_type": 2}],
         "rdp_enabled": True, "admin_shares": ["C$", "ADMIN$"]},
        {"hostname": "SRV-ASSESSMENT-02", "os": "Windows Server 2019", "ip": "192.0.2.20",
         "sessions": [{"user": FIXTURES["username"], "source": "network", "logon_type": 3}],
         "rdp_enabled": True, "admin_shares": ["C$", "ADMIN$", "IPC$"]},
        {"hostname": "LNX-ASSESSMENT-03", "os": "Ubuntu 22.04", "ip": "192.0.2.30",
         "sessions": [{"user": FIXTURES["username"], "source": "ssh", "logon_type": "ssh"}],
         "rdp_enabled": False, "admin_shares": []},
    ],
    "credential_artifacts": [
        {"type": "kerberos_ticket", "user": FIXTURES["username"], "source_host": "WS-ASSESSMENT-01",
         "simulated": True, "note": "Synthetic TGT; no real ticket was requested or forged."},
        {"type": "cached_credentials", "user": FIXTURES["username"], "source_host": "SRV-ASSESSMENT-02",
         "simulated": True, "note": "Synthetic cached logon; no SAM/LSASS was accessed."},
    ],
}


def scenario_lateral_movement() -> None:
    audit("scenario.started", {"name": "lateral_movement"})
    print(paint("\n[Scenario] Lateral Movement Simulation", "cyan"))
    print("  MITRE ATT&CK: T1021 (Remote Services), T1550 (Alt Auth Material), T1087 (Account Discovery)")
    print("  All hostnames, IPs, and credentials are synthetic. No real system is contacted.\n")

    emit("lateral", "Enumerating synthetic host inventory from offline fixture.")
    for host in LATERAL_FIXTURES["hosts"]:
        emit("lateral", f"Host {host['hostname']} ({host['os']}) at {host['ip']} — {len(host['sessions'])} active session(s).", delay=0.08)
    emit("lateral", "Simulating remote service discovery (RDP/SSH availability check).", delay=0.08)
    for host in LATERAL_FIXTURES["hosts"]:
        svc = "RDP+admin-shares" if host["rdp_enabled"] and host["admin_shares"] else ("SSH" if not host["rdp_enabled"] else "RDP")
        emit("lateral", f"  {host['hostname']}: {svc} — lateral pathway candidate.", delay=0.08)

    emit("lateral", "Simulating alternate-auth-material usage (pass-the-ticket / pass-the-hash).", delay=0.08)
    for artifact in LATERAL_FIXTURES["credential_artifacts"]:
        emit("lateral", f"  {artifact['type']} for {artifact['user']} from {artifact['source_host']} — {artifact['note']}", delay=0.08)

    print(paint("\n[DETECTION] Expected alerts:", "yellow"))
    print("  - T1021: Alert on lateral RDP/SSH to non-standard hosts")
    print("  - T1550: Alert on authentication without password (ticket/hash reuse)")
    print("  - T1087: Alert on rapid account/group enumeration across multiple hosts")
    print("  - Correlate: source host, destination host, user, logon type, time window")

    operator_audit("scenario.lateral_movement", {"hosts": len(LATERAL_FIXTURES["hosts"]),
                                                     "artifacts": len(LATERAL_FIXTURES["credential_artifacts"]),
                                                     "mitre": ["T1021", "T1550", "T1087"]})
    audit("scenario.completed", {"name": "lateral_movement"})


# ---------------------------------------------------------------------------
#  Credential dumping scenario (T1003 / T1110)
# ---------------------------------------------------------------------------

CRED_DUMP_FIXTURES = {
    "targets": [
        {"process": "lsass.exe", "host": "WS-ASSESSMENT-01", "method": "synthetic_mini_dump",
         "simulated": True, "note": "No real LSASS memory was read or dumped."},
        {"process": "/etc/shadow", "host": "LNX-ASSESSMENT-03", "method": "synthetic_file_read",
         "simulated": True, "note": "No real shadow file was accessed."},
        {"source": "ntds.dit", "host": "SRV-ASSESSMENT-02", "method": "synthetic_vss_copy",
         "simulated": True, "note": "No real VSS snapshot or ntds.dit was created or read."},
    ],
    "brute_force_patterns": [
        {"target": FIXTURES["username"], "attempts": 47, "interval_seconds": 12,
         "note": "Synthetic timing pattern; no real authentication was attempted."},
        {"target": "admin@assessment.invalid", "attempts": 3, "interval_seconds": 600,
         "note": "Synthetic slow-pattern; no real authentication was attempted."},
    ],
    "synthetic_hash_samples": [
        {"hash_type": "NTLM", "value": "AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0",
         "user": FIXTURES["username"], "note": "Well-known empty-password NTLM hash; not a real credential."},
        {"hash_type": "Kerberoast", "value": "SIMULATED-KERBEROAST-HASH-NOT-REAL",
         "user": FIXTURES["username"], "note": "Synthetic hash string; no real ticket was requested."},
    ],
}


def scenario_credential_dumping() -> None:
    audit("scenario.started", {"name": "credential_dumping"})
    print(paint("\n[Scenario] Credential Dumping Pattern Simulation", "cyan"))
    print("  MITRE ATT&CK: T1003 (OS Credential Dumping), T1110 (Brute Force)")
    print("  All targets, hashes, and patterns are synthetic. No real credential store is accessed.\n")

    emit("cred_dump", "Simulating credential store access patterns (T1003).", delay=0.08)
    for target in CRED_DUMP_FIXTURES["targets"]:
        target_name = target.get("process") or target.get("source", "unknown")
        emit("cred_dump", f"  Target: {target_name} on {target['host']} via {target['method']}.", delay=0.08)
        emit("cred_dump", f"  {target['note']}", delay=0.05)

    emit("cred_dump", "Simulating brute-force timing patterns (T1110).", delay=0.08)
    for pattern in CRED_DUMP_FIXTURES["brute_force_patterns"]:
        rate = pattern["attempts"] / max(pattern["interval_seconds"], 1)
        emit("cred_dump", f"  Target: {pattern['target']} — {pattern['attempts']} attempts at {rate:.1f}/s. {pattern['note']}", delay=0.08)

    emit("cred_dump", "Displaying synthetic hash samples for detection-rule calibration.", delay=0.08)
    for sample in CRED_DUMP_FIXTURES["synthetic_hash_samples"]:
        emit("cred_dump", f"  {sample['hash_type']} ({sample['user']}): {sample['value'][:40]}...", delay=0.05)
        emit("cred_dump", f"  {sample['note']}", delay=0.05)

    print(paint("\n[DETECTION] Expected alerts:", "yellow"))
    print("  - T1003.001: Alert on process accessing LSASS (e.g. Mimikatz, procdump, comsvcs.dll)")
    print("  - T1003.002: Alert on ntds.dit access or VSS snapshot creation by non-admin")
    print("  - T1003.008: Alert on /etc/shadow read by non-root process")
    print("  - T1110: Alert on repeated authentication failures exceeding threshold")
    print("  - Correlate: process name, access rights, target file, user context, time")

    operator_audit("scenario.credential_dumping", {"targets": len(CRED_DUMP_FIXTURES["targets"]),
                                                        "brute_patterns": len(CRED_DUMP_FIXTURES["brute_force_patterns"]),
                                                        "mitre": ["T1003", "T1110"]})
    audit("scenario.completed", {"name": "credential_dumping"})


# ---------------------------------------------------------------------------
#  C2 beacon detection scenario (T1071 / T1571 / T1572 / T1573)
# ---------------------------------------------------------------------------

C2_FIXTURES = {
    "beacons": [
        {"id": "BCN-001", "host": "WS-ASSESSMENT-01", "dst_ip": "198.51.100.5",
         "dst_port": 443, "protocol": "HTTPS", "interval_seconds": 60, "jitter_seconds": 5,
         "mitre": "T1071", "note": "Synthetic periodic beacon to documentation IP range."},
        {"id": "BCN-002", "host": "WS-ASSESSMENT-01", "dst_ip": "198.51.100.10",
         "dst_port": 8443, "protocol": "TLS", "interval_seconds": 30, "jitter_seconds": 2,
         "mitre": "T1571", "note": "Synthetic beacon on non-standard port 8443."},
        {"id": "BCN-003", "host": "SRV-ASSESSMENT-02", "dst_ip": "198.51.100.15",
         "dst_port": 53, "protocol": "DNS-over-HTTPS", "interval_seconds": 120, "jitter_seconds": 15,
         "mitre": "T1572", "note": "Synthetic DNS tunneling pattern for data exfiltration simulation."},
        {"id": "BCN-004", "host": "LNX-ASSESSMENT-03", "dst_ip": "198.51.100.20",
         "dst_port": 993, "protocol": "IMAPS (tunneled)", "interval_seconds": 300, "jitter_seconds": 30,
         "mitre": "T1573", "note": "Synthetic encrypted channel masquerading as legitimate IMAPS traffic."},
    ],
    "dns_queries": [
        {"query": "update.assessment.invalid", "type": "A", "frequency": "every 60s",
         "mitre": "T1071", "note": "Synthetic C2 domain in .invalid TLD; no real DNS was made."},
        {"query": "cdn.assessment.invalid", "type": "TXT", "frequency": "every 90s",
         "mitre": "T1071", "note": "Synthetic TXT record exfil pattern; no real DNS was made."},
    ],
}


def scenario_c2_beacon() -> None:
    audit("scenario.started", {"name": "c2_beacon_detection"})
    print(paint("\n[Scenario] C2 Beacon Detection Simulation", "cyan"))
    print("  MITRE ATT&CK: T1071 (App Layer Protocol), T1571 (Non-Standard Port),")
    print("                T1572 (Protocol Tunneling), T1573 (Encrypted Channel)")
    print("  All IPs, domains, and traffic patterns are synthetic. No real network connection is made.\n")

    emit("c2", "Analyzing synthetic network beacon patterns from offline fixture.", delay=0.08)
    for beacon in C2_FIXTURES["beacons"]:
        mitre_name = MITRE_ATTACK.get(beacon["mitre"], {}).get("name", "")
        emit("c2", f"  {beacon['id']}: {beacon['host']} -> {beacon['dst_ip']}:{beacon['dst_port']} "
              f"({beacon['protocol']}) every {beacon['interval_seconds']}s +/- {beacon['jitter_seconds']}s "
              f"[{beacon['mitre']} {mitre_name}]", delay=0.08)
        emit("c2", f"    {beacon['note']}", delay=0.05)

    emit("c2", "Analyzing synthetic DNS query patterns for C2 and exfiltration indicators.", delay=0.08)
    for query in C2_FIXTURES["dns_queries"]:
        mitre_name = MITRE_ATTACK.get(query["mitre"], {}).get("name", "")
        emit("c2", f"  {query['query']} ({query['type']}) {query['frequency']} [{query['mitre']} {mitre_name}]", delay=0.08)
        emit("c2", f"    {query['note']}", delay=0.05)

    print(paint("\n[DETECTION] Expected alerts:", "yellow"))
    print("  - T1071: Alert on regular, low-jitter beacon intervals to external hosts")
    print("  - T1571: Alert on TLS/HTTPS traffic to non-standard ports (e.g. 8443, 993 for C2)")
    print("  - T1572: Alert on DNS tunneling indicators (high TXT volume, long subdomain labels)")
    print("  - T1573: Alert on encrypted channels to newly-seen domains or IPs")
    print("  - Correlate: destination reputation, port, interval regularity, beacon jitter, payload size")

    operator_audit("scenario.c2_beacon", {"beacons": len(C2_FIXTURES["beacons"]),
                                              "dns_queries": len(C2_FIXTURES["dns_queries"]),
                                              "mitre": ["T1071", "T1571", "T1572", "T1573"]})
    audit("scenario.completed", {"name": "c2_beacon_detection"})


# ---------------------------------------------------------------------------
#  MITRE ATT&CK technique browser
# ---------------------------------------------------------------------------

def mitre_browser() -> None:
    print(paint("\nMITRE ATT&CK Technique Reference", "cyan"))
    print(f"  {len(MITRE_ATTACK)} techniques mapped in this tool.\n")
    for tactic in sorted(set(t["tactic"] for t in MITRE_ATTACK.values())):
        print(paint(f"  [{tactic}]", "yellow"))
        for tid, info in sorted(MITRE_ATTACK.items()):
            if info["tactic"] == tactic:
                platforms = ", ".join(info["platforms"])
                print(f"    {tid}  {info['name']:<45}  ({platforms})")
    print()
    audit("mitre.browsed", {"technique_count": len(MITRE_ATTACK)})


# ---------------------------------------------------------------------------
#  Engagement report generator
# ---------------------------------------------------------------------------

def generate_report() -> None:
    print(paint("\nEngagement Report Generator", "cyan"))
    op = load_operator()
    if op:
        print(f"  Operator:       {op.get('operator', '?')}")
        print(f"  Engagement ID:  {op.get('engagement_id', '?')}")
        print(f"  Authorization:  {op.get('authorization', '?')}")
    else:
        print(paint("  [!] No operator registered. Use menu 15 to register for attribution.", "yellow"))

    chain_ok, event_count, chain_msg = verify_audit_chain()
    session, session_valid = load_session()

    scenarios_run: list[str] = []
    detections_run = 0
    detection_alerts = 0
    adapter_reads = 0
    live_reads = 0

    if AUDIT_FILE.exists():
        with AUDIT_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                evt = record.get("event", "")
                if evt == "scenario.completed":
                    name = record.get("details", {}).get("name", "unknown")
                    scenarios_run.append(name)
                elif evt == "detection.completed":
                    detections_run += 1
                    detection_alerts += record.get("details", {}).get("alerts", 0)
                elif evt == "integration.snapshot_read":
                    adapter_reads += 1
                elif evt == "integration.live_read_succeeded":
                    live_reads += 1

    mitre_used: set[str] = set()
    for sname in scenarios_run:
        for mapping in _SCENARIO_MITRE_MAP.values():
            if sname in mapping.get("names", []):
                mitre_used.update(mapping["techniques"])

    report = {
        "generated_at": now_iso(),
        "operator": op or {"operator": "unregistered", "engagement_id": "unknown", "authorization": "unknown"},
        "tool": APP_NAME,
        "engagement_summary": {
            "scenarios_executed": scenarios_run,
            "scenario_count": len(scenarios_run),
            "detection_test_runs": detections_run,
            "detection_alerts_total": detection_alerts,
            "adapter_snapshot_reads": adapter_reads,
            "live_read_only_connectors": live_reads,
        },
        "mitre_attack_coverage": {
            tid: MITRE_ATTACK[tid] for tid in sorted(mitre_used) if tid in MITRE_ATTACK
        },
        "integrity": {
            "session_valid": session_valid,
            "audit_chain_valid": chain_ok,
            "audit_event_count": event_count,
            "audit_chain_message": chain_msg,
        },
        "note": "All scenarios use synthetic fixtures. No real system, credential, or network was contacted unless a live read-only connector was explicitly approved.",
    }

    atomic_write_json(REPORT_FILE, report)
    audit("report.generated", {"scenarios": len(scenarios_run), "detections": detections_run,
                                "mitre_techniques": len(mitre_used), "file": REPORT_FILE.name})

    print(f"\n  Scenarios executed:    {len(scenarios_run)}")
    for s in scenarios_run:
        print(f"    - {s}")
    print(f"  Detection test runs:   {detections_run} ({detection_alerts} total alerts)")
    print(f"  Adapter snapshot reads: {adapter_reads}")
    print(f"  Live read-only reads:  {live_reads}")
    print(f"  MITRE techniques covered: {len(mitre_used)}")
    for tid in sorted(mitre_used):
        name = MITRE_ATTACK.get(tid, {}).get("name", "?")
        print(f"    {tid}  {name}")
    print(f"\n  Audit chain: {'OK' if chain_ok else 'FAILED'} — {event_count} events")
    print(f"  Session:     {'OK' if session_valid else 'FAILED'}")
    print(paint(f"\n[+] Report saved to {REPORT_FILE}", "green"))


_SCENARIO_MITRE_MAP = {
    "identity": {"names": ["synthetic_identity"], "techniques": ["T1078", "T1087"]},
    "wireless": {"names": ["synthetic_wireless"], "techniques": ["T1190", "T1573"]},
    "pipeline": {"names": ["synthetic_pipeline"], "techniques": ["T1190", "T1053", "T1547"]},
    "lateral": {"names": ["lateral_movement"], "techniques": ["T1021", "T1550", "T1087"]},
    "cred_dump": {"names": ["credential_dumping"], "techniques": ["T1003", "T1110"]},
    "c2": {"names": ["c2_beacon_detection"], "techniques": ["T1071", "T1571", "T1572", "T1573"]},
}


def integrity_check() -> None:
    session, valid = load_session()
    chain_ok, count, chain_msg = verify_audit_chain()
    print("\nIntegrity report")
    print(f"  Session JSON: {'OK' if valid else 'FAILED / MISSING OR INVALID'}")
    print(f"  Audit chain:  {'OK' if chain_ok else 'FAILED'} — {chain_msg}")
    _, key_mode = _audit_key()
    print(f"  Audit signing: {key_mode}")
    if key_mode.endswith("weak"):
        print(paint("  WARNING: set SHADOWBOX_SEC_AUDIT_KEY to a random secret of at least 32 bytes for meaningful HMAC protection.", "yellow"))
    audit("integrity.checked", {"session_valid": valid, "audit_chain_valid": chain_ok, "prior_event_count": count})
    if not valid or not chain_ok:
        print(paint("[-] Integrity issue found. Preserve evidence and investigate before repair.", "red"))
    else:
        print(paint("[+] Local integrity checks passed.", "green"))


def show_menu() -> None:
    config = load_integration_config()
    print("\n" + paint("=" * 74, "cyan"))
    print(paint(f"  {APP_NAME.upper()}", "cyan"))
    print("=" * 74)
    print(f"  Mode: {config['mode'].upper()} ({'synthetic fixtures' if config['mode'] == 'offline' else 'live read-only'})")
    print(f"  Operator: {get_operator_label()}")
    print("\n  [INTEGRATION ADAPTERS]")
    print("  1) RFID/NFC")
    print("  2) Wireless")
    print("  3) Active Directory / Entra ID / OpenLDAP")
    print("  4) CI/CD")
    print("\n  [RED TEAM TELEMETRY SCENARIOS]")
    print("  7) Identity telemetry")
    print("  8) Wireless telemetry")
    print("  9) Pipeline telemetry")
    print(" 10) Lateral movement")
    print(" 11) Credential dumping")
    print(" 12) C2 beacon")
    print("\n  [SYSTEM TOOLS & UTILITIES]")
    print("  5) Requirements guide")
    toggle_label = "ON (select to disable)" if config["mode"] == "live" else "OFF (select to enable)"
    print(f"  6) Live mode: {toggle_label}")
    print(" 13) Detection test")
    print(" 14) MITRE browser")
    print(" 15) Register operator")
    print(" 16) Integrity check")
    print(" 17) Generate report")
    print("\n  Select 1-4 to choose a provider and run that adapter. Option 5 shows Live requirements in either mode.")
    print("  Option 6 toggles Live mode; the guide opens only when you select 5.")
    print("  Live automatically resets to OFFLINE on quit/interrupt; a forced-close run starts OFFLINE next time.")
    print("  Enter Q to quit.\n")


def main() -> int:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Cannot initialize state directory ({type(exc).__name__}). Check filesystem permissions.", file=sys.stderr)
        return 2
    session, _ = load_session()
    if reset_live_mode_to_offline("startup_recovery"):
        print("Previous Live mode was reset to OFFLINE; provider selections were preserved.")
    try:
        audit("application.started", {"app": APP_NAME, "mode": load_integration_config()["mode"]})
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Cannot safely initialize audit trail ({type(exc).__name__}); refusing to start.", file=sys.stderr)
        return 2
    try:
        print_startup_status()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Startup check failed ({type(exc).__name__}). Check state files and permissions.", file=sys.stderr)
        return 2
    interrupted = False
    try:
        while True:
            show_menu()
            try:
                choice = input("shadowbox_sec [1-17/Q]> ").strip().lower()
            except EOFError:
                choice = "q"
            if choice in {"q", "quit", "exit"}:
                break
            elif choice == "1":
                choose_provider_and_run("rfid_nfc")
            elif choice == "2":
                choose_provider_and_run("wireless")
            elif choice == "3":
                choose_provider_and_run("active_directory")
            elif choice == "4":
                choose_provider_and_run("cicd")
            elif choice == "5":
                print_connection_requirements(load_integration_config())
            elif choice == "6":
                toggle_live_mode()
            elif choice == "7":
                scenario_identity()
            elif choice == "8":
                scenario_wireless()
            elif choice == "9":
                scenario_pipeline()
            elif choice == "10":
                scenario_lateral_movement()
            elif choice == "11":
                scenario_credential_dumping()
            elif choice == "12":
                scenario_c2_beacon()
            elif choice == "13":
                detection_test()
            elif choice == "14":
                mitre_browser()
            elif choice == "15":
                register_operator()
            elif choice == "16":
                integrity_check()
            elif choice == "17":
                generate_report()
            else:
                print(paint("[-] Choose 1-17, or Q to quit.", "yellow"))
    except (KeyboardInterrupt, EOFError):
        interrupted = True
    finally:
        try:
            if reset_live_mode_to_offline("application_exit"):
                print("Live mode automatically switched OFF; provider selections were preserved.")
        except Exception as exc:
            print(f"Could not reset Live mode to OFFLINE: {type(exc).__name__}", file=sys.stderr)
        message = "Interrupted; tool files left intact." if interrupted else "Exited normally; tool files left intact."
        try:
            audit("application.stopped", {"message": message})
        except OSError as exc:
            print(f"Could not append audit event: {exc}", file=sys.stderr)
        print(paint(f"\n[+] {message}", "green"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
