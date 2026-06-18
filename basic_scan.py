#!/usr/bin/env python3
"""
Python 3.12 version of the legacy basic network inventory scanner.

Main changes:
- Replaces deprecated pysnmp.entity.rfc3413.oneliner.cmdgen with pysnmp.hlapi.v3arch.asyncio.
- Supports SNMPv2c and SNMPv3, with optional v2c-first/v3 fallback probing.
- Replaces MySQLdb/mysqlclient usage with mysql-connector-python.
- Uses JSON for list/dict columns instead of Python repr strings.
- Removes hard-coded SSH passwords. Put secrets in Settings.json or environment variables.
- Adds Huawei VRP CLI fallback collection for interfaces, serial number, BGP local AS/router ID, and peer summary.
- Adds Fortigate-safe SNMP IP OID parsing and optional Fortigate CLI interface fallback.
- Decodes SNMP OCTET STRING hex output such as 0x4875... into readable model/version text.
- Keeps only the latest database row per device IP by using upsert when possible and deleting stale rows.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import random
import re
import smtplib
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import mysql.connector
from netmiko import ConnectHandler
# PySNMP 7.x: use v3arch asyncio for both SNMPv1/v2c and SNMPv3.
# The fallback keeps compatibility with older pysnmp packages that expose the
# same objects directly under pysnmp.hlapi.asyncio.
try:
    from pysnmp.hlapi.v3arch import asyncio as pysnmp_asyncio
except ImportError:  # pragma: no cover - compatibility fallback
    from pysnmp.hlapi import asyncio as pysnmp_asyncio  # type: ignore

SnmpEngine = pysnmp_asyncio.SnmpEngine
CommunityData = pysnmp_asyncio.CommunityData
UsmUserData = pysnmp_asyncio.UsmUserData
UdpTransportTarget = pysnmp_asyncio.UdpTransportTarget
ContextData = pysnmp_asyncio.ContextData
ObjectType = pysnmp_asyncio.ObjectType
ObjectIdentity = pysnmp_asyncio.ObjectIdentity
get_cmd = getattr(pysnmp_asyncio, "get_cmd", None) or getattr(pysnmp_asyncio, "getCmd", None)
walk_cmd = getattr(pysnmp_asyncio, "walk_cmd", None) or getattr(pysnmp_asyncio, "nextCmd", None)
if get_cmd is None or walk_cmd is None:  # pragma: no cover - import-time guard
    raise ImportError("PySNMP asyncio get/walk command functions are unavailable")

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
OID_ARISTA_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11.1"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"
OID_IP_AD_ENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"
OID_BGP_LOCAL_AS = "1.3.6.1.2.1.15.2.0"
OID_BGP_IDENTIFIER = "1.3.6.1.2.1.15.4.0"

OS_ESCAPE = (
    "juniper",
    "dell network",
    "arbor",
    "peakflow",
    "linux",
    "f5hosst",
    "sg300",
)
OS_SET1 = ("arista", "nx-os", "ios", "huawei", "ruijie")
OS_SET2 = ("fortigate", "adaptive security appliance", "thunder", "palo alto")
NO_SUCH_MARKERS = ("No Such", "No more variables left", "EndOfMibView")
MYSQL_RETRYABLE_ERRNOS = {1205, 1213}

# Canonical platform -> sysDescr aliases.  Huawei devices often expose VRP/Quidway/
# CloudEngine/NetEngine in sysDescr without the literal word "Huawei".
PLATFORM_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("huawei", (
        "huawei",
        "huawei technologies",
        "vrp",
        "versatile routing platform",
        "quidway",
        "cloudengine",
        "netengine",
        "s5700",
        "s5720",
        "s5730",
        "s5731",
        "s5735",
        "s6720",
        "s6730",
        "ce5800",
        "ce6800",
        "ce8800",
        "ne40e",
        "ne8000",
    )),
    ("arista", ("arista", "eos")),
    ("nx-os", ("nx-os", "nxos", "nexus")),
    ("ios", ("ios-xe", "ios xe", "ios software", "cisco ios")),
    ("ruijie", ("ruijie",)),
    ("fortigate", ("fortigate", "fortinet")),
    ("adaptive security appliance", ("adaptive security appliance", "cisco adaptive security appliance", "asa software")),
    ("thunder", ("thunder", "a10")),
    ("palo alto", ("palo alto", "pan-os", "panos")),
    ("juniper", ("juniper", "junos")),
    ("dell network", ("dell network", "dell networking")),
    ("arbor", ("arbor",)),
    ("peakflow", ("peakflow",)),
    ("linux", ("linux",)),
    ("f5hosst", ("f5hosst", "f5", "big-ip")),
    ("sg300", ("sg300",)),
)
HUAWEI_DETECTION_ALIASES = PLATFORM_ALIASES[0][1]
HUAWEI_SYSOBJECTID_PREFIXES = ("1.3.6.1.4.1.2011",)

Settings = dict[str, Any]
InterfaceList = list[dict[str, str]]


def to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def secret_value(
    settings: Settings,
    direct_keys: tuple[str, ...],
    env_setting_keys: tuple[str, ...] = (),
    env_names: tuple[str, ...] = (),
) -> str | None:
    """Read a secret from an env-var name in settings, a fixed env var, or a direct setting."""
    for setting_key in env_setting_keys:
        env_name = str(settings.get(setting_key, "")).strip()
        if env_name:
            value = os.getenv(env_name)
            if value:
                return value

    for env_name in env_names:
        value = os.getenv(env_name)
        if value:
            return value

    for direct_key in direct_keys:
        value = settings.get(direct_key)
        if value not in (None, ""):
            return str(value)

    return None


def pretty(obj: Any) -> str:
    try:
        value = obj.prettyPrint()
    except AttributeError:
        value = str(obj)
    return decode_snmp_hex_octet_string(value)


def has_no_such(value: str | None) -> bool:
    if value is None:
        return True
    return any(marker in value for marker in NO_SUCH_MARKERS)


def printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    printable_count = sum(1 for char in value if char.isprintable() or char in "\r\n\t")
    return printable_count / len(value)


def decode_snmp_hex_octet_string(value: str | None) -> str:
    """Decode PySNMP hex-rendered OCTET STRING values when they are printable text.

    Some Huawei sysDescr values contain CR/LF bytes.  PySNMP can render those
    OCTET STRINGs as hex, for example 0x487561776569..., although the payload is
    actually readable display-version/sysDescr text.
    """
    if value is None:
        return ""

    text = str(value)
    stripped = text.strip()
    if not stripped.lower().startswith("0x"):
        return text

    hex_digits = re.sub(r"[^0-9A-Fa-f]", "", stripped[2:])
    if len(hex_digits) < 2 or len(hex_digits) % 2:
        return text

    try:
        payload = bytes.fromhex(hex_digits)
    except ValueError:
        return text

    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            decoded = payload.decode(encoding)
        except UnicodeDecodeError:
            continue

        decoded = decoded.replace("\x00", "").strip()
        if decoded and printable_ratio(decoded) >= 0.85:
            return decoded

    return text


def display_text(value: str | None) -> str:
    """Return a readable SNMP text value while preserving useful line breaks."""
    text = decode_snmp_hex_octet_string(value)
    text = text.replace("\x00", "")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def compact_display_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", display_text(value)).strip()


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def trailing_ipv4_from_oid(oid: str) -> str | None:
    parts = oid.strip(".").split(".")
    if len(parts) < 4:
        return None
    tail = parts[-4:]
    if all(part.isdigit() and 0 <= int(part) <= 255 for part in tail):
        return ".".join(tail)
    return None



def oid_numeric_parts(oid: str) -> list[int]:
    """Return numeric OID components from a dotted numeric OID string."""
    parts: list[int] = []
    for raw_part in str(oid or "").strip().strip(".").split("."):
        part = raw_part.strip()
        if part.isdigit():
            parts.append(int(part))
    return parts


def ipv4_index_after_base_oid(oid: str, base_oid: str) -> str | None:
    """Extract the IPv4 instance immediately after a known SNMP table OID.

    The old parser used the last four OID components.  On some Fortigate/FortiOS
    SNMP rows, an extra numeric component can appear after the IPv4 address, for
    example::

        1.3.6.1.2.1.4.20.1.2.10.163.2.209.103

    Last-four parsing turns that into 163.2.209.103.  For ipAdEntIfIndex and
    ipAdEntNetMask, the IPv4 address begins immediately after the base OID, so
    this function uses the first four suffix octets and ignores any later suffix.
    """
    oid_parts = oid_numeric_parts(oid)
    base_parts = oid_numeric_parts(base_oid)
    if base_parts and len(oid_parts) >= len(base_parts) + 4 and oid_parts[: len(base_parts)] == base_parts:
        candidate = oid_parts[len(base_parts): len(base_parts) + 4]
        if all(0 <= part <= 255 for part in candidate):
            return ".".join(str(part) for part in candidate)

    # Compatibility fallback for unexpected renderings that do not start with the
    # numeric base OID.
    return trailing_ipv4_from_oid(oid)


def last_index_from_oid(oid: str) -> str | None:
    parts = oid.strip(".").split(".")
    if not parts:
        return None
    return parts[-1] if parts[-1].isdigit() else None


def netmask_to_prefix_len(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return None


def normalize_ip_cidr_token(value: str) -> str | None:
    """Normalize tokens like 10.0.0.1/24 or 10.0.0.1/255.255.255.0."""
    token = str(value).strip().strip(",;()[]{}")
    if "/" not in token:
        return None

    ip_text, mask_text = token.rsplit("/", 1)
    ip_text = ip_text.strip()
    mask_text = mask_text.strip()
    try:
        ipaddress.IPv4Address(ip_text)
    except ValueError:
        return None

    if mask_text.isdigit():
        prefix_len = to_int(mask_text, -1)
    else:
        prefix_len = netmask_to_prefix_len(mask_text)

    if prefix_len is None or prefix_len < 0 or prefix_len > 32:
        return None

    try:
        iface = ipaddress.IPv4Interface(f"{ip_text}/{prefix_len}")
    except ValueError:
        return None
    return f"{iface.ip}/{iface.network.prefixlen}"


def is_ipv4_text(value: str) -> bool:
    try:
        ipaddress.IPv4Address(str(value).strip())
        return True
    except ValueError:
        return False


def probable_serial_token(value: str) -> str | None:
    token = str(value).strip().strip(" ,;:'\"[](){}<>")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{8,80}", token):
        return None
    if "." in token and is_ipv4_text(token):
        return None
    lower_token = token.lower()
    excluded = {
        "barcode",
        "bar-code",
        "serial",
        "number",
        "device",
        "manufacture",
        "manufactured",
        "slotid",
        "boardtype",
        "item",
        "description",
        "port",
        "module",
        "version",
    }
    if lower_token in excluded:
        return None
    if not any(ch.isdigit() for ch in token):
        return None
    if len(set(token.replace("-", "").replace("_", "").replace(".", ""))) <= 1:
        return None
    return token


def setting_list(settings: Settings, key: str, default: list[str]) -> list[str]:
    value = settings.get(key)
    if value in (None, ""):
        return list(default)
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        parts = re.split(r"[,;\n]+", value)
        return [part.strip() for part in parts if part.strip()]
    return list(default)


def parse_ip_cidr(ip_cidr: str) -> tuple[str, int | None]:
    value = str(ip_cidr).strip()
    try:
        iface = ipaddress.ip_interface(value)
        return str(iface.ip), int(iface.network.prefixlen)
    except ValueError:
        pass

    if "/" in value:
        ip_part, prefix_part = value.rsplit("/", 1)
        return ip_part.strip(), to_int(prefix_part, -1) if prefix_part.isdigit() else None

    return value, None


def normalized_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", display_text(value).replace("\n", " ")).strip().lower()


def alias_in_text(alias: str, text: str) -> bool:
    alias_norm = normalized_text(alias)
    if not alias_norm:
        return False

    # Short aliases such as VRP/EOS/F5 should match as whole tokens only to avoid
    # false positives inside unrelated words.
    if re.fullmatch(r"[a-z0-9]{2,4}", alias_norm):
        return re.search(rf"(?<![a-z0-9]){re.escape(alias_norm)}(?![a-z0-9])", text) is not None

    return alias_norm in text


def normalize_sysobjectid(value: str | None) -> str:
    oid = str(value or "").strip().lower()
    oid = oid.replace("iso.", "1.")
    oid = oid.replace("snmpv2-smi::enterprises.", "1.3.6.1.4.1.")
    oid = oid.replace("enterprises.", "1.3.6.1.4.1.")
    return oid.strip(" .")


def oid_has_prefix(oid: str | None, prefix: str) -> bool:
    oid_norm = normalize_sysobjectid(oid)
    prefix_norm = normalize_sysobjectid(prefix)
    return oid_norm == prefix_norm or oid_norm.startswith(prefix_norm + ".")


def normalize_platform_name(value: Any) -> str | None:
    platform = normalized_text(str(value or ""))
    if not platform:
        return None
    aliases = {
        "nxos": "nx-os",
        "cisco_nxos": "nx-os",
        "cisco nx-os": "nx-os",
        "eos": "arista",
        "arista_eos": "arista",
        "huawei_vrp": "huawei",
        "huawei_vrpv8": "huawei",
        "huawei vrp": "huawei",
        "pa": "palo alto",
        "panos": "palo alto",
        "paloalto": "palo alto",
        "paloalto_panos": "palo alto",
    }
    platform = aliases.get(platform, platform)
    known_platforms = set(OS_SET1) | set(OS_SET2) | set(OS_ESCAPE)
    return platform if platform in known_platforms else None


def detect_platform(
    sys_descr: str,
    sys_object_id: str | None = None,
    settings: Settings | None = None,
) -> str | None:
    settings = settings or {}

    huawei_oid_prefixes = setting_list(
        settings,
        "huawei_sysobjectid_prefixes",
        list(HUAWEI_SYSOBJECTID_PREFIXES),
    )
    if sys_object_id and any(oid_has_prefix(sys_object_id, prefix) for prefix in huawei_oid_prefixes):
        return "huawei"

    text = normalized_text(sys_descr)
    huawei_aliases = setting_list(
        settings,
        "huawei_description_keywords",
        list(HUAWEI_DETECTION_ALIASES),
    )
    if any(alias_in_text(alias, text) for alias in huawei_aliases):
        return "huawei"

    for platform, aliases in PLATFORM_ALIASES:
        if platform == "huawei":
            continue
        if any(alias_in_text(alias, text) for alias in aliases):
            return platform
    return None


def selector_matches_ip(device_ip: str, selector: str) -> bool:
    selector = str(selector or "").strip()
    if not selector:
        return False
    if selector == device_ip:
        return True
    if "/" not in selector:
        return False
    try:
        return ipaddress.ip_address(device_ip) in ipaddress.ip_network(selector, strict=False)
    except ValueError:
        return False


def platform_override(device_ip: str, settings: Settings) -> str | None:
    overrides = settings.get("platform_overrides", {})
    if isinstance(overrides, dict):
        for selector, platform in overrides.items():
            if not selector_matches_ip(device_ip, str(selector)):
                continue
            override = normalize_platform_name(platform)
            if override:
                return override
            if platform not in (None, ""):
                raise ValueError(f"Unsupported platform override for {device_ip}: {platform}")

    for selector in setting_list(settings, "force_huawei_ips", []):
        if selector_matches_ip(device_ip, selector):
            return "huawei"

    return None


def setting_or_env(settings: Settings, key: str, env_name: str, default: Any = None) -> Any:
    value = settings.get(key)
    if value not in (None, ""):
        return value
    env_value = os.getenv(env_name)
    if env_value not in (None, ""):
        return env_value
    return default


def setting_or_configured_env(
    settings: Settings,
    direct_keys: tuple[str, ...],
    env_setting_keys: tuple[str, ...] = (),
    env_names: tuple[str, ...] = (),
    default: Any = None,
) -> Any:
    for setting_key in env_setting_keys:
        env_name = str(settings.get(setting_key, "")).strip()
        if env_name:
            env_value = os.getenv(env_name)
            if env_value not in (None, ""):
                return env_value

    for env_name in env_names:
        env_value = os.getenv(env_name)
        if env_value not in (None, ""):
            return env_value

    for direct_key in direct_keys:
        value = settings.get(direct_key)
        if value not in (None, ""):
            return value

    return default


def normalize_snmp_version(value: Any) -> str | None:
    version = str(value or "").strip().lower()
    version = version.replace("snmp", "").replace("v", "")
    if version in {"1"}:
        return "1"
    if version in {"2", "2c", "c2"}:
        return "2c"
    if version in {"3"}:
        return "3"
    return None


def snmp_version_order(settings: Settings) -> list[str]:
    raw_versions = settings.get("snmp_versions")
    versions_key = "snmp_versions"
    if raw_versions in (None, "") and settings.get("snmp_try_versions") not in (None, ""):
        raw_versions = settings.get("snmp_try_versions")
        versions_key = "snmp_try_versions"
    versions: list[str]
    if raw_versions not in (None, ""):
        versions = setting_list(settings, versions_key, [])
    else:
        raw_version = str(setting_or_env(settings, "snmp_version", "SNMP_VERSION", "2c")).strip().lower()
        if raw_version in {"auto", "fallback", "v2c+v3", "v2c,v3", "2c,3", "all"}:
            versions = ["2c", "3"]
        elif raw_version in {"v3+v2c", "v3,v2c", "3,2c"}:
            versions = ["3", "2c"]
        else:
            versions = [raw_version]

    normalized: list[str] = []
    for item in versions:
        version = normalize_snmp_version(item)
        if version and version not in normalized:
            normalized.append(version)

    if as_bool(setting_or_env(settings, "snmpv3_enabled", "SNMPV3_ENABLED", False), False) and "3" not in normalized:
        if as_bool(setting_or_env(settings, "snmpv3_prefer", "SNMPV3_PREFER", False), False):
            normalized.insert(0, "3")
        else:
            normalized.append("3")

    return normalized or ["2c"]


def _pysnmp_symbol(name: str, fallback: Any = None) -> Any:
    return getattr(pysnmp_asyncio, name, fallback)


def snmpv3_auth_protocol(name: Any) -> Any:
    default_proto = _pysnmp_symbol("usmHMACSHAAuthProtocol")
    mapping = {
        "md5": _pysnmp_symbol("usmHMACMD5AuthProtocol", default_proto),
        "sha": default_proto,
        "sha1": default_proto,
        "sha224": _pysnmp_symbol("usmHMAC128SHA224AuthProtocol", default_proto),
        "sha256": _pysnmp_symbol("usmHMAC192SHA256AuthProtocol", default_proto),
        "sha384": _pysnmp_symbol("usmHMAC256SHA384AuthProtocol", default_proto),
        "sha512": _pysnmp_symbol("usmHMAC384SHA512AuthProtocol", default_proto),
    }
    key = str(name or "sha").strip().lower()
    key = key.replace("hmac", "").replace("_", "").replace("-", "")
    return mapping.get(key, default_proto)


def snmpv3_priv_protocol(name: Any) -> Any:
    default_proto = _pysnmp_symbol("usmAesCfb128Protocol")
    mapping = {
        "des": _pysnmp_symbol("usmDESPrivProtocol", default_proto),
        "3des": _pysnmp_symbol("usm3DESEDEPrivProtocol", default_proto),
        "aes": default_proto,
        "aes128": default_proto,
        "aes192": _pysnmp_symbol("usmAesCfb192Protocol", default_proto),
        "aes256": _pysnmp_symbol("usmAesCfb256Protocol", default_proto),
    }
    key = str(name or "aes128").strip().lower().replace("_", "").replace("-", "")
    return mapping.get(key, default_proto)


@dataclass(frozen=True)
class SnmpAuthAttempt:
    label: str
    auth_data: Any


SNMP_AUTH_CACHE: dict[tuple[str, int], str] = {}


@dataclass
class SnmpClient:
    host: str
    settings: Settings

    def __post_init__(self) -> None:
        self.community = str(setting_or_env(self.settings, "community", "SNMP_COMMUNITY", "public"))
        self.port = to_int(setting_or_env(self.settings, "port", "SNMP_PORT", 161), 161)
        self.timeout = to_float(setting_or_env(self.settings, "snmp_timeout", "SNMP_TIMEOUT", 5.0), 5.0)
        self.retries = to_int(setting_or_env(self.settings, "snmp_retries", "SNMP_RETRIES", 3), 3)
        self.snmp_engine = SnmpEngine()
        self.credential_errors: list[str] = []
        self.auth_attempts = self.build_auth_attempts()

    def build_auth_attempts(self) -> list[SnmpAuthAttempt]:
        attempts: list[SnmpAuthAttempt] = []
        for version in snmp_version_order(self.settings):
            if version == "1":
                attempts.append(SnmpAuthAttempt("v1", CommunityData(self.community, mpModel=0)))
            elif version == "2c":
                attempts.append(SnmpAuthAttempt("v2c", CommunityData(self.community, mpModel=1)))
            elif version == "3":
                attempt = self.snmpv3_auth_attempt()
                if attempt:
                    attempts.append(attempt)
        return attempts

    def snmpv3_auth_attempt(self) -> SnmpAuthAttempt | None:
        username = str(
            setting_or_configured_env(
                self.settings,
                direct_keys=("snmpv3_user", "snmpv3_username", "snmpv3_security_name"),
                env_setting_keys=("snmpv3_user_env", "snmpv3_username_env", "snmpv3_security_name_env"),
                env_names=("SNMPV3_USER", "SNMPV3_USERNAME", "SNMPV3_SECURITY_NAME"),
                default="",
            )
            or ""
        ).strip()
        if not username:
            self.credential_errors.append("snmpv3: missing snmpv3_user/SNMPV3_USER")
            return None

        level = str(
            setting_or_configured_env(
                self.settings,
                direct_keys=("snmpv3_security_level", "snmp_security_level"),
                env_setting_keys=("snmpv3_security_level_env", "snmp_security_level_env"),
                env_names=("SNMPV3_SECURITY_LEVEL", "SNMP_SECURITY_LEVEL"),
                default="",
            )
            or ""
        ).strip().lower().replace("-", "")

        auth_key = secret_value(
            self.settings,
            ("snmpv3_auth_key", "snmpv3_authkey", "snmpv3_auth_password", "snmpv3_auth_passphrase"),
            ("snmpv3_auth_key_env", "snmpv3_authkey_env", "snmpv3_auth_password_env", "snmpv3_auth_passphrase_env"),
            ("SNMPV3_AUTH_KEY", "SNMPV3_AUTHKEY", "SNMPV3_AUTH_PASSWORD", "SNMPV3_AUTH_PASSPHRASE"),
        )
        priv_key = secret_value(
            self.settings,
            ("snmpv3_priv_key", "snmpv3_privkey", "snmpv3_priv_password", "snmpv3_priv_passphrase"),
            ("snmpv3_priv_key_env", "snmpv3_privkey_env", "snmpv3_priv_password_env", "snmpv3_priv_passphrase_env"),
            ("SNMPV3_PRIV_KEY", "SNMPV3_PRIVKEY", "SNMPV3_PRIV_PASSWORD", "SNMPV3_PRIV_PASSPHRASE"),
        )

        if not level:
            if auth_key and priv_key:
                level = "authpriv"
            elif auth_key:
                level = "authnopriv"
            else:
                level = "noauthnopriv"

        if level in {"noauth", "noauthnopriv", "none"}:
            return SnmpAuthAttempt(f"v3:{username}:noAuthNoPriv", UsmUserData(username))

        if not auth_key:
            self.credential_errors.append(f"snmpv3:{username}: missing auth key for {level}")
            return None

        auth_proto_name = setting_or_configured_env(
            self.settings,
            direct_keys=("snmpv3_auth_proto", "snmpv3_auth_protocol"),
            env_setting_keys=("snmpv3_auth_proto_env", "snmpv3_auth_protocol_env"),
            env_names=("SNMPV3_AUTH_PROTO", "SNMPV3_AUTH_PROTOCOL"),
            default="sha",
        )
        auth_proto = snmpv3_auth_protocol(auth_proto_name)

        if level in {"auth", "authnopriv"}:
            no_priv = _pysnmp_symbol("usmNoPrivProtocol", None)
            kwargs: dict[str, Any] = {
                "authProtocol": auth_proto,
            }
            if no_priv is not None:
                kwargs["privProtocol"] = no_priv
            return SnmpAuthAttempt(
                f"v3:{username}:authNoPriv:{auth_proto_name}",
                UsmUserData(username, authKey=auth_key, **kwargs),
            )

        if level in {"authpriv", "priv"}:
            if not priv_key and as_bool(self.settings.get("snmpv3_priv_key_default_to_auth_key"), True):
                priv_key = auth_key
            if not priv_key:
                self.credential_errors.append(f"snmpv3:{username}: missing priv key for authPriv")
                return None
            priv_proto_name = setting_or_configured_env(
                self.settings,
                direct_keys=("snmpv3_priv_proto", "snmpv3_priv_protocol"),
                env_setting_keys=("snmpv3_priv_proto_env", "snmpv3_priv_protocol_env"),
                env_names=("SNMPV3_PRIV_PROTO", "SNMPV3_PRIV_PROTOCOL"),
                default="aes128",
            )
            return SnmpAuthAttempt(
                f"v3:{username}:authPriv:{auth_proto_name}/{priv_proto_name}",
                UsmUserData(
                    username,
                    authKey=auth_key,
                    privKey=priv_key,
                    authProtocol=auth_proto,
                    privProtocol=snmpv3_priv_protocol(priv_proto_name),
                ),
            )

        self.credential_errors.append(f"snmpv3:{username}: unsupported security level {level!r}")
        return None

    def ordered_auth_attempts(self) -> list[SnmpAuthAttempt]:
        cache_key = (self.host, self.port)
        cached_label = SNMP_AUTH_CACHE.get(cache_key)
        if not cached_label:
            return list(self.auth_attempts)
        cached = [attempt for attempt in self.auth_attempts if attempt.label == cached_label]
        remaining = [attempt for attempt in self.auth_attempts if attempt.label != cached_label]
        return cached + remaining

    def remember_success(self, attempt: SnmpAuthAttempt) -> None:
        SNMP_AUTH_CACHE[(self.host, self.port)] = attempt.label

    async def target(self) -> UdpTransportTarget:
        return await UdpTransportTarget.create(
            (self.host, self.port), timeout=self.timeout, retries=self.retries
        )

    def context(self) -> ContextData:
        context_name = str(
            setting_or_configured_env(
                self.settings,
                direct_keys=("snmpv3_context_name", "snmp_context_name"),
                env_setting_keys=("snmpv3_context_name_env", "snmp_context_name_env"),
                env_names=("SNMPV3_CONTEXT_NAME", "SNMP_CONTEXT_NAME"),
                default="",
            )
            or ""
        )
        if context_name:
            return ContextData(contextName=context_name)
        return ContextData()

    @staticmethod
    def format_error_status(error_status: Any, error_index: Any, var_binds: Any) -> str:
        try:
            status_text = error_status.prettyPrint()
        except AttributeError:
            status_text = str(error_status)
        if not status_text or status_text == "0":
            status_text = str(error_status)
        return f"{status_text} at {error_index}"

    async def get_with_auth(self, attempt: SnmpAuthAttempt, oid: str) -> str | None:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            self.snmp_engine,
            attempt.auth_data,
            await self.target(),
            self.context(),
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
        )
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(self.format_error_status(error_status, error_index, var_binds))

        self.remember_success(attempt)
        for _name, value in var_binds:
            result = pretty(value)
            return None if has_no_such(result) else result
        return None

    async def get(self, oid: str) -> str | None:
        if not self.auth_attempts:
            detail = "; ".join(self.credential_errors) or "no SNMP credentials configured"
            raise RuntimeError(f"SNMP credential setup failed: {detail}")

        errors: list[str] = []
        for attempt in self.ordered_auth_attempts():
            try:
                return await self.get_with_auth(attempt, oid)
            except Exception as exc:
                errors.append(f"{attempt.label}: {exc}")
        if self.credential_errors:
            errors.extend(self.credential_errors)
        raise RuntimeError("; ".join(errors))

    async def walk_with_auth(self, attempt: SnmpAuthAttempt, oid: str, max_rows: int = 20000) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        objects = walk_cmd(
            self.snmp_engine,
            attempt.auth_data,
            await self.target(),
            self.context(),
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
            lexicographicMode=False,
            maxRows=max_rows,
        )
        async for error_indication, error_status, error_index, var_binds in objects:
            if error_indication:
                raise RuntimeError(str(error_indication))
            if error_status:
                raise RuntimeError(self.format_error_status(error_status, error_index, var_binds))
            for name, value in var_binds:
                value_text = pretty(value)
                if not has_no_such(value_text):
                    rows.append((pretty(name), value_text))

        self.remember_success(attempt)
        return rows

    async def walk(self, oid: str, max_rows: int = 20000) -> list[tuple[str, str]]:
        if not self.auth_attempts:
            detail = "; ".join(self.credential_errors) or "no SNMP credentials configured"
            raise RuntimeError(f"SNMP credential setup failed: {detail}")

        errors: list[str] = []
        for attempt in self.ordered_auth_attempts():
            try:
                return await self.walk_with_auth(attempt, oid, max_rows=max_rows)
            except Exception as exc:
                errors.append(f"{attempt.label}: {exc}")
        if self.credential_errors:
            errors.extend(self.credential_errors)
        raise RuntimeError("; ".join(errors))


@dataclass
class BasicInfo:
    device_ip: str
    platform: str
    model: str
    settings: Settings
    logger: logging.Logger
    localhostname: str = "None"
    interfacelist: InterfaceList = field(default_factory=list)
    projectname: str = "None"
    sn: list[str] = field(default_factory=list)
    devicelocation: str = "None"
    peer_as: dict[str, Any] = field(default_factory=dict)
    recprefix: list[Any] = field(default_factory=list)
    bgplocal_as: str = "None"
    bgpid: str = "None"
    batch: str = "999"

    def __post_init__(self) -> None:
        self.region = str(self.settings.get("region", ""))
        self.idc = str(self.settings.get("idc", ""))
        self.table_name = str(self.settings.get("db_table", "ipaddresslist"))

    def snmp_client(self) -> SnmpClient:
        return SnmpClient(self.device_ip, self.settings)

    def log_exception(self, message: str) -> None:
        self.logger.exception("%s :: %s", self.device_ip, message)

    async def safe_get(self, snmp: SnmpClient, oid: str, label: str) -> str | None:
        try:
            return await snmp.get(oid)
        except Exception:
            self.log_exception(f"SNMP GET failed for {label} ({oid})")
            return None

    async def safe_walk(self, snmp: SnmpClient, oid: str, label: str) -> list[tuple[str, str]]:
        try:
            return await snmp.walk(oid)
        except Exception:
            self.log_exception(f"SNMP WALK failed for {label} ({oid})")
            return []

    def collect_escape(self) -> None:
        self.localhostname = "Legacy Vendor"
        self.interfacelist = []
        self.projectname = "NA"
        self.sn = []
        self.devicelocation = "NA"
        self.save_to_db()

    def collect_set1(self) -> None:
        asyncio.run(self.collect_set1_snmp())
        if self.platform == "huawei":
            self.collect_huawei_cli_fallback()
        elif len(self.interfacelist) <= 2 and self.platform in {"arista", "nx-os"}:
            self.collect_nxos_arista_interfaces()
        self.save_to_db()

    def collect_set2(self) -> None:
        asyncio.run(self.collect_common_basic())
        if self.platform == "fortigate":
            self.collect_fortigate_cli_fallback()
        elif not self.interfacelist and self.platform == "palo alto":
            self.collect_palo_alto_interfaces()
        self.save_to_db()

    async def collect_set1_snmp(self) -> None:
        await self.collect_common_basic()
        await self.collect_bgp_basic()

    async def collect_common_basic(self) -> None:
        snmp = self.snmp_client()

        hostname = await self.safe_get(snmp, OID_SYS_NAME, "sysName")
        if hostname:
            self.localhostname = hostname
            try:
                self.projectname = hostname.split("-")[2]
            except IndexError:
                self.projectname = "name-format-mismatch"

        location = await self.safe_get(snmp, OID_SYS_LOCATION, "sysLocation")
        if location:
            self.devicelocation = location

        self.sn = []
        if self.platform == "arista":
            serial = await self.safe_get(snmp, OID_ARISTA_SERIAL, "arista serial")
            if serial:
                self.sn.append(serial)
        else:
            serial_rows = await self.safe_walk(snmp, OID_ENT_PHYSICAL_SERIAL, "serial table")
            for _oid, value in serial_rows:
                if value:
                    self.sn.append(value)
                    break

        await self.collect_interface_list(snmp)

    async def collect_interface_list(self, snmp: SnmpClient) -> None:
        self.interfacelist = []
        index_name: dict[str, str] = {}
        ip_index: dict[str, str] = {}
        ip_subnet: dict[str, str] = {}

        for oid, value in await self.safe_walk(snmp, OID_IF_NAME, "ifName"):
            index = last_index_from_oid(oid)
            if index:
                index_name[index] = value

        for oid, value in await self.safe_walk(snmp, OID_IP_AD_ENT_IF_INDEX, "ipAdEntIfIndex"):
            ip_addr = ipv4_index_after_base_oid(oid, OID_IP_AD_ENT_IF_INDEX)
            if ip_addr:
                ip_index[ip_addr] = value

        for oid, value in await self.safe_walk(snmp, OID_IP_AD_ENT_NETMASK, "ipAdEntNetMask"):
            ip_addr = ipv4_index_after_base_oid(oid, OID_IP_AD_ENT_NETMASK)
            if ip_addr:
                ip_subnet[ip_addr] = value

        if not index_name or not ip_index or not ip_subnet:
            return

        for ip_addr, index in ip_index.items():
            interface_name = index_name.get(str(index))
            mask = ip_subnet.get(ip_addr)
            if not interface_name or not mask:
                continue
            prefix_len = netmask_to_prefix_len(mask)
            if prefix_len is None:
                continue
            self.interfacelist.append({interface_name: f"{ip_addr}/{prefix_len}"})

    async def collect_bgp_basic(self) -> None:
        snmp = self.snmp_client()

        local_as = await self.safe_get(snmp, OID_BGP_LOCAL_AS, "bgpLocalAs")
        if local_as and not has_no_such(local_as):
            self.bgplocal_as = local_as

        bgp_id = await self.safe_get(snmp, OID_BGP_IDENTIFIER, "bgpIdentifier")
        if bgp_id and not has_no_such(bgp_id):
            self.bgpid = bgp_id

    def netmiko_commands(self, device: dict[str, Any], commands: list[str]) -> dict[str, str]:
        outputs: dict[str, str] = {}
        if not commands:
            return outputs

        read_timeout = to_int(self.settings.get("netmiko_read_timeout", 30), 30)
        last_error: Exception | None = None
        for attempt in range(1, 3):
            connection = None
            try:
                connection = ConnectHandler(**device)
                connection.find_prompt()
                for command in commands:
                    try:
                        outputs[command] = connection.send_command(command, read_timeout=read_timeout)
                    except TypeError:
                        # Compatibility fallback for older Netmiko versions.
                        outputs[command] = connection.send_command(command)
                    except Exception as exc:
                        self.logger.error(
                            "%s :: Netmiko command %r failed on attempt %s: %s",
                            self.device_ip,
                            command,
                            attempt,
                            exc,
                        )
                return outputs
            except Exception as exc:
                last_error = exc
                self.logger.error(
                    "%s :: Netmiko connection attempt %s failed for %s: %s",
                    self.device_ip,
                    attempt,
                    device.get("device_type", "unknown"),
                    exc,
                )
            finally:
                if connection is not None:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass
        if last_error:
            self.logger.error("%s :: Netmiko connection failed: %s", self.device_ip, last_error)
        return outputs

    def netmiko_command(self, device: dict[str, Any], command: str) -> str | None:
        return self.netmiko_commands(device, [command]).get(command)

    def fortigate_netmiko_device(self) -> dict[str, Any] | None:
        username = str(self.settings.get("fortigate_username", self.settings.get("netmiko_username", "net-bot")))
        password = secret_value(
            self.settings,
            direct_keys=("fortigate_password", "netmiko_password", "ssh_password"),
            env_setting_keys=("fortigate_password_env", "netmiko_password_env", "ssh_password_env"),
            env_names=("FORTIGATE_PASSWORD", "NETMIKO_PASSWORD", "SSH_PASSWORD"),
        )
        if not password:
            self.logger.error("%s :: Missing Fortigate/Netmiko password", self.device_ip)
            return None

        device: dict[str, Any] = {
            "device_type": str(self.settings.get("fortigate_netmiko_device_type", "fortinet")),
            "host": self.device_ip,
            "username": username,
            "password": password,
            "ssh_strict": False,
            "fast_cli": as_bool(self.settings.get("fortigate_fast_cli"), False),
        }
        port = self.settings.get("fortigate_ssh_port", self.settings.get("netmiko_ssh_port"))
        if port not in (None, ""):
            device["port"] = to_int(port, 22)
        return device

    def fortigate_expected_prefix_mismatch(self) -> bool:
        prefixes = setting_list(self.settings, "fortigate_interface_expected_ip_prefixes", [])
        if not prefixes:
            return False

        for item in self.interfacelist:
            if not isinstance(item, dict):
                continue
            for _interface_name, ip_cidr in item.items():
                ip_value, _prefix_len = parse_ip_cidr(str(ip_cidr))
                if not is_ipv4_text(ip_value):
                    continue
                if not any(ip_value.startswith(prefix) for prefix in prefixes):
                    return True
        return False

    def collect_fortigate_cli_fallback(self) -> None:
        if not as_bool(self.settings.get("fortigate_cli_fallback"), True):
            return

        prefer_cli_interfaces = as_bool(
            self.settings.get("fortigate_prefer_cli_interfaces", self.settings.get("fortigate_force_ssh_interfaces")),
            False,
        )
        interface_threshold = to_int(
            self.settings.get("fortigate_cli_interface_threshold", self.settings.get("fortigate_snmp_interface_threshold", 0)),
            0,
        )
        needs_interfaces = (
            prefer_cli_interfaces
            or len(self.interfacelist) <= interface_threshold
            or self.fortigate_expected_prefix_mismatch()
        )
        if not needs_interfaces:
            return

        device = self.fortigate_netmiko_device()
        if not device:
            return

        commands = setting_list(
            self.settings,
            "fortigate_interface_commands",
            ["show system interface", "get system interface"],
        )
        outputs = self.netmiko_commands(device, commands)
        for command in commands:
            parsed = self.parse_fortigate_interfaces(outputs.get(command, ""))
            if parsed:
                self.interfacelist = parsed
                self.logger.info("%s :: Fortigate interfaces collected by CLI command %r", self.device_ip, command)
                return

    def parse_fortigate_interfaces(self, output: str) -> InterfaceList:
        interfaces: InterfaceList = []
        seen: set[tuple[str, str]] = set()
        current_interface: str | None = None

        edit_re = re.compile(r'^\s*edit\s+"?(?P<ifname>[^"\s]+)"?', re.IGNORECASE)
        bracket_re = re.compile(r'^\s*==\s*\[\s*(?P<ifname>[^\]]+)\s*\]')
        name_re = re.compile(r'\bname:\s*(?P<ifname>\S+)')
        set_ip_re = re.compile(
            r'^\s*set\s+ip\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
            r'(?P<mask>(?:\d{1,3}\.){3}\d{1,3})\b',
            re.IGNORECASE,
        )
        inline_ip_re = re.compile(
            r'\bip:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
            r'(?P<mask>(?:\d{1,3}\.){3}\d{1,3})\b',
            re.IGNORECASE,
        )
        cidr_re = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})/(?P<prefix>\d{1,2})\b')

        def add_interface(interface_name: str | None, ip_value: str, mask_or_prefix: str) -> None:
            if not interface_name:
                return
            try:
                ipaddress.IPv4Address(ip_value)
            except ValueError:
                return
            if ip_value == "0.0.0.0":
                return

            if mask_or_prefix.isdigit():
                prefix_len = to_int(mask_or_prefix, -1)
            else:
                prefix_len = netmask_to_prefix_len(mask_or_prefix)
            if prefix_len is None or prefix_len < 0 or prefix_len > 32:
                return

            ip_cidr = f"{ip_value}/{prefix_len}"
            key = (interface_name, ip_cidr)
            if key in seen:
                return
            seen.add(key)
            interfaces.append({interface_name: ip_cidr})

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            edit_match = edit_re.match(line)
            if edit_match:
                current_interface = edit_match.group("ifname")
                continue

            bracket_match = bracket_re.match(line)
            if bracket_match:
                current_interface = bracket_match.group("ifname").strip()
                continue

            name_match = name_re.search(line)
            if name_match:
                current_interface = name_match.group("ifname").strip().strip('"')

            set_ip_match = set_ip_re.match(line)
            if set_ip_match:
                add_interface(current_interface, set_ip_match.group("ip"), set_ip_match.group("mask"))
                continue

            inline_ip_match = inline_ip_re.search(line)
            if inline_ip_match:
                add_interface(current_interface, inline_ip_match.group("ip"), inline_ip_match.group("mask"))
                continue

            if current_interface:
                cidr_match = cidr_re.search(line)
                if cidr_match:
                    add_interface(current_interface, cidr_match.group("ip"), cidr_match.group("prefix"))

        return interfaces

    def collect_palo_alto_interfaces(self) -> None:
        username = str(self.settings.get("pa_username", "sgnoc"))
        password = secret_value(
            self.settings,
            direct_keys=("pa_password", "paloalto_password"),
            env_setting_keys=("pa_password_env", "paloalto_password_env"),
            env_names=("PALOALTO_PASSWORD", "PA_PASSWORD"),
        )
        if not password:
            self.logger.error("%s :: Missing Palo Alto password", self.device_ip)
            return

        device = {
            "device_type": "paloalto_panos",
            "host": self.device_ip,
            "username": username,
            "password": password,
        }
        output = self.netmiko_command(device, "show interface all")
        if not output:
            return

        subnet_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
        interfaces: InterfaceList = []
        for line in output.splitlines():
            if subnet_regex.search(line) is None:
                continue
            fields = line.split()
            if len(fields) >= 6:
                interfaces.append({str(fields[0]): str(fields[-1])})
        self.interfacelist = interfaces

    def parse_nxos_ip_interface_detail(self, output: str) -> InterfaceList:
        """Parse NX-OS `show ip interface vrf all` output into iface -> host/prefix.

        `show ip interface brief vrf all` prints only the host IP address. The
        detailed command prints both `IP address` and `IP subnet`, which lets us
        derive the real prefix length without guessing /32.
        """
        interfaces: InterfaceList = []
        seen: set[tuple[str, str]] = set()
        current_interface: str | None = None

        interface_re = re.compile(r"^(?P<ifname>[A-Za-z][A-Za-z0-9_.:/-]+),\s+Interface status:")
        ip_subnet_re = re.compile(
            r"\bIP address:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s*,\s*"
            r"IP subnet:\s*(?P<subnet>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})\b",
            re.IGNORECASE,
        )
        ip_prefix_re = re.compile(
            r"\bIP address:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})\b",
            re.IGNORECASE,
        )

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            interface_match = interface_re.match(line)
            if interface_match:
                current_interface = interface_match.group("ifname")
                continue

            if not current_interface:
                continue

            prefix_match = ip_prefix_re.search(line)
            if prefix_match:
                value = prefix_match.group("ip")
                key = (current_interface, value)
                if key not in seen:
                    seen.add(key)
                    interfaces.append({current_interface: value})
                continue

            subnet_match = ip_subnet_re.search(line)
            if not subnet_match:
                continue

            ip_value = subnet_match.group("ip")
            subnet_value = subnet_match.group("subnet")
            try:
                prefix_length = ipaddress.ip_network(subnet_value, strict=False).prefixlen
            except ValueError:
                self.logger.warning(
                    "%s :: unable to parse NX-OS subnet %r for %s",
                    self.device_ip,
                    subnet_value,
                    current_interface,
                )
                continue

            value = f"{ip_value}/{prefix_length}"
            key = (current_interface, value)
            if key not in seen:
                seen.add(key)
                interfaces.append({current_interface: value})

        return interfaces

    def parse_nxos_running_config_interfaces(self, output: str) -> InterfaceList:
        """Fallback parser for `show running-config interface` on NX-OS."""
        interfaces: InterfaceList = []
        seen: set[tuple[str, str]] = set()
        current_interface: str | None = None
        interface_re = re.compile(r"^interface\s+(?P<ifname>\S+)", re.IGNORECASE)
        slash_re = re.compile(
            r"^ip address\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})/(?P<prefix>\d{1,2})\b",
            re.IGNORECASE,
        )
        mask_re = re.compile(
            r"^ip address\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
            r"(?P<mask>(?:\d{1,3}\.){3}\d{1,3})\b",
            re.IGNORECASE,
        )

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("!"):
                continue

            interface_match = interface_re.match(line)
            if interface_match:
                current_interface = interface_match.group("ifname")
                continue

            if not current_interface:
                continue

            value: str | None = None
            slash_match = slash_re.match(line)
            if slash_match:
                value = f"{slash_match.group('ip')}/{slash_match.group('prefix')}"
            else:
                mask_match = mask_re.match(line)
                if mask_match:
                    try:
                        prefix_length = ipaddress.ip_network(mask_match.group("mask"), strict=False).prefixlen
                    except ValueError:
                        prefix_length = None
                    if prefix_length is not None:
                        value = f"{mask_match.group('ip')}/{prefix_length}"

            if value:
                key = (current_interface, value)
                if key not in seen:
                    seen.add(key)
                    interfaces.append({current_interface: value})

        return interfaces

    def parse_brief_interfaces_with_prefix(self, output: str) -> InterfaceList:
        """Parse brief output that already contains host/prefix values."""
        subnet_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
        interfaces: InterfaceList = []
        seen: set[tuple[str, str]] = set()
        for line in output.splitlines():
            if subnet_regex.search(line) is None:
                continue
            fields = line.split()
            if len(fields) < 2:
                continue
            interface_name = str(fields[0])
            interface_ip = str(fields[1])
            key = (interface_name, interface_ip)
            if key not in seen:
                seen.add(key)
                interfaces.append({interface_name: interface_ip})
        return interfaces

    def collect_nxos_arista_interfaces(self) -> None:
        platform_map = {"nx-os": "cisco_nxos", "arista": "arista_eos"}
        command_map = {"nx-os": "show ip interface brief vrf all", "arista": "show ip interface brief"}
        username = str(self.settings.get("netmiko_username", "net-bot"))
        password = secret_value(
            self.settings,
            direct_keys=("netmiko_password", "ssh_password"),
            env_setting_keys=("netmiko_password_env", "ssh_password_env"),
            env_names=("NETMIKO_PASSWORD", "SSH_PASSWORD"),
        )
        if not password:
            self.logger.error("%s :: Missing Netmiko password", self.device_ip)
            return

        device = {
            "device_type": platform_map[self.platform],
            "host": self.device_ip,
            "username": username,
            "password": password,
            "ssh_strict": False,
        }

        if self.platform == "nx-os":
            detail_command = str(self.settings.get("nxos_interface_detail_command", "show ip interface vrf all"))
            config_command = str(self.settings.get("nxos_interface_config_command", "show running-config interface"))
            commands = [detail_command, command_map[self.platform]]
            if as_bool(self.settings.get("nxos_running_config_prefix_fallback"), True):
                commands.append(config_command)

            outputs = self.netmiko_commands(device, commands)
            interfaces = self.parse_nxos_ip_interface_detail(outputs.get(detail_command, ""))

            if not interfaces and as_bool(self.settings.get("nxos_running_config_prefix_fallback"), True):
                interfaces = self.parse_nxos_running_config_interfaces(outputs.get(config_command, ""))

            if interfaces:
                self.interfacelist = interfaces
                return

            brief_output = outputs.get(command_map[self.platform], "")
            brief_interfaces = self.parse_brief_interfaces_with_prefix(brief_output)
            if brief_interfaces:
                self.interfacelist = brief_interfaces
                return

            if as_bool(self.settings.get("nxos_missing_prefix_as_32"), False):
                ipv4_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
                fallback_interfaces: InterfaceList = []
                for line in brief_output.splitlines():
                    if ipv4_regex.search(line) is None:
                        continue
                    fields = line.split()
                    if len(fields) < 3:
                        continue
                    fallback_interfaces.append({str(fields[0]): f"{fields[1]}/32"})
                if fallback_interfaces:
                    self.logger.warning(
                        "%s :: NX-OS prefix could not be collected; using configured /32 fallback",
                        self.device_ip,
                    )
                    self.interfacelist = fallback_interfaces
                return

            self.logger.warning(
                "%s :: NX-OS CLI fallback found no prefix information; not writing guessed /32 values",
                self.device_ip,
            )
            return

        output = self.netmiko_command(device, command_map[self.platform])
        if not output:
            return
        interfaces = self.parse_brief_interfaces_with_prefix(output)
        if interfaces:
            self.interfacelist = interfaces

    def huawei_netmiko_device(self) -> dict[str, Any] | None:
        username = str(self.settings.get("huawei_username", self.settings.get("netmiko_username", "net-bot")))
        password = secret_value(
            self.settings,
            direct_keys=("huawei_password", "netmiko_password", "ssh_password"),
            env_setting_keys=("huawei_password_env", "netmiko_password_env", "ssh_password_env"),
            env_names=("HUAWEI_PASSWORD", "NETMIKO_PASSWORD", "SSH_PASSWORD"),
        )
        if not password:
            self.logger.error("%s :: Missing Huawei/Netmiko password", self.device_ip)
            return None

        device: dict[str, Any] = {
            "device_type": str(self.settings.get("huawei_netmiko_device_type", self.settings.get("huawei_device_type", "huawei"))),
            "host": self.device_ip,
            "username": username,
            "password": password,
            "ssh_strict": False,
            "fast_cli": as_bool(self.settings.get("huawei_fast_cli"), False),
        }
        port = self.settings.get("huawei_ssh_port", self.settings.get("netmiko_ssh_port"))
        if port not in (None, ""):
            device["port"] = to_int(port, 22)
        return device

    def collect_huawei_cli_fallback(self) -> None:
        if not as_bool(self.settings.get("huawei_cli_fallback"), True):
            return

        prefer_cli_interfaces = as_bool(
            self.settings.get("huawei_prefer_cli_interfaces", self.settings.get("huawei_force_ssh_interfaces")),
            False,
        )
        interface_threshold = to_int(
            self.settings.get("huawei_cli_interface_threshold", self.settings.get("huawei_snmp_interface_threshold", 2)),
            2,
        )
        needs_interfaces = prefer_cli_interfaces or len(self.interfacelist) <= interface_threshold
        needs_bgp = self.bgplocal_as == "None" or self.bgpid == "None"
        needs_serial = not self.sn
        collect_cli_model = as_bool(self.settings.get("huawei_collect_display_version_model"), True)
        prefer_cli_model = as_bool(self.settings.get("huawei_prefer_cli_model"), True)
        needs_model = collect_cli_model and (prefer_cli_model or self.model.strip().lower().startswith("0x"))

        if not any((needs_interfaces, needs_bgp, needs_serial, needs_model)):
            return

        device = self.huawei_netmiko_device()
        if not device:
            return

        interface_commands = setting_list(
            self.settings,
            "huawei_interface_commands",
            ["display ip interface brief"],
        ) if needs_interfaces else []
        bgp_commands = setting_list(
            self.settings,
            "huawei_bgp_commands",
            ["display bgp peer"],
        ) if needs_bgp else []
        serial_commands = setting_list(
            self.settings,
            "huawei_serial_commands",
            ["display esn", "display device manufacture-info", "display elabel"],
        ) if needs_serial else []
        model_commands = setting_list(
            self.settings,
            "huawei_model_commands",
            ["display version"],
        ) if needs_model else []

        commands = list(dict.fromkeys(model_commands + interface_commands + bgp_commands + serial_commands))
        outputs = self.netmiko_commands(device, commands)

        if needs_interfaces:
            for command in interface_commands:
                parsed = self.parse_huawei_interfaces(outputs.get(command, ""))
                if parsed:
                    self.interfacelist = parsed
                    break

        if needs_bgp:
            for command in bgp_commands:
                self.apply_huawei_bgp(outputs.get(command, ""))
                if self.bgplocal_as != "None" and self.bgpid != "None":
                    break

        if needs_serial:
            for command in serial_commands:
                serial = self.parse_huawei_serial(outputs.get(command, ""))
                if serial:
                    self.sn = [serial]
                    break

        if needs_model:
            for command in model_commands:
                model_text = display_text(outputs.get(command, ""))
                if model_text:
                    self.model = model_text
                    break

    def parse_huawei_interfaces(self, output: str) -> InterfaceList:
        interfaces: InterfaceList = []
        seen: set[tuple[str, str]] = set()
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lower_line = line.lower()
            if (
                lower_line.startswith("interface")
                or lower_line.startswith("*")
                or "ip address/mask" in lower_line
                or "physical" in lower_line and "protocol" in lower_line
                or set(line) <= {"-", " "}
            ):
                continue

            fields = line.split()
            if len(fields) < 2:
                continue

            interface_name = fields[0].lstrip("*")
            ip_cidr = None
            for field_value in fields[1:]:
                ip_cidr = normalize_ip_cidr_token(field_value)
                if ip_cidr:
                    break

            if not ip_cidr:
                continue

            key = (interface_name, ip_cidr)
            if key in seen:
                continue
            seen.add(key)
            interfaces.append({interface_name: ip_cidr})
        return interfaces

    def apply_huawei_bgp(self, output: str) -> None:
        if not output:
            return

        local_as_patterns = (
            r"\bLocal\s+AS\s+number\s*(?:is|:|：)\s*(\d+)",
            r"\blocal\s+as\s*(?:is|:|：)\s*(\d+)",
        )
        router_id_patterns = (
            r"\bBGP\s+(?:local\s+)?router\s+ID\s*(?:is|:|：)\s*((?:\d{1,3}\.){3}\d{1,3})",
            r"\bRouter\s+ID\s*(?:is|:|：)\s*((?:\d{1,3}\.){3}\d{1,3})",
        )

        if self.bgplocal_as == "None":
            for pattern in local_as_patterns:
                match = re.search(pattern, output, flags=re.IGNORECASE)
                if match:
                    self.bgplocal_as = match.group(1)
                    break

        if self.bgpid == "None":
            for pattern in router_id_patterns:
                match = re.search(pattern, output, flags=re.IGNORECASE)
                if match and is_ipv4_text(match.group(1)):
                    self.bgpid = match.group(1)
                    break

        peer_as: dict[str, str] = {}
        peer_prefix: list[dict[str, str]] = []
        for raw_line in output.splitlines():
            fields = raw_line.split()
            if len(fields) < 3 or not is_ipv4_text(fields[0]):
                continue
            peer_ip = fields[0]
            # Typical Huawei summary line:
            # Peer V AS MsgRcvd MsgSent OutQ Up/Down State PrefRcv
            if fields[2].isdigit():
                peer_as[peer_ip] = fields[2]
            if len(fields) >= 9 and fields[-1].isdigit():
                peer_prefix.append({peer_ip: fields[-1]})

        if peer_as and not self.peer_as:
            self.peer_as = peer_as
        if peer_prefix and not self.recprefix:
            self.recprefix = peer_prefix

    def parse_huawei_serial(self, output: str) -> str | None:
        if not output:
            return None

        key_value_patterns = (
            r"\bESN\b\s*(?:of\s+device\s*)?(?:is|:|=|：)\s*([A-Za-z0-9_.-]{8,80})",
            r"\bSerial\s*(?:Number|No\.?|Num)?\b\s*(?:is|:|=|：)\s*([A-Za-z0-9_.-]{8,80})",
            r"\bSN\b\s*(?:is|:|=|：)\s*([A-Za-z0-9_.-]{8,80})",
            r"\bBar\s*Code\b\s*(?:is|:|=|：)\s*([A-Za-z0-9_.-]{8,80})",
            r"\bBarCode\b\s*(?:is|:|=|：)\s*([A-Za-z0-9_.-]{8,80})",
        )
        for pattern in key_value_patterns:
            for match in re.finditer(pattern, output, flags=re.IGNORECASE):
                serial = probable_serial_token(match.group(1))
                if serial:
                    return serial

        for raw_line in output.splitlines():
            lower_line = raw_line.lower()
            if not any(keyword in lower_line for keyword in ("esn", "serial", "sn", "barcode", "bar code")):
                continue
            for token in reversed(raw_line.split()):
                serial = probable_serial_token(token)
                if serial:
                    return serial
        return None

    def mysql_config(self) -> dict[str, Any]:
        password = secret_value(
            self.settings,
            direct_keys=("sql_password", "mysql_password"),
            env_setting_keys=("sql_password_env", "mysql_password_env"),
            env_names=("NETBOT_SQL_PASSWORD", "MYSQL_PASSWORD"),
        )
        if not password:
            raise RuntimeError("Missing SQL password")

        return {
            "host": str(self.settings.get("cdb_ip", self.settings.get("sql_host", "127.0.0.1"))),
            "port": to_int(self.settings.get("sql_port", 3306), 3306),
            "user": str(self.settings["sql_username"]),
            "password": password,
            "database": str(self.settings["sql_database"]),
            "charset": "utf8mb4",
            "connection_timeout": to_int(self.settings.get("sql_connection_timeout", 10), 10),
        }

    def save_to_db(self) -> None:
        """Persist one device inventory row and its query-friendly interface rows.

        InnoDB can legitimately choose a transaction as a deadlock victim under
        concurrent writes.  Keep the write path retryable and serialize writes per
        management IP so duplicate device-list entries do not delete/insert the
        same interface rows at the same time.
        """
        max_retries = max(1, to_int(self.settings.get("db_deadlock_retries", 6), 6))
        base_sleep_setting = self.settings.get(
            "db_deadlock_retry_base_sleep",
            self.settings.get("db_deadlock_retry_base_seconds", self.settings.get("db_deadlock_base_sleep", 0.25)),
        )
        max_sleep_setting = self.settings.get(
            "db_deadlock_retry_max_sleep",
            self.settings.get("db_deadlock_retry_max_seconds", 5.0),
        )
        base_sleep = max(0.05, to_float(base_sleep_setting, 0.25))
        max_sleep = max(base_sleep, to_float(max_sleep_setting, 5.0))

        for attempt in range(1, max_retries + 1):
            try:
                self._save_to_db_once()
                return
            except mysql.connector.Error as exc:
                errno = getattr(exc, "errno", None)
                sqlstate = getattr(exc, "sqlstate", None)
                message = str(exc).lower()
                retryable = (
                    errno in MYSQL_RETRYABLE_ERRNOS
                    or sqlstate == "40001"
                    or "deadlock found" in message
                    or "lock wait timeout" in message
                )
                if retryable and attempt < max_retries:
                    sleep_seconds = min(max_sleep, base_sleep * (2 ** (attempt - 1)))
                    sleep_seconds += random.uniform(0, base_sleep)
                    self.logger.warning(
                        "%s :: retryable MySQL error errno=%s sqlstate=%s while saving DB "
                        "attempt=%s/%s; retrying after %.2fs",
                        self.device_ip,
                        errno,
                        getattr(exc, "sqlstate", None),
                        attempt,
                        max_retries,
                        sleep_seconds,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise

    def _save_to_db_once(self) -> None:
        upsert_sql = f"""
            INSERT INTO `{self.table_name}`
            (`ipaddr`, `localhostname`, `interfacelist`, `project`, `batch`, `region`, `idc`,
             `model`, `SN`, `platform`, `bgpid`, `bgplocalAS`, `peerAS`, `peerPrefix`, `Device_DC_Loc`)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              `id` = LAST_INSERT_ID(`id`),
              `localhostname` = VALUES(`localhostname`),
              `interfacelist` = VALUES(`interfacelist`),
              `project` = VALUES(`project`),
              `batch` = VALUES(`batch`),
              `region` = VALUES(`region`),
              `idc` = VALUES(`idc`),
              `model` = VALUES(`model`),
              `SN` = VALUES(`SN`),
              `platform` = VALUES(`platform`),
              `bgpid` = VALUES(`bgpid`),
              `bgplocalAS` = VALUES(`bgplocalAS`),
              `peerAS` = VALUES(`peerAS`),
              `peerPrefix` = VALUES(`peerPrefix`),
              `Device_DC_Loc` = VALUES(`Device_DC_Loc`),
              `scan_time` = CURRENT_TIMESTAMP
        """
        params = (
            self.device_ip,
            self.localhostname,
            json_text(self.interfacelist),
            self.projectname,
            self.batch,
            self.region,
            self.idc,
            self.model,
            json_text(self.sn),
            self.platform,
            self.bgpid,
            self.bgplocal_as,
            json_text(self.peer_as),
            json_text(self.recprefix),
            self.devicelocation,
        )

        connection = mysql.connector.connect(**self.mysql_config())
        connection.autocommit = True
        cursor = None
        device_lock_name: str | None = None
        device_lock_acquired = False
        transaction_started = False
        try:
            cursor = connection.cursor()
            self.configure_db_session(cursor)

            use_device_lock = self.settings.get("db_use_device_advisory_lock", self.settings.get("db_use_named_lock", True))
            if as_bool(use_device_lock, True):
                device_lock_name = self.db_device_lock_name()
                lock_timeout_setting = self.settings.get("db_device_lock_timeout", self.settings.get("db_named_lock_timeout", 30))
                lock_timeout = max(0, to_int(lock_timeout_setting, 30))
                cursor.execute("SELECT GET_LOCK(%s, %s)", (device_lock_name, lock_timeout))
                row = cursor.fetchone()
                device_lock_acquired = bool(row and row[0] == 1)
                if not device_lock_acquired:
                    raise RuntimeError(
                        f"Unable to acquire MySQL device lock {device_lock_name!r} for {self.device_ip}"
                    )

            connection.start_transaction()
            transaction_started = True
            cursor.execute(upsert_sql, params)
            inventory_id = int(cursor.lastrowid or 0)
            if not inventory_id:
                raise RuntimeError(f"Unable to determine inventory id for {self.device_ip}")

            self.clear_interface_rows(cursor, inventory_id)
            self.insert_interface_rows(cursor, inventory_id)

            if self.should_delete_stale_device_rows(cursor):
                self.delete_stale_device_rows(cursor, inventory_id)

            connection.commit()
            transaction_started = False
        except Exception:
            if transaction_started:
                try:
                    connection.rollback()
                except Exception:
                    pass
            raise
        finally:
            if cursor is not None and device_lock_acquired and device_lock_name:
                try:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (device_lock_name,))
                    cursor.fetchone()
                except Exception:
                    self.logger.warning("%s :: failed to release MySQL device lock", self.device_ip, exc_info=True)
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    pass
            connection.close()

    def configure_db_session(self, cursor: Any) -> None:
        if as_bool(self.settings.get("db_read_committed", True), True):
            cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")

        lock_wait_timeout = to_int(self.settings.get("db_innodb_lock_wait_timeout", 15), 15)
        if lock_wait_timeout > 0:
            cursor.execute(f"SET SESSION innodb_lock_wait_timeout = {lock_wait_timeout}")

    def db_device_lock_name(self) -> str:
        # MySQL user-level lock names are limited to 64 characters.  IPv6 maxes
        # out at 45 chars, so the configured prefix is trimmed to keep the name safe.
        prefix = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(self.settings.get("db_named_lock_prefix", "basic_scan")))
        prefix = (prefix or "basic_scan")[:16]
        return f"{prefix}:{self.device_ip}"[:64]

    def should_delete_stale_device_rows(self, cursor: Any) -> bool:
        if not as_bool(self.settings.get("db_keep_latest_per_device"), True):
            return False
        if as_bool(self.settings.get("db_always_delete_stale_device_rows"), False):
            return True
        if not as_bool(self.settings.get("db_skip_stale_cleanup_when_unique_ipaddr"), True):
            return True
        try:
            return not self.unique_ipaddr_key_exists(cursor)
        except mysql.connector.Error:
            self.logger.warning(
                "%s :: unable to check UNIQUE(ipaddr); running stale-row cleanup defensively",
                self.device_ip,
                exc_info=True,
            )
            return True

    def unique_ipaddr_key_exists(self, cursor: Any) -> bool:
        index_name = str(self.settings.get("db_unique_ipaddr_key_name", "uk_ipaddresslist_ipaddr"))
        cursor.execute(
            """
            SELECT COUNT(*)
              FROM INFORMATION_SCHEMA.STATISTICS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = %s
               AND INDEX_NAME = %s
               AND NON_UNIQUE = 0
               AND COLUMN_NAME = 'ipaddr'
            """,
            (self.table_name, index_name),
        )
        row = cursor.fetchone()
        return bool(row and int(row[0]) > 0)

    def clear_interface_rows(self, cursor: Any, inventory_id: int) -> None:
        child_table = str(self.settings.get("interface_table", "ipaddresslist_interfaces"))
        if as_bool(self.settings.get("db_clear_interfaces_by_device_ip"), True):
            delete_sql = f"DELETE FROM `{child_table}` WHERE `device_ip` = %s"
            cursor.execute(delete_sql, (self.device_ip,))
            return

        delete_sql = f"DELETE FROM `{child_table}` WHERE `inventory_id` = %s"
        cursor.execute(delete_sql, (inventory_id,))

    def delete_stale_device_rows(self, cursor: Any, keep_inventory_id: int) -> None:
        """Keep only the newest inventory row for this management IP.

        With UNIQUE(ipaddr), the upsert updates the existing row and this method
        is normally skipped.  This fallback is retained for databases that have
        not run the migration yet.
        """
        child_table = str(self.settings.get("interface_table", "ipaddresslist_interfaces"))
        delete_old_children_sql = f"""
            DELETE child FROM `{child_table}` AS child
            INNER JOIN `{self.table_name}` AS parent ON parent.`id` = child.`inventory_id`
            WHERE parent.`ipaddr` = %s AND parent.`id` <> %s
        """
        cursor.execute(delete_old_children_sql, (self.device_ip, keep_inventory_id))

        delete_old_parents_sql = f"""
            DELETE FROM `{self.table_name}`
            WHERE `ipaddr` = %s AND `id` <> %s
        """
        cursor.execute(delete_old_parents_sql, (self.device_ip, keep_inventory_id))

    def insert_interface_rows(self, cursor: Any, inventory_id: int) -> None:
        child_table = str(self.settings.get("interface_table", "ipaddresslist_interfaces"))
        rows: list[tuple[int, str, str, str, int | None, str]] = []
        seen: set[tuple[int, str, str]] = set()
        for item in self.interfacelist:
            if not isinstance(item, dict):
                continue
            for interface_name, ip_cidr in item.items():
                interface_name_text = str(interface_name)
                ip_cidr_text = str(ip_cidr)
                row_key = (inventory_id, interface_name_text, ip_cidr_text)
                if row_key in seen:
                    continue
                seen.add(row_key)
                interface_ip, prefix_len = parse_ip_cidr(ip_cidr_text)
                rows.append(
                    (
                        inventory_id,
                        self.device_ip,
                        interface_name_text,
                        interface_ip,
                        prefix_len,
                        ip_cidr_text,
                    )
                )

        if not rows:
            return

        # Deterministic order reduces the chance of two transactions taking
        # unique-index locks in different orders when a device is accidentally
        # scanned twice.
        rows.sort(key=lambda row: (row[1], row[2], row[5]))

        insert_sql = f"""
            INSERT IGNORE INTO `{child_table}`
            (`inventory_id`, `device_ip`, `interface_name`, `interface_ip`, `prefix_len`, `ip_cidr`)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        batch_size_setting = self.settings.get(
            "db_interface_insert_batch_size",
            self.settings.get("db_interface_insert_chunk_size", 200),
        )
        batch_size = max(1, to_int(batch_size_setting, 200))
        for start in range(0, len(rows), batch_size):
            cursor.executemany(insert_sql, rows[start:start + batch_size])


async def get_sys_descr(device_ip: str, settings: Settings) -> str | None:
    snmp = SnmpClient(device_ip, settings)
    return await snmp.get(OID_SYS_DESCR)


async def get_sys_object_id(device_ip: str, settings: Settings) -> str | None:
    snmp = SnmpClient(device_ip, settings)
    return await snmp.get(OID_SYS_OBJECT_ID)


def detect_huawei_by_cli_probe(device_ip: str, sys_descr: str, settings: Settings, logger: logging.Logger) -> bool:
    """Last-resort probe for devices whose SNMP sysDescr does not identify the vendor."""
    if not as_bool(settings.get("huawei_unknown_cli_probe"), True):
        return False

    probe = BasicInfo(device_ip, "huawei", sys_descr or "unknown", settings, logger)
    base_device = probe.huawei_netmiko_device()
    if not base_device:
        return False

    commands = setting_list(settings, "huawei_probe_commands", ["display version"])
    configured_type = str(base_device.get("device_type", "huawei"))
    device_types = setting_list(
        settings,
        "huawei_probe_device_types",
        [configured_type, "huawei_vrp", "huawei_vrpv8"],
    )
    device_types = list(dict.fromkeys(device_types))

    for device_type in device_types:
        device = dict(base_device)
        device["device_type"] = device_type
        outputs = probe.netmiko_commands(device, commands)
        output_text = normalized_text("\n".join(outputs.values()))
        if output_text and any(alias_in_text(alias, output_text) for alias in HUAWEI_DETECTION_ALIASES):
            logger.info("%s :: detected Huawei by CLI probe with Netmiko device_type=%s", device_ip, device_type)
            return True

    return False


def start_from_sysname(device_ip: str, settings: Settings, logger: logging.Logger) -> dict[str, str]:
    try:
        sys_descr = asyncio.run(get_sys_descr(device_ip, settings))
        if not sys_descr:
            logger.error("%s :: the device cannot be accessed by SNMP in BASIC collection", device_ip)
            return {"device": device_ip, "status": "snmp_failed"}

        try:
            sys_object_id = asyncio.run(get_sys_object_id(device_ip, settings))
        except Exception:
            sys_object_id = None
            logger.exception("%s :: SNMP GET failed for sysObjectID (%s)", device_ip, OID_SYS_OBJECT_ID)

        sys_descr_text = display_text(sys_descr)
        sys_descr_norm = normalized_text(sys_descr_text)
        model_text = sys_descr_text or compact_display_text(sys_descr)
        platform = platform_override(device_ip, settings) or detect_platform(sys_descr_text, sys_object_id, settings)
        if not platform and detect_huawei_by_cli_probe(device_ip, sys_descr_text, settings, logger):
            platform = "huawei"
            model_text = f"{model_text}\n[detected-huawei-by-cli]" if model_text else "detected-huawei-by-cli"

        if not platform:
            logger.error(
                "%s :: BASIC+unknown-device; add platform_overrides if needed, for example "
                "\"platform_overrides\": {\"%s\": \"huawei\"}\nsysDescr=%s\nsysObjectID=%s",
                device_ip,
                device_ip,
                sys_descr_text or sys_descr_norm,
                sys_object_id or "None",
            )
            return {"device": device_ip, "status": "unknown_device"}

        device = BasicInfo(device_ip, platform, model_text, settings, logger)
        if platform in OS_SET1:
            device.collect_set1()
        elif platform in OS_SET2:
            device.collect_set2()
        elif platform in OS_ESCAPE:
            device.collect_escape()
        else:
            logger.error("%s :: BASIC+unknown-device\n%s", device_ip, sys_descr_text or sys_descr_norm)
            return {"device": device_ip, "status": "unknown_device"}

        return {"device": device_ip, "status": "ok", "platform": platform}
    except Exception:
        logger.exception("%s :: unhandled collection error", device_ip)
        return {"device": device_ip, "status": "error"}


def send_error_email(logcontent: str, subject: str, recipients_list: list[str], settings: Settings) -> None:
    if not recipients_list:
        return

    sender_name = str(settings.get("sender_name", "seainfra_notifications@sea.com"))
    smtp_server = str(settings.get("smtp_server", "mail.insea.io"))
    smtp_port = to_int(settings.get("smtp_port", 587), 587)
    smtp_tls = as_bool(settings.get("smtp_tls"), False)

    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = sender_name
    msg["To"] = ", ".join(recipients_list)

    msg_alternative = MIMEMultipart("alternative")
    msg.attach(msg_alternative)
    msg_alternative.attach(MIMEText(logcontent, "html", "utf-8"))

    session = None
    try:
        session = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
        if smtp_tls:
            session.ehlo()
            session.starttls()
            session.ehlo()
        session.sendmail(sender_name, recipients_list, msg.as_string())
        print("error email sent")
    finally:
        if session:
            session.quit()


def load_settings(path: Path) -> Settings:
    with path.open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def load_devices(path: Path) -> list[str]:
    devices: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as file_obj:
        for line in file_obj:
            device_ip = line.strip()
            if not device_ip or device_ip.startswith("#") or device_ip in seen:
                continue
            seen.add(device_ip)
            devices.append(device_ip)
    return devices


def default_workers(settings: Settings) -> int:
    region = str(settings.get("region", ""))
    if any(code in region for code in ("US", "BR", "AR", "CL")):
        return 4
    return 16


def setup_logger(run_dir: Path, timeformat: str) -> tuple[logging.Logger, Path]:
    run_dir.mkdir(parents=True, exist_ok=True)
    error_file = run_dir / f"MAINErr_{timeformat}"

    logger = logging.getLogger("basic_scan")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    error_handler = logging.FileHandler(error_file, mode="a", encoding="utf-8")
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger, error_file


def html_from_log(log_path: Path) -> str:
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    body = "".join(f"<br>{line}<br>" for line in lines)
    return f"</pre>{body}<pre>"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Basic network inventory scanner for Python 3.12")
    parser.add_argument(
        "--devices",
        default="/home/ops/net-bot-sa/idcdevicelist",
        help="Path to the device IP list file",
    )
    parser.add_argument(
        "--settings",
        default="/home/ops/net-bot-sa/Settings.json",
        help="Path to Settings.json",
    )
    parser.add_argument(
        "--log-dir",
        default="/tmp/netdevback/basic",
        help="Base directory for runtime logs",
    )
    parser.add_argument("--workers", type=int, default=None, help="Override worker count")
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="Do not send an error email even if MAINErr has content",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timeformat = time.strftime("%Y-%m-%d-%H", time.localtime())
    run_dir = Path(args.log_dir) / timeformat
    logger, error_file = setup_logger(run_dir, timeformat)
    diffdevice_file = run_dir / f"diffdevice_{timeformat}"
    diffdevice_file.touch(exist_ok=True)

    settings: Settings = {}
    try:
        settings = load_settings(Path(args.settings))
        devices = load_devices(Path(args.devices))
        workers = args.workers or default_workers(settings)

        logger.info("starting scan: devices=%s workers=%s", len(devices), workers)
        results: list[dict[str, str]] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(start_from_sysname, device_ip, settings, logger): device_ip
                for device_ip in devices
            }
            for future in as_completed(future_map):
                result = future.result()
                results.append(result)
                if result.get("status") == "ok":
                    logger.info("%s :: collection ok (%s)", result.get("device"), result.get("platform"))
                else:
                    logger.error("%s :: collection status=%s", result.get("device"), result.get("status"))

        ok_count = sum(1 for item in results if item.get("status") == "ok")
        logger.info("scan finished: ok=%s failed=%s", ok_count, len(results) - ok_count)

        if not args.no_email and error_file.exists() and error_file.stat().st_size > 0:
            recipients_list = [item.strip() for item in str(settings.get("holders", "")).split(",") if item.strip()]
            email_sub = str(settings.get("subject", f"basic scan errors {timeformat}"))
            send_error_email(html_from_log(error_file), email_sub, recipients_list, settings)
        return 0

    except Exception:
        logger.error("fatal error:\n%s", traceback.format_exc())
        if not args.no_email and error_file.exists() and error_file.stat().st_size > 0 and settings:
            recipients_list = [item.strip() for item in str(settings.get("holders", "")).split(",") if item.strip()]
            email_sub = str(settings.get("subject", f"basic scan fatal error {timeformat}"))
            try:
                send_error_email(html_from_log(error_file), email_sub, recipients_list, settings)
            except Exception:
                logger.error("failed to send fatal error email:\n%s", traceback.format_exc())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

