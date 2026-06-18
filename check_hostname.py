#!/usr/bin/env python3
"""
check_hostname.py

Search network inventory data in MySQL.

Default behavior:
  * If the input is a normal keyword, search ipaddresslist.localhostname and
    return hostname + ipaddr.
  * If the input is an IP address or CIDR, search device interface data and
    return ipaddr + localhostname + interface + interface_ip.

Examples:
  python3.12 check_hostname.py ce6863
  python3.12 check_hostname.py 10.163.130.31
  python3.12 check_hostname.py 10.163.130.30
  python3.12 check_hostname.py 10.163.130.31/31 --json
  python3.12 check_hostname.py core --settings /home/ops/net-bot-sa/Settings.json

Environment variables supported:
  NETBOT_SQL_HOST / MYSQL_HOST
  NETBOT_SQL_USER / MYSQL_USER
  NETBOT_SQL_PASSWORD / MYSQL_PASSWORD
  NETBOT_SQL_DATABASE / MYSQL_DATABASE
  NETBOT_SQL_PORT / MYSQL_PORT

The script also supports the existing Settings.json keys used by basic_scan.py:
  cdb_ip, sql_username, sql_password, sql_database, cdb_port/sql_port/mysql_port
"""

from __future__ import annotations

import argparse
import ast
import csv
import ipaddress
import json
import os
import re
import sys
if sys.argv and sys.argv[0] == "-":
    sys.argv[0] = "q"
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:  # Keep --help usable even before dependencies are installed.
    mysql = None  # type: ignore[assignment]

    class MySQLError(Exception):
        pass


def _settings_fallback_candidates() -> list[str]:
    """Return Settings.json candidates for user-local, shared, and legacy installs."""
    home = Path.home()
    return [
        os.environ.get("CHECK_HOSTNAME_SETTINGS", ""),
        "Settings.json",
        str(home / ".config" / "basic_scan" / "Settings.json"),
        str(home / ".local" / "etc" / "basic_scan" / "Settings.json"),
        str(home / ".local" / "share" / "basic_scan" / "Settings.json"),
        "/etc/basic_scan/Settings.json",
        "/usr/local/etc/basic_scan/Settings.json",
        "/usr/local/share/basic_scan/Settings.json",
        "/usr/local/lib/basic_scan/Settings.json",
        "/opt/basic_scan/Settings.json",
        "/home/ops/net-bot-sa/Settings.json",
        "/root/script/basic_scan/Settings.json",
    ]


def default_settings_path() -> str:
    """Return the first readable Settings.json path for short commands like `q R017`."""
    candidates = [path for path in _settings_fallback_candidates() if path]
    for path in candidates:
        expanded = Path(path).expanduser()
        if expanded.is_file() and os.access(expanded, os.R_OK):
            return str(expanded)
    return "Settings.json"


DEFAULT_INVENTORY_TABLE = "ipaddresslist"
DEFAULT_INTERFACE_TABLE = "ipaddresslist_interfaces"
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class DBConfig:
    host: str
    user: str
    password: str
    database: str
    port: int = 3306
    charset: str = "utf8mb4"


@dataclass(frozen=True)
class IPQuery:
    original: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    has_prefix: bool


@dataclass(frozen=True)
class ParsedInterface:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    normalized_cidr: str


def load_settings(path: str) -> dict[str, Any]:
    settings_path = Path(path)
    if not settings_path.exists():
        return {}
    try:
        with settings_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("settings file must contain a JSON object")
            return data
    except Exception as exc:
        print(f"Failed to read settings file {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)


def first_setting(settings: dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for key in keys:
        value = settings.get(key)
        if value not in (None, ""):
            return value
    return default


def first_env(env_names: Iterable[str]) -> str | None:
    for name in env_names:
        value = os.environ.get(name)
        if value not in (None, ""):
            return value
    return None


def setting_or_env_password(settings: dict[str, Any]) -> str:
    """Prefer env vars over plaintext Settings.json passwords."""
    configured_env_name = first_setting(
        settings,
        [
            "sql_password_env",
            "db_password_env",
            "mysql_password_env",
            "netbot_sql_password_env",
        ],
    )
    env_candidates: list[str] = []
    if configured_env_name:
        env_candidates.append(str(configured_env_name))
    env_candidates.extend(["NETBOT_SQL_PASSWORD", "SQL_PASSWORD", "MYSQL_PASSWORD"])

    password_from_env = first_env(env_candidates)
    if password_from_env is not None:
        return password_from_env

    return str(first_setting(settings, ["sql_password", "db_password", "mysql_password"], ""))


def build_db_config(args: argparse.Namespace, settings: dict[str, Any]) -> DBConfig:
    host = args.host or first_env(["NETBOT_SQL_HOST", "SQL_HOST", "MYSQL_HOST"]) or first_setting(
        settings, ["cdb_ip", "sql_host", "db_host", "mysql_host"], "127.0.0.1"
    )
    user = args.user or first_env(["NETBOT_SQL_USER", "SQL_USER", "MYSQL_USER"]) or first_setting(
        settings, ["sql_username", "sql_user", "db_user", "mysql_user"], "root"
    )
    database = args.database or first_env(
        ["NETBOT_SQL_DATABASE", "SQL_DATABASE", "MYSQL_DATABASE"]
    ) or first_setting(settings, ["sql_database", "db_name", "database", "mysql_database"], "")
    password = args.password or setting_or_env_password(settings)
    port_value = args.port or first_env(["NETBOT_SQL_PORT", "SQL_PORT", "MYSQL_PORT"]) or first_setting(
        settings, ["cdb_port", "sql_port", "db_port", "mysql_port"], 3306
    )

    try:
        port = int(port_value)
    except (TypeError, ValueError):
        print(f"Invalid MySQL port: {port_value}", file=sys.stderr)
        raise SystemExit(2)

    missing = []
    if not host:
        missing.append("host")
    if not user:
        missing.append("user")
    if not database:
        missing.append("database")
    if missing:
        db_keys = [
            "cdb_ip",
            "sql_host",
            "db_host",
            "mysql_host",
            "sql_username",
            "sql_user",
            "db_user",
            "mysql_user",
            "sql_database",
            "db_name",
            "database",
            "mysql_database",
            "cdb_port",
            "sql_port",
            "db_port",
            "mysql_port",
        ]
        present_keys = [key for key in db_keys if settings.get(key) not in (None, "")]
        print(
            "Missing DB config: " + ", ".join(missing) +
            ". Provide it in Settings.json, environment variables, or CLI options.\n"
            f"Settings path used: {args.settings}\n"
            "DB setting keys found: " + (", ".join(present_keys) if present_keys else "none"),
            file=sys.stderr,
        )
        raise SystemExit(2)

    return DBConfig(host=str(host), user=str(user), password=str(password), database=str(database), port=port)


def quote_identifier(identifier: str) -> str:
    """Safely quote a simple MySQL identifier such as a table name."""
    if not IDENTIFIER_RE.fullmatch(identifier):
        raise ValueError(f"Unsafe MySQL identifier: {identifier!r}")
    return f"`{identifier}`"


def escape_like_literal(value: str) -> str:
    """Escape MySQL LIKE wildcards so user input is treated as a normal keyword."""
    return value.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def connect_mysql(config: DBConfig):
    if mysql is None:  # type: ignore[name-defined]
        print(
            "Missing dependency: mysql-connector-python\n"
            "Install it with: python3.12 -m pip install mysql-connector-python",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return mysql.connector.connect(
        host=config.host,
        user=config.user,
        password=config.password,
        database=config.database,
        port=config.port,
        charset=config.charset,
        use_unicode=True,
        connection_timeout=10,
        autocommit=True,
    )


def table_exists(conn, table_name: str) -> bool:
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = %s
            """,
            (table_name,),
        )
        row = cursor.fetchone()
        return bool(row and int(row[0]) > 0)
    finally:
        cursor.close()


def parse_ip_query(value: str) -> IPQuery | None:
    text = value.strip()
    if not text:
        return None

    try:
        if "/" in text:
            iface = ipaddress.ip_interface(text)
            return IPQuery(original=text, ip=iface.ip, network=iface.network, has_prefix=True)
        ip = ipaddress.ip_address(text)
        prefix = 32 if ip.version == 4 else 128
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return IPQuery(original=text, ip=ip, network=network, has_prefix=False)
    except ValueError:
        return None


def _prefix_from_dotted_mask(mask: str) -> int | None:
    try:
        # ipaddress accepts a dotted IPv4 netmask in IPv4Network.
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def parse_interface_cidr(value: Any) -> ParsedInterface | None:
    """Parse interface values like 10.0.0.1/24 or 10.0.0.1/255.255.255.0."""
    if value is None:
        return None

    text = str(value).strip().strip("'\"")
    if not text or text.lower() in {"none", "null", "na", "n/a", "unassigned", "unnumbered"}:
        return None
    if "No Such" in text:
        return None

    # Some command outputs include extra text. Keep the first IP/CIDR-looking token.
    token_match = re.search(
        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/(\d{1,2}|[0-9]{1,3}(?:\.[0-9]{1,3}){3}))?",
        text,
    )
    token = token_match.group(0) if token_match else text

    try:
        if "/" not in token:
            ip = ipaddress.ip_address(token)
            prefix = 32 if ip.version == 4 else 128
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            return ParsedInterface(ip=ip, network=network, normalized_cidr=f"{ip}/{prefix}")

        addr_text, prefix_text = token.split("/", 1)
        prefix_text = prefix_text.strip()
        if "." in prefix_text:
            prefix_len = _prefix_from_dotted_mask(prefix_text)
            if prefix_len is None:
                return None
            token = f"{addr_text}/{prefix_len}"

        iface = ipaddress.ip_interface(token)
        return ParsedInterface(ip=iface.ip, network=iface.network, normalized_cidr=f"{iface.ip}/{iface.network.prefixlen}")
    except ValueError:
        return None


def get_interface_match_type(query: IPQuery, parsed: ParsedInterface, *, subnet_match: bool = True) -> str | None:
    if query.ip.version != parsed.ip.version:
        return None

    if query.has_prefix:
        if query.network == parsed.network:
            return "network_exact"
        if query.ip == parsed.ip:
            return "interface_ip"
        if subnet_match and query.network.overlaps(parsed.network):
            return "network_overlaps"
        return None

    if query.ip == parsed.ip:
        return "interface_ip"
    if subnet_match and query.ip in parsed.network:
        return "subnet_contains"
    return None


def decode_interfacelist_value(value: Any) -> list[Any]:
    """Decode JSON interfacelist or legacy Python repr like [{'Eth1': '10.0.0.1/24'}]."""
    if value is None:
        return []

    if isinstance(value, (list, tuple)):
        return list(value)

    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    text = text.strip()
    if not text or text.lower() in {"none", "null"}:
        return []

    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
            if isinstance(parsed, str):
                # Handles a double-encoded JSON string.
                try:
                    parsed = json.loads(parsed)
                except Exception:
                    pass
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, (list, tuple)):
                return list(parsed)
        except Exception:
            continue

    return []


def iter_interfaces_from_interfacelist(value: Any) -> Iterator[tuple[str, str]]:
    parsed = decode_interfacelist_value(value)
    for item in parsed:
        if isinstance(item, dict):
            for name, ip_cidr in item.items():
                yield str(name), str(ip_cidr)
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            yield str(item[0]), str(item[1])


def dedupe_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[dict[str, str]] = []
    for row in rows:
        key = (
            str(row.get("ipaddr", "")),
            str(row.get("localhostname", "")),
            str(row.get("interface", "")),
            str(row.get("interface_ip", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def search_hostname(
    conn,
    keyword: str,
    *,
    table_name: str,
    case_sensitive: bool = False,
    limit: int = 0,
) -> list[dict[str, str]]:
    pattern = f"%{escape_like_literal(keyword)}%"
    table = quote_identifier(table_name)

    if case_sensitive:
        condition = "BINARY localhostname LIKE BINARY %s ESCAPE '!'"
    else:
        condition = "LOWER(localhostname) LIKE LOWER(%s) ESCAPE '!'"

    sql = f"""
        SELECT DISTINCT
            localhostname AS hostname,
            ipaddr
        FROM {table}
        WHERE localhostname IS NOT NULL
          AND localhostname <> ''
          AND {condition}
        ORDER BY localhostname, ipaddr
    """
    params: list[Any] = [pattern]

    if limit > 0:
        sql += " LIMIT %s"
        params.append(limit)

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    finally:
        cursor.close()

    return [
        {
            "hostname": str(row.get("hostname") or ""),
            "ipaddr": str(row.get("ipaddr") or ""),
        }
        for row in rows
    ]


def search_interface_child_table(
    conn,
    query: IPQuery,
    *,
    table_name: str,
    interface_table_name: str,
    subnet_match: bool = True,
    limit: int = 0,
) -> list[dict[str, str]]:
    if not table_exists(conn, interface_table_name):
        return []

    parent_table = quote_identifier(table_name)
    interface_table = quote_identifier(interface_table_name)
    results: list[dict[str, str]] = []

    sql = f"""
        SELECT
            child.device_ip AS ipaddr,
            COALESCE(parent.localhostname, parent_by_ip.localhostname, '') AS localhostname,
            child.interface_name AS interface_name,
            child.ip_cidr AS ip_cidr
        FROM {interface_table} AS child
        LEFT JOIN {parent_table} AS parent
               ON parent.id = child.inventory_id
        LEFT JOIN {parent_table} AS parent_by_ip
               ON parent_by_ip.ipaddr = child.device_ip
        WHERE child.ip_cidr IS NOT NULL
          AND child.ip_cidr <> ''
        ORDER BY child.device_ip, child.interface_name, child.ip_cidr
    """

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql)
        for row in cursor:
            parsed = parse_interface_cidr(row.get("ip_cidr"))
            if not parsed:
                continue
            match_type = get_interface_match_type(query, parsed, subnet_match=subnet_match)
            if not match_type:
                continue
            results.append(
                {
                    "ipaddr": str(row.get("ipaddr") or ""),
                    "localhostname": str(row.get("localhostname") or ""),
                    "interface": str(row.get("interface_name") or ""),
                    "interface_ip": str(row.get("ip_cidr") or parsed.normalized_cidr),
                    "match_type": match_type,
                }
            )
            if limit > 0 and len(results) >= limit:
                break
    finally:
        cursor.close()

    return results


def search_interface_main_table(
    conn,
    query: IPQuery,
    *,
    table_name: str,
    subnet_match: bool = True,
    limit: int = 0,
) -> list[dict[str, str]]:
    table = quote_identifier(table_name)
    results: list[dict[str, str]] = []

    sql = f"""
        SELECT
            ipaddr,
            localhostname,
            interfacelist
        FROM {table}
        WHERE interfacelist IS NOT NULL
          AND CAST(interfacelist AS CHAR) <> ''
        ORDER BY ipaddr, localhostname
    """

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql)
        for row in cursor:
            for interface_name, ip_cidr in iter_interfaces_from_interfacelist(row.get("interfacelist")):
                parsed = parse_interface_cidr(ip_cidr)
                if not parsed:
                    continue
                match_type = get_interface_match_type(query, parsed, subnet_match=subnet_match)
                if not match_type:
                    continue
                results.append(
                    {
                        "ipaddr": str(row.get("ipaddr") or ""),
                        "localhostname": str(row.get("localhostname") or ""),
                        "interface": interface_name,
                        "interface_ip": str(ip_cidr),
                        "match_type": match_type,
                    }
                )
                if limit > 0 and len(results) >= limit:
                    return results
    finally:
        cursor.close()

    return results


def search_device_ip_exact(
    conn,
    query: IPQuery,
    *,
    table_name: str,
) -> list[dict[str, str]]:
    table = quote_identifier(table_name)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            f"""
            SELECT ipaddr, localhostname
            FROM {table}
            WHERE ipaddr = %s
            ORDER BY localhostname, ipaddr
            """,
            (str(query.ip),),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()

    return [
        {
            "ipaddr": str(row.get("ipaddr") or ""),
            "localhostname": str(row.get("localhostname") or ""),
            "interface": "<device-ipaddr>",
            "interface_ip": str(row.get("ipaddr") or ""),
            "match_type": "device_ip",
        }
        for row in rows
    ]


def search_by_ip(
    conn,
    query: IPQuery,
    *,
    table_name: str,
    interface_table_name: str,
    subnet_match: bool = True,
    scan_main_table: bool = True,
    include_device_ip: bool = True,
    limit: int = 0,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    results.extend(
        search_interface_child_table(
            conn,
            query,
            table_name=table_name,
            interface_table_name=interface_table_name,
            subnet_match=subnet_match,
            limit=limit,
        )
    )

    if scan_main_table and (limit <= 0 or len(results) < limit):
        remaining_limit = 0 if limit <= 0 else limit - len(results)
        results.extend(
            search_interface_main_table(
                conn,
                query,
                table_name=table_name,
                subnet_match=subnet_match,
                limit=remaining_limit,
            )
        )

    results = dedupe_rows(results)

    if include_device_ip and (limit <= 0 or len(results) < limit):
        # Useful when the input is a management IP that is not present in interfacelist.
        device_rows = search_device_ip_exact(conn, query, table_name=table_name)
        existing_device_ips = {row.get("ipaddr") for row in results}
        for row in device_rows:
            if row.get("ipaddr") not in existing_device_ips:
                results.append(row)

    exact_rank = {
        "interface_ip": 0,
        "network_exact": 1,
        "subnet_contains": 2,
        "network_overlaps": 3,
        "device_ip": 4,
    }
    results.sort(
        key=lambda row: (
            exact_rank.get(str(row.get("match_type")), 99),
            row.get("ipaddr", ""),
            row.get("interface", ""),
            row.get("interface_ip", ""),
        )
    )

    if limit > 0:
        results = results[:limit]
    return results


def print_table(rows: list[dict[str, str]], headers: list[str], empty_message: str) -> None:
    if not rows:
        print(empty_message)
        return

    widths = {
        header: max(len(header), *(len(str(row.get(header, ""))) for row in rows))
        for header in headers
    }
    line = "  ".join(header.ljust(widths[header]) for header in headers)
    sep = "  ".join("-" * widths[header] for header in headers)
    print(line)
    print(sep)
    for row in rows:
        print("  ".join(str(row.get(header, "")).ljust(widths[header]) for header in headers))


def print_csv(rows: list[dict[str, str]], headers: list[str]) -> None:
    writer = csv.DictWriter(sys.stdout, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Search inventory by localhostname keyword, or search interface ownership "
            "when the input is an IP address/CIDR."
        )
    )
    parser.add_argument(
        "keyword",
        nargs="?",
        help="Hostname keyword, IP address, or CIDR. If omitted, the script will prompt for it.",
    )
    parser.add_argument(
        "--settings",
        default=default_settings_path(),
        help="Path to Settings.json. Default lookup: CHECK_HOSTNAME_SETTINGS, ./Settings.json, ~/.config/basic_scan/Settings.json, /etc/basic_scan/Settings.json, /usr/local/etc/basic_scan/Settings.json, /usr/local/share/basic_scan/Settings.json, /opt/basic_scan/Settings.json, /home/ops/net-bot-sa/Settings.json, /root/script/basic_scan/Settings.json.",
    )
    parser.add_argument("--host", help="MySQL host. Overrides Settings.json/env.")
    parser.add_argument("--port", type=int, help="MySQL port. Overrides Settings.json/env.")
    parser.add_argument("--user", help="MySQL username. Overrides Settings.json/env.")
    parser.add_argument("--password", help="MySQL password. Prefer env vars for production.")
    parser.add_argument("--database", help="MySQL database. Overrides Settings.json/env.")
    parser.add_argument(
        "--table",
        default=None,
        help=f"Inventory table name. Default: Settings inventory_table/table_name or {DEFAULT_INVENTORY_TABLE}.",
    )
    parser.add_argument(
        "--interface-table",
        default=None,
        help=(
            "Interface child table name. Default: Settings interface_table or "
            f"{DEFAULT_INTERFACE_TABLE}. If it does not exist, the script falls back to parsing interfacelist."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "hostname", "ip"],
        default="auto",
        help="Search mode. auto detects IP/CIDR input automatically. Default: auto.",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Use case-sensitive keyword matching in hostname mode.",
    )
    parser.add_argument(
        "--exact-ip",
        action="store_true",
        help="Only match the exact interface IP. Do not match IPs contained in an interface subnet.",
    )
    parser.add_argument(
        "--no-main-table-scan",
        action="store_true",
        help="In IP mode, do not parse ipaddresslist.interfacelist; only use the interface child table.",
    )
    parser.add_argument(
        "--no-device-ip-match",
        action="store_true",
        help="In IP mode, do not return a row when the input matches ipaddresslist.ipaddr exactly.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of rows to return. 0 means no limit.",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Output JSON array.")
    output.add_argument("--csv", action="store_true", help="Output CSV.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    keyword = args.keyword
    if keyword is None:
        keyword = input("Input hostname keyword, IP address, or CIDR: ").strip()
    if not keyword:
        print("Keyword/IP cannot be empty.", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("--limit must be greater than or equal to 0.", file=sys.stderr)
        return 2

    settings = load_settings(args.settings)
    table_name = str(
        args.table
        or first_setting(settings, ["inventory_table", "table_name", "db_table"], DEFAULT_INVENTORY_TABLE)
    )
    interface_table_name = str(
        args.interface_table
        or first_setting(settings, ["interface_table", "interfaces_table"], DEFAULT_INTERFACE_TABLE)
    )

    try:
        quote_identifier(table_name)
        quote_identifier(interface_table_name)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    ip_query = parse_ip_query(keyword)
    if args.mode == "ip" and ip_query is None:
        print(f"Input is not a valid IP address or CIDR: {keyword}", file=sys.stderr)
        return 2

    effective_mode = "ip" if (args.mode == "ip" or (args.mode == "auto" and ip_query is not None)) else "hostname"

    db_config = build_db_config(args, settings)
    try:
        conn = connect_mysql(db_config)
    except MySQLError as exc:
        print(f"Failed to connect MySQL: {exc}", file=sys.stderr)
        return 1

    try:
        if effective_mode == "ip":
            assert ip_query is not None
            rows = search_by_ip(
                conn,
                ip_query,
                table_name=table_name,
                interface_table_name=interface_table_name,
                subnet_match=not args.exact_ip,
                scan_main_table=not args.no_main_table_scan,
                include_device_ip=not args.no_device_ip_match,
                limit=args.limit,
            )
            headers = ["ipaddr", "localhostname", "interface", "interface_ip", "match_type"]
            empty_message = "No matched interface/device IP found."
        else:
            rows = search_hostname(
                conn,
                keyword,
                table_name=table_name,
                case_sensitive=args.case_sensitive,
                limit=args.limit,
            )
            headers = ["hostname", "ipaddr"]
            empty_message = "No matched hostname found."
    except MySQLError as exc:
        print(f"Query failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    elif args.csv:
        print_csv(rows, headers)
    else:
        print_table(rows, headers, empty_message)
        print(f"\nMatched rows: {len(rows)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
