#!/usr/bin/env python3
"""
NetSage AI - Deterministic Rule Checker
Reads cases.csv and performs evidence-based checks for six basic
network configuration problems.

Important:
- This script does NOT use expected_fault to decide the answer.
- Missing evidence is reported as NOT_CHECKED, not FAIL.
- The checker is deterministic; AI diagnosis is a separate step.
- Standard Python library only.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Host:
    device: str
    ip: str
    mask: str
    gateway: Optional[str] = None


@dataclass
class Interface:
    device: str
    name: str
    ip: Optional[str] = None
    mask: Optional[str] = None
    status: str = "unknown"
    protocol: str = "unknown"


@dataclass
class SwitchPort:
    device: str
    port: str
    vlan: Optional[int] = None
    status: str = "unknown"


@dataclass
class Evidence:
    hosts: List[Host] = field(default_factory=list)
    interfaces: List[Interface] = field(default_factory=list)
    vlan_ids: Dict[str, set] = field(default_factory=dict)
    switchports: List[SwitchPort] = field(default_factory=list)
    route_text_present: bool = False
    raw_text: str = ""


@dataclass
class Result:
    rule: str
    status: str                 # PASS / FAIL / NOT_CHECKED / ERROR
    details: str


# ============================================================
# PARSING HELPERS
# ============================================================

IP_MASK_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/'
    r'(?P<prefix>\d{1,2})'
)

GATEWAY_RE = re.compile(
    r'Gateway\s+(?P<gw>\d{1,3}(?:\.\d{1,3}){3})',
    re.I
)

# Example:
# PC_A [192.168.10.10/24, Gateway 192.168.10.1]
HOST_RE = re.compile(
    r'(?P<device>[A-Za-z][A-Za-z0-9_-]*)\s*'
    r'\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/'
    r'(?P<prefix>\d{1,2})'
    r'(?:,\s*Gateway\s+(?P<gw>\d{1,3}(?:\.\d{1,3}){3}))?\]',
    re.I
)

# Example:
# R1 Fa0/0.10 [192.168.10.1/24]
INTERFACE_BRACKET_RE = re.compile(
    r'(?P<device>R\d+|Router\d*|SW\d+|Switch\d*)\s+'
    r'(?P<intf>[A-Za-z]+[\w/.-]*)\s*'
    r'\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/'
    r'(?P<prefix>\d{1,2})\]',
    re.I
)

def prefix_to_mask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def parse_hosts_and_bracket_interfaces(topology: str) -> Tuple[List[Host], List[Interface]]:
    hosts: List[Host] = []
    interfaces: List[Interface] = []

    # Host entries such as PC_A [ip/mask, Gateway gw]
    for m in HOST_RE.finditer(topology):
        device = m.group("device")
        ip = m.group("ip")
        prefix = int(m.group("prefix"))
        gw = m.group("gw")

        if not valid_ip(ip) or not 0 <= prefix <= 32:
            continue

        # PC/laptop/server style entries are hosts.
        if re.match(r"^(PC|Laptop|Server|Host|Client)", device, re.I):
            hosts.append(
                Host(
                    device=device,
                    ip=ip,
                    mask=prefix_to_mask(prefix),
                    gateway=gw
                )
            )
        else:
            interfaces.append(
                Interface(
                    device=device,
                    name="topology-interface",
                    ip=ip,
                    mask=prefix_to_mask(prefix)
                )
            )

    # Router/switch interface entries written outside the host syntax.
    for m in INTERFACE_BRACKET_RE.finditer(topology):
        device = m.group("device")
        ip = m.group("ip")
        prefix = int(m.group("prefix"))
        interfaces.append(
            Interface(
                device=device,
                name=m.group("intf"),
                ip=ip,
                mask=prefix_to_mask(prefix)
            )
        )

    return hosts, interfaces


def normalize_interface_name(name: str) -> str:
    """Normalize Cisco short/long interface names for duplicate detection."""
    n = name.strip().lower()
    replacements = [
        ("fastethernet", "fa"),
        ("gigabitethernet", "gi"),
        ("tengigabitethernet", "te"),
        ("ethernet", "eth"),
    ]
    for long_name, short_name in replacements:
        if n.startswith(long_name):
            return short_name + n[len(long_name):]
    return n


def parse_show_ip_interface_brief(text: str) -> List[Interface]:
    """
    Parse Cisco 'show ip interface brief'.
    This command does NOT contain subnet masks, so mask remains None.
    """
    interfaces: List[Interface] = []

    pattern = re.compile(
        r'^(?P<intf>\S+)\s+'
        r'(?P<ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'(?P<status>administratively\s+down|up|down)\s+'
        r'(?P<protocol>up|down)\s*$',
        re.I
    )

    current_device = "Unknown"

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        prompt = re.match(r'^(R\d+|SW\d+|Router\d+|Switch\d+)#', line, re.I)
        if prompt:
            current_device = prompt.group(1)
            continue

        m = pattern.match(line)
        if not m:
            continue

        ip = None if m.group("ip").lower() == "unassigned" else m.group("ip")

        interfaces.append(
            Interface(
                device=current_device,
                name=m.group("intf"),
                ip=ip,
                mask=None,
                status=re.sub(r"\s+", " ", m.group("status").lower()),
                protocol=m.group("protocol").lower()
            )
        )

    return interfaces


def parse_show_vlan_brief(text: str) -> Dict[str, set]:
    """
    Parse VLAN IDs from 'show vlan brief'.
    The switch name is taken from the most recent Cisco prompt.
    """
    vlan_ids: Dict[str, set] = {}
    current_device = "Unknown"

    for line in text.splitlines():
        line = line.strip()

        prompt = re.match(r'^(SW\d+|Switch\d+)#', line, re.I)
        if prompt:
            current_device = prompt.group(1)
            vlan_ids.setdefault(current_device, set())
            continue

        # VLAN brief rows start with an integer VLAN ID.
        m = re.match(r'^(\d+)\s+\S+', line)
        if m:
            vlan_ids.setdefault(current_device, set()).add(int(m.group(1)))

    return vlan_ids


def parse_switchport_status(text: str) -> List[SwitchPort]:
    """
    Parse common 'show interfaces status' output.

    Example:
    Fa0/5   inactive   30   auto   auto   10/100BaseTX
    """
    ports: List[SwitchPort] = []
    current_device = "Unknown"

    for line in text.splitlines():
        line = line.strip()

        prompt = re.match(r'^(SW\d+|Switch\d+)#', line, re.I)
        if prompt:
            current_device = prompt.group(1)
            continue

        # Port, status, VLAN are the first three useful columns.
        m = re.match(
            r'^(?P<port>(?:Fa|Gi|Te|Eth)\S+)\s+'
            r'(?P<status>\S+)\s+'
            r'(?P<vlan>\d+)\b',
            line,
            re.I
        )
        if m:
            ports.append(
                SwitchPort(
                    device=current_device,
                    port=m.group("port"),
                    vlan=int(m.group("vlan")),
                    status=m.group("status").lower()
                )
            )

    return ports


def parse_running_config_interfaces(text: str) -> List[Interface]:
    """Parse common interface blocks from show running-config output."""
    interfaces: List[Interface] = []
    current_device = "Unknown"
    current_name: Optional[str] = None
    current_ip: Optional[str] = None
    current_mask: Optional[str] = None
    current_status = "unknown"

    def flush() -> None:
        nonlocal current_name, current_ip, current_mask, current_status
        if current_name:
            interfaces.append(Interface(
                device=current_device,
                name=current_name,
                ip=current_ip,
                mask=current_mask,
                status=current_status,
                protocol="unknown",
            ))
        current_name = None
        current_ip = None
        current_mask = None
        current_status = "unknown"

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        prompt = re.match(r'^(R\d+|Router\d+|SW\d+|Switch\d+)#', line, re.I)
        if prompt:
            flush()
            current_device = prompt.group(1)
            continue
        m = re.match(r'^interface\s+(\S+)', line, re.I)
        if m:
            flush()
            current_name = m.group(1)
            continue
        if current_name is None:
            continue
        m = re.match(
            r'^ip address\s+(\d{1,3}(?:\.\d{1,3}){3})\s+'
            r'(\d{1,3}(?:\.\d{1,3}){3})',
            line, re.I
        )
        if m:
            current_ip, current_mask = m.group(1), m.group(2)
        elif re.match(r'^shutdown$', line, re.I):
            current_status = "administratively down"
        elif re.match(r'^no shutdown$', line, re.I):
            current_status = "up"

    flush()
    return interfaces


def parse_vlan_assignment_from_topology(topology: str) -> List[SwitchPort]:
    ports: List[SwitchPort] = []
    for m in re.finditer(
        r'(?P<device>SW\d+|Switch\d+)\s+'
        r'(?P<port>(?:Fa|Gi|Te|Eth)\S+)\s*'
        r'\([^)]*?access vlan\s+(?P<vlan>\d+)[^)]*\)',
        topology, re.I
    ):
        ports.append(
            SwitchPort(
                m.group("device"),
                m.group("port"),
                int(m.group("vlan")),
                "configured"
            )
        )
    return ports


def parse_explicit_destination(text: str) -> Optional[str]:
    """Find an explicit target subnet in the case evidence, never in expected_fault."""
    patterns = [
        r'(?:destination|target|remote|branch|expected)\s+'
        r'(?:subnet|network)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})',
        r'route\s+to\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(1)
    return None


def build_evidence(topology: str, show_output: str) -> Evidence:
    hosts, interfaces = parse_hosts_and_bracket_interfaces(topology)
    interfaces.extend(parse_show_ip_interface_brief(show_output))
    interfaces.extend(parse_running_config_interfaces(show_output))

    # The same interface can appear in topology_note and CLI output.
    # Keep one logical record so duplicate-IP/subnet checks do not double-count it.
    unique_interfaces = {}
    for iface in interfaces:
        key = (
            iface.device.lower(),
            normalize_interface_name(iface.name),
            iface.ip,
            iface.mask,
        )
        existing = unique_interfaces.get(key)
        if existing is None:
            unique_interfaces[key] = iface
        else:
            # Prefer explicit status/protocol information from CLI output.
            if existing.status == "unknown" and iface.status != "unknown":
                existing.status = iface.status
            if existing.protocol == "unknown" and iface.protocol != "unknown":
                existing.protocol = iface.protocol
    interfaces = list(unique_interfaces.values())

    vlan_ids = parse_show_vlan_brief(show_output)
    switchports = parse_switchport_status(show_output)
    switchports.extend(parse_vlan_assignment_from_topology(topology))

    # Avoid counting the same port twice when it appears in both topology_note
    # and CLI output.
    unique_ports = {}
    for port in switchports:
        key = (port.device.lower(), port.port.lower(), port.vlan)
        unique_ports[key] = port
    switchports = list(unique_ports.values())

    return Evidence(
        hosts=hosts,
        interfaces=interfaces,
        vlan_ids=vlan_ids,
        switchports=switchports,
        route_text_present=("show ip route" in show_output.lower()),
        raw_text=show_output,
    )


# ============================================================
# RULE CHECKS
# ============================================================

class RuleChecker:
    def __init__(self, evidence: Evidence):
        self.e = evidence

    def duplicate_ip(self) -> Result:
        # Use a set per IP so the same interface appearing once in topology
        # text and once in show output is not falsely counted twice.
        owners: Dict[str, set] = {}

        for h in self.e.hosts:
            owners.setdefault(h.ip, set()).add(h.device)

        for i in self.e.interfaces:
            if i.ip:
                owner = f"{i.device} {normalize_interface_name(i.name)}"
                owners.setdefault(i.ip, set()).add(owner)

        total_unique_owners = sum(len(v) for v in owners.values())

        if total_unique_owners < 2:
            return Result(
                "Duplicate IP Addresses",
                "NOT_CHECKED",
                "Fewer than two distinct IP endpoints were available; "
                "duplicate-IP checking needs at least two endpoints."
            )

        duplicates = {
            ip: sorted(names) for ip, names in owners.items()
            if len(names) > 1
        }

        if duplicates:
            details = "; ".join(
                f"{ip} assigned to {', '.join(names)}"
                for ip, names in duplicates.items()
            )
            return Result("Duplicate IP Addresses", "FAIL", details)

        return Result(
            "Duplicate IP Addresses",
            "PASS",
            "No duplicate IP addresses detected among the available endpoints."
        )

    def subnet_mask_mismatch(self) -> Result:
        endpoints: List[Tuple[str, str, str]] = []

        for h in self.e.hosts:
            endpoints.append((h.device, h.ip, h.mask))

        for i in self.e.interfaces:
            if i.ip and i.mask:
                endpoints.append((f"{i.device} {i.name}", i.ip, i.mask))

        if len(endpoints) < 2:
            return Result(
                "Subnet Mask Mismatch",
                "NOT_CHECKED",
                "At least two IP endpoints with explicit subnet masks are required."
            )

        mismatches = []

        # Two endpoints are candidates for the same link/subnet when each
        # endpoint's address lies inside the other's configured network.
        for idx in range(len(endpoints)):
            name_a, ip_a, mask_a = endpoints[idx]
            try:
                net_a = ipaddress.IPv4Network(f"{ip_a}/{mask_a}", strict=False)
                addr_a = ipaddress.IPv4Address(ip_a)
            except ValueError:
                continue

            for jdx in range(idx + 1, len(endpoints)):
                name_b, ip_b, mask_b = endpoints[jdx]
                if mask_a == mask_b:
                    continue
                try:
                    net_b = ipaddress.IPv4Network(f"{ip_b}/{mask_b}", strict=False)
                    addr_b = ipaddress.IPv4Address(ip_b)
                except ValueError:
                    continue

                if addr_b in net_a and addr_a in net_b:
                    mismatches.append(
                        f"{name_a}={mask_a} vs {name_b}={mask_b} "
                        f"(overlapping subnet evidence)"
                    )

        if mismatches:
            return Result(
                "Subnet Mask Mismatch",
                "FAIL",
                " | ".join(mismatches)
            )

        return Result(
            "Subnet Mask Mismatch",
            "PASS",
            "No subnet-mask mismatch was detected among comparable IP endpoints."
        )

    def default_gateway_mismatch(self) -> Result:
        if not self.e.hosts:
            return Result(
                "Default Gateway Mismatch",
                "NOT_CHECKED",
                "No host IP/gateway information was found."
            )

        router_ips = {
            i.ip for i in self.e.interfaces
            if i.ip and re.match(r"^(R\d+|Router\d+)$", i.device, re.I)
        }

        # If topology uses bracketed router interfaces, they are also included.
        if not router_ips:
            return Result(
                "Default Gateway Mismatch",
                "NOT_CHECKED",
                "Host gateways exist, but no router-interface IP was found in the evidence."
            )

        checked = 0
        failures = []

        for h in self.e.hosts:
            if not h.gateway:
                continue

            checked += 1

            if h.gateway not in router_ips:
                failures.append(
                    f"{h.device}: gateway {h.gateway} does not match "
                    f"any observed router interface ({', '.join(sorted(router_ips))})"
                )
                continue

            try:
                host_net = ipaddress.IPv4Network(
                    f"{h.ip}/{h.mask}", strict=False
                )
                if ipaddress.IPv4Address(h.gateway) not in host_net:
                    failures.append(
                        f"{h.device}: gateway {h.gateway} is outside "
                        f"host subnet {host_net}"
                    )
            except ValueError:
                failures.append(f"{h.device}: invalid IP/mask information.")

        if checked == 0:
            return Result(
                "Default Gateway Mismatch",
                "NOT_CHECKED",
                "No host with a configured gateway was found."
            )

        if failures:
            return Result(
                "Default Gateway Mismatch",
                "FAIL",
                " | ".join(failures)
            )

        return Result(
            "Default Gateway Mismatch",
            "PASS",
            "Observed host gateways match observed router-interface IPs and host subnets."
        )

    def interface_status_down(self) -> Result:
        admin_down = [
            i for i in self.e.interfaces
            if i.status == "administratively down"
        ]
        if admin_down:
            details = " | ".join(
                f"{i.device} {i.name}: administratively down"
                for i in admin_down
            )
            return Result("Interface Status Down", "FAIL", details)

        explicit = [
            i for i in self.e.interfaces
            if i.status in {"up", "down"} and "." not in i.name
        ]
        if not explicit:
            return Result(
                "Interface Status Down",
                "NOT_CHECKED",
                "No explicit interface status evidence was found."
            )

        failures = [
            f"{i.device} {i.name}: status=down, IP={i.ip}"
            for i in explicit
            if i.status == "down" and i.ip
        ]
        if failures:
            return Result(
                "Interface Status Down",
                "FAIL",
                " | ".join(failures)
            )

        return Result(
            "Interface Status Down",
            "PASS",
            "No IP-configured interface was explicitly shown down."
        )

    def missing_vlan(self) -> Result:
        if not self.e.switchports:
            return Result(
                "Missing VLAN Configuration",
                "NOT_CHECKED",
                "No access-port VLAN assignment was found in the supplied evidence."
            )

        if not self.e.vlan_ids:
            return Result(
                "Missing VLAN Configuration",
                "NOT_CHECKED",
                "A VLAN assignment was found, but no VLAN database was supplied."
            )

        failures = []
        checked = 0

        for port in self.e.switchports:
            if port.vlan is None:
                continue

            known = self.e.vlan_ids.get(port.device, set())
            if not known:
                continue

            checked += 1
            if port.vlan not in known:
                failures.append(
                    f"{port.device} {port.port} is assigned to VLAN {port.vlan}, "
                    f"but VLAN {port.vlan} is absent from that switch's VLAN database."
                )

        if checked == 0:
            return Result(
                "Missing VLAN Configuration",
                "NOT_CHECKED",
                "No switchport VLAN assignment could be compared with the corresponding VLAN database."
            )

        if failures:
            return Result(
                "Missing VLAN Configuration",
                "FAIL",
                " | ".join(failures)
            )

        return Result(
            "Missing VLAN Configuration",
            "PASS",
            "Observed switchport VLANs exist in the corresponding VLAN database."
        )

    def missing_route(self) -> Result:
        if not self.e.route_text_present:
            return Result(
                "Missing Route",
                "NOT_CHECKED",
                "No 'show ip route' evidence was supplied."
            )

        target = parse_explicit_destination(self.e.raw_text)
        if not target:
            return Result(
                "Missing Route",
                "NOT_CHECKED",
                "No explicit destination/target subnet was provided in the evidence."
            )

        try:
            target_net = ipaddress.IPv4Network(target, strict=False)
        except ValueError:
            return Result(
                "Missing Route",
                "ERROR",
                f"Invalid target subnet: {target}"
            )

        route_nets = []
        for route in re.findall(
            r'(?<!\d)(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})(?!\d)',
            self.e.raw_text
        ):
            try:
                route_nets.append(ipaddress.IPv4Network(route, strict=False))
            except ValueError:
                pass

        if any(
            target_net == n or target_net.subnet_of(n)
            for n in route_nets
        ):
            return Result(
                "Missing Route",
                "PASS",
                f"A route covering {target_net} is present in the supplied routing evidence."
            )

        return Result(
            "Missing Route",
            "FAIL",
            f"No route covering {target_net} was found in the supplied routing evidence."
        )

    def run_all(self) -> List[Result]:
        return [
            self.duplicate_ip(),
            self.subnet_mask_mismatch(),
            self.default_gateway_mismatch(),
            self.interface_status_down(),
            self.missing_vlan(),
            self.missing_route(),
        ]


# ============================================================
# CSV PROCESSING
# ============================================================

REQUIRED_COLUMNS = {
    "symptom",
    "topology_note",
    "show_command_output",
    "expected_fault",
    "osi_layer",
    "concept",
    "severity",
}


def process_csv(csv_path: str) -> List[dict]:
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                "CSV is missing required columns: " + ", ".join(sorted(missing))
            )

        output_rows = []

        for case_number, row in enumerate(reader, start=1):
            topology = row.get("topology_note", "") or ""
            show_output = row.get("show_command_output", "") or ""

            evidence = build_evidence(topology, show_output)
            results = RuleChecker(evidence).run_all()

            for result in results:
                output_rows.append({
                    "case_id": case_number,
                    "rule": result.rule,
                    "status": result.status,
                    "details": result.details,
                    "expected_fault_for_comparison_only":
                        row.get("expected_fault", ""),
                    "concept": row.get("concept", ""),
                    "severity": row.get("severity", ""),
                })

        return output_rows


def save_results(rows: List[dict], output_path: str) -> None:
    fields = [
        "case_id",
        "rule",
        "status",
        "details",
        "expected_fault_for_comparison_only",
        "concept",
        "severity",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def print_report(rows: List[dict]) -> None:
    print("=" * 78)
    print(" NetSage AI - Deterministic Rule Checker")
    print("=" * 78)

    case_ids = sorted({r["case_id"] for r in rows})

    for case_id in case_ids:
        print(f"\nCASE {case_id}")
        print("-" * 78)

        case_rows = [r for r in rows if r["case_id"] == case_id]
        shown = [r for r in case_rows if r["status"] != "NOT_CHECKED"]

        if not shown:
            print("No applicable deterministic rule had enough evidence to evaluate this case.")
            continue

        for r in shown:
            print(f"[{r['status']:<12}] {r['rule']}")
            print(f"  Evidence: {r['details']}")

    total = len(rows)
    passed = sum(r["status"] == "PASS" for r in rows)
    failed = sum(r["status"] == "FAIL" for r in rows)
    not_checked = sum(r["status"] == "NOT_CHECKED" for r in rows)
    errors = sum(r["status"] == "ERROR" for r in rows)

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"Cases processed : {len(case_ids)}")
    print(f"Rule checks     : {total}")
    print(f"PASS            : {passed}")
    print(f"FAIL            : {failed}")
    print(f"NOT_CHECKED     : {not_checked}")
    print(f"ERROR           : {errors}")
    print("=" * 78)


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run deterministic NetSage AI checks against cases.csv"
    )
    parser.add_argument(
        "--csv",
        default="cases.csv",
        help="Path to cases.csv (default: cases.csv)"
    )
    parser.add_argument(
        "--output",
        default="rule_checker_results.csv",
        help="Output CSV for checker results"
    )

    args = parser.parse_args()

    try:
        rows = process_csv(args.csv)
        save_results(rows, args.output)
        print_report(rows)

        print(f"\nResults saved to: {args.output}")

    except FileNotFoundError:
        print(f"ERROR: Could not find CSV file: {args.csv}")
    except Exception as exc:
        print(f"ERROR: {exc}")


if __name__ == "__main__":
    main()
