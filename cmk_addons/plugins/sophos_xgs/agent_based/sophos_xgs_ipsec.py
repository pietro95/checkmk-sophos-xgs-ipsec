#!/usr/bin/env python3
"""Checkmk 2.5 SNMP check for Sophos Firewall IPsec tunnels."""

from collections.abc import Mapping, Sequence
from typing import TypedDict

from cmk.agent_based.v2 import (
    CheckPlugin,
    Result,
    Service,
    SimpleSNMPSection,
    SNMPTree,
    State,
    StringTable,
    startswith,
)


class Tunnel(TypedDict):
    index: str
    description: str
    policy: str
    mode: str
    connection_type: str
    local_gateway: str
    active_tunnels: int | None
    status: int | None
    activated: int | None


Section = Mapping[str, Tunnel]


def _as_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_sophos_xgs_ipsec(string_table: StringTable) -> Section:
    tunnels: dict[str, Tunnel] = {}

    for row in string_table:
        if len(row) < 10:
            continue

        index, name, description, policy, mode, conn_type, gateway, active, status, activated = row[:10]
        if not name:
            continue

        tunnels[name] = {
            "index": index,
            "description": description,
            "policy": policy,
            "mode": mode,
            "connection_type": conn_type,
            "local_gateway": gateway,
            "active_tunnels": _as_int(active),
            "status": _as_int(status),
            "activated": _as_int(activated),
        }

    return tunnels


snmp_section_sophos_xgs_ipsec = SimpleSNMPSection(
    name="sophos_xgs_ipsec",
    # sfosDeviceType contains values such as XG... and XGS....
    detect=startswith(".1.3.6.1.4.1.2604.5.1.1.2.0", "XG"),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.2604.5.1.6.1.1.1.1",
        oids=[
            "1",   # table index
            "2",   # connection name
            "3",   # description
            "4",   # policy name
            "5",   # mode
            "6",   # connection type
            "7",   # local gateway port
            "8",   # number of active child tunnels
            "9",   # connection status: 0/1/2
            "10",  # configured activation status: 0/1
        ],
    ),
    parse_function=parse_sophos_xgs_ipsec,
)


def discover_sophos_xgs_ipsec(section: Section) -> Sequence[Service]:
    return [Service(item=name) for name in section]


def check_sophos_xgs_ipsec(item: str, section: Section):
    tunnel = section.get(item)
    if tunnel is None:
        yield Result(state=State.UNKNOWN, summary="Tunnel no longer present in the SNMP table")
        return

    activated = tunnel["activated"]
    status = tunnel["status"]
    active_tunnels = tunnel["active_tunnels"]

    if activated == 0:
        state = State.OK
        status_text = "administratively disabled"
    elif activated != 1:
        state = State.UNKNOWN
        status_text = f"unknown activation value ({activated})"
    elif status == 1:
        state = State.OK
        status_text = "active"
    elif status == 2:
        state = State.WARN
        status_text = "partially active"
    elif status == 0:
        state = State.CRIT
        status_text = "inactive"
    else:
        state = State.UNKNOWN
        status_text = f"unknown status value ({status})"

    summary = f"Status: {status_text}"
    if active_tunnels is not None:
        summary += f", active child tunnels: {active_tunnels}"

    details = (
        f"Status: {status_text}\n"
        f"Active child tunnels: {active_tunnels if active_tunnels is not None else 'unknown'}\n"
        f"Policy: {tunnel['policy'] or 'n/a'}\n"
        f"Mode: {tunnel['mode'] or 'n/a'}\n"
        f"Connection type: {tunnel['connection_type'] or 'n/a'}\n"
        f"Local gateway: {tunnel['local_gateway'] or 'n/a'}\n"
        f"Description: {tunnel['description'] or 'n/a'}\n"
        f"SNMP table index: {tunnel['index']}"
    )
    yield Result(state=state, summary=summary, details=details)


check_plugin_sophos_xgs_ipsec = CheckPlugin(
    name="sophos_xgs_ipsec",
    service_name="IPsec VPN %s",
    discovery_function=discover_sophos_xgs_ipsec,
    check_function=check_sophos_xgs_ipsec,
)
