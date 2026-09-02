# Checkmk Sophos XGS IPsec

A Checkmk 2.5 SNMP check plug-in that monitors IPsec tunnel status on Sophos XG/XGS firewalls running SFOS 22.

The plug-in discovers every IPsec connection exposed by the Sophos Firewall MIB and creates one Checkmk service per tunnel.

## Status mapping

| Sophos state | Checkmk state | Meaning |
|---|---:|---|
| `activated=0` | OK | Administratively disabled |
| `activated=1, status=1` | OK | Active |
| `activated=1, status=2` | WARN | Partially active |
| `activated=1, status=0` | CRIT | Inactive |
| Unknown or malformed value | UNKNOWN | Unsupported SNMP value |

The activation flag is evaluated first, preventing deliberately disabled connections—such as unused remote-access definitions—from generating false alerts.

## Requirements

- Checkmk 2.5
- Sophos XG/XGS Firewall with SFOS 22
- SNMP enabled and accessible from the Checkmk server
- SNMPv3 is recommended

## Installation

Copy the plug-in into the Checkmk site as the site user:

```bash
mkdir -p ~/local/lib/python3/cmk_addons/plugins/sophos_xgs/agent_based
cp sophos_xgs_ipsec.py \
  ~/local/lib/python3/cmk_addons/plugins/sophos_xgs/agent_based/
cmk -R
```

Configure the firewall host for SNMP monitoring, then discover and test the services:

```bash
cmk --snmpwalk FIREWALL_HOST
cmk -vvI FIREWALL_HOST
cmk -vv FIREWALL_HOST
```

Discovered services are named `IPsec VPN <connection name>`.

## SNMP data

The plug-in identifies Sophos XG/XGS devices through:

```text
.1.3.6.1.4.1.2604.5.1.1.2.0
```

It reads the IPsec tunnel table rooted at:

```text
.1.3.6.1.4.1.2604.5.1.6.1.1.1.1
```

SNMP reports the firewall's IPsec/SA state but does not prove that application traffic can cross the tunnel. For end-to-end monitoring, add an ICMP or TCP reachability check for a remote address behind each tunnel.

## AI disclosure

This project was created with the assistance of an artificial intelligence language model. The generated implementation and documentation should be reviewed and tested by a qualified administrator before production deployment. The repository owner remains responsible for validation, maintenance, security and operational use.

## License

Released under the [GNU General Public License v2.0](LICENSE).
