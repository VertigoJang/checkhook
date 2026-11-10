"""Windows network helpers: find the capture device for Npcap.

Npcap names devices \\Device\\NPF_{InterfaceGuid}. The GUID is stable, unlike
the adapter's IP address (which changes with DHCP), so CheckHook captures on the
device name.
"""
import json
import re

from checkhook.winfw import _ps

_GUID = re.compile(r"^\{[0-9A-Fa-f-]{36}\}$")

_DEFAULT_ADAPTER = r"""
$ErrorActionPreference = 'Stop'
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
     Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric } |
     Select-Object -First 1
$a = Get-NetAdapter -InterfaceIndex $r.ifIndex
$ip = (Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress
[pscustomobject]@{ Name = $a.Name; Guid = $a.InterfaceGuid; IPv4 = $ip } | ConvertTo-Json -Compress
"""


def _adapter_by_name(name):
    safe = name.replace("'", "''")
    return (r"$ErrorActionPreference = 'Stop'; $a = Get-NetAdapter -Name '" + safe + "'; "
            r"[pscustomobject]@{ Name = $a.Name; Guid = $a.InterfaceGuid; IPv4 = '' } | ConvertTo-Json -Compress")


def adapter(name=None, runner=_ps):
    """{'Name', 'Guid', 'IPv4', 'Device'} of the named adapter, or of the one
    that carries the default route when name is None/'auto'."""
    script = _DEFAULT_ADAPTER if name in (None, "", "auto") else _adapter_by_name(name)
    r = runner(script)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"could not find network adapter {name or '(default route)'}: "
                           f"{(r.stderr or r.stdout).strip()}")
    info = json.loads(r.stdout)
    guid = info.get("Guid", "")
    if not _GUID.match(guid):
        raise RuntimeError(f"unexpected interface GUID: {guid!r}")
    info["Device"] = "\\Device\\NPF_" + guid
    return info


def capture_device(value, runner=_ps):
    """Config value -> Npcap device name. Accepts 'auto', an adapter name
    (e.g. 'Wi-Fi') or a device name (\\Device\\NPF_{...})."""
    if value and value.startswith("\\Device\\"):
        return value
    return adapter(value, runner)["Device"]
