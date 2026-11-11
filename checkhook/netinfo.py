"""This host's own network: DNS servers, default gateways, own addresses.

Used to never block the host's own infrastructure (`protect_local`), and by
the triage to mark such alerts as false positives without asking the model.
A laptop changes networks, so the bridge re-reads it at most once a minute.
"""
import ipaddress, json, os, re, subprocess, time

WINDOWS = os.name == "nt"


def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _ipv4s(text):
    out = []
    for tok in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text or ""):
        try:
            ipaddress.IPv4Address(tok)
        except ValueError:
            continue
        if tok not in out:
            out.append(tok)
    return out


def local_context():
    """This host's DNS servers, default gateways and own IPv4 addresses.

    Best effort: anything that can't be read is left empty."""
    dns, gw, own = [], [], []
    if WINDOWS:
        ps = ["powershell", "-NoProfile", "-Command"]
        dns = _ipv4s(_run(ps + ["Get-DnsClientServerAddress -AddressFamily IPv4 | "
                                "ForEach-Object { $_.ServerAddresses }"]))
        gw = _ipv4s(_run(ps + ["Get-NetRoute -DestinationPrefix 0.0.0.0/0 "
                               "-ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop }"]))
        own = _ipv4s(_run(ps + ["Get-NetIPAddress -AddressFamily IPv4 | "
                                "ForEach-Object { $_.IPAddress }"]))
    else:
        for f in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.startswith("nameserver"):
                            dns += [ip for ip in _ipv4s(line) if ip not in dns]
            except OSError:
                pass
        # systemd-resolved stub (127.0.0.53) hides the real servers; ask NetworkManager too
        dns += [ip for ip in _ipv4s(_run(["nmcli", "-t", "-f", "IP4.DNS", "dev", "show"]))
                if ip not in dns]
        try:
            for r in json.loads(_run(["ip", "-j", "-4", "route", "show", "default"]) or "[]"):
                if r.get("gateway") and r["gateway"] not in gw:
                    gw.append(r["gateway"])
        except ValueError:
            pass
        try:
            for link in json.loads(_run(["ip", "-j", "-4", "addr"]) or "[]"):
                for a in link.get("addr_info", []):
                    if a.get("local") and a["local"] not in own:
                        own.append(a["local"])
        except ValueError:
            pass
    dns = [ip for ip in dns if not ipaddress.IPv4Address(ip).is_loopback]
    own = [ip for ip in own if not ipaddress.IPv4Address(ip).is_loopback]
    return {"dns": dns, "gateway": gw, "own": own}




class LocalInfra:
    """Cached set of local infrastructure IPs (DNS servers, gateways, own
    addresses), refreshed at most every `ttl` seconds."""

    def __init__(self, ttl=60, probe=None, clock=time.monotonic):
        self.ttl, self.probe, self.clock = ttl, probe or local_context, clock
        self._at, self._ips = None, frozenset()

    def ips(self):
        now = self.clock()
        if self._at is None or now - self._at >= self.ttl:
            try:
                c = self.probe()
                self._ips = frozenset(c["dns"] + c["gateway"] + c["own"])
            except Exception:
                pass                      # keep the previous answer
            self._at = now
        return self._ips

    def __contains__(self, ip):
        return ip in self.ips()
