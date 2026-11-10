"""Windows enforcement backend: Windows Defender Firewall (WFP) rules.

Windows has no nftables/XDP and its firewall rules have no timeouts, so:
  * the blocklist (IP -> expiry, wall clock) lives in a JSON state file,
    %ProgramData%\\CheckHook\\blocklist.json, guarded by a lock file;
  * after every change the firewall rules in group "CheckHook" are rebuilt from
    the state: one inbound + one outbound Block rule per chunk of addresses, so
    a blocked source is cut off in both directions (like dropping all of its
    packets on Linux);
  * expired entries are removed by reconcile(), which checkhookd runs
    every minute.

Only addresses that parse as IPv4 ever reach PowerShell, so the generated
script cannot be injected into.
"""
import ipaddress
import json
import os
import subprocess
import time

GROUP = "CheckHook"
CHUNK = 1000                 # addresses per rule (stays well inside WFP limits)


def state_dir():
    return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "CheckHook")


def _ps(script):
    """Run a PowerShell script; return CompletedProcess."""
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        capture_output=True, text=True)


class _Lock:
    """Cross-process lock via an exclusively created file (stale after 30 s)."""

    def __init__(self, path, timeout=10.0):
        self.path, self.timeout = path, timeout

    def __enter__(self):
        end = time.time() + self.timeout
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > 30:
                        os.unlink(self.path)          # stale lock from a crash
                        continue
                except FileNotFoundError:
                    continue
                if time.time() > end:
                    raise TimeoutError(f"lock busy: {self.path}")
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


class WinFirewall:
    def __init__(self, base=None, runner=_ps, clock=time.time):
        self.base = base or state_dir()
        self.state = os.path.join(self.base, "blocklist.json")
        self.lockfile = os.path.join(self.base, "blocklist.lock")
        self.run = runner
        self.now = clock

    # ------------------------------------------------------------ state file
    def _load(self):
        try:
            with open(self.state, encoding="utf-8") as f:
                data = json.load(f)
            return {ip: float(exp) for ip, exp in data.items()}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self, entries):
        os.makedirs(self.base, exist_ok=True)
        tmp = self.state + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=0, sort_keys=True)
        os.replace(tmp, self.state)

    def _live(self, entries):
        now = self.now()
        return {ip: exp for ip, exp in entries.items() if exp == 0 or exp > now}

    # --------------------------------------------------------------- rules
    def _apply(self, entries):
        ips = sorted(entries, key=ipaddress.ip_address)
        for ip in ips:                                   # defence in depth
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError(ip)
        lines = ["$ErrorActionPreference = 'Stop'",
                 f"Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"]
        for n, i in enumerate(range(0, len(ips), CHUNK), 1):
            addrs = ",".join(f"'{ip}'" for ip in ips[i:i + CHUNK])
            for direction in ("Inbound", "Outbound"):
                lines.append(
                    f"New-NetFirewallRule -Group '{GROUP}' -DisplayName 'CheckHook block {direction} {n:03d}' "
                    f"-Direction {direction} -Action Block -Profile Any -RemoteAddress @({addrs}) | Out-Null")
        r = self.run("\n".join(lines))
        if r.returncode != 0:
            raise RuntimeError(f"firewall update failed: {(r.stderr or r.stdout).strip()}")

    # ------------------------------------------------------------- public API
    def add(self, ip, seconds):
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            raise ValueError(f"IPv4 only: {ip}")
        with _Lock(self.lockfile):
            entries = self._live(self._load())
            entries[str(addr)] = self.now() + seconds if seconds else 0
            self._save(entries)
            self._apply(entries)

    def remove(self, ip):
        with _Lock(self.lockfile):
            entries = self._live(self._load())
            if entries.pop(str(ipaddress.ip_address(ip)), None) is not None:
                self._save(entries)
                self._apply(entries)

    def entries(self):
        """[(ip, expiry_epoch)] that are still active (0 = never)."""
        return sorted(self._live(self._load()).items(),
                      key=lambda e: ipaddress.ip_address(e[0]))

    def reconcile(self):
        """Drop expired entries and rebuild rules if anything changed.
        Returns the number of entries removed."""
        with _Lock(self.lockfile):
            entries = self._load()
            live = self._live(entries)
            if len(live) != len(entries):
                self._save(live)
                self._apply(live)
            return len(entries) - len(live)

    def flush(self):
        with _Lock(self.lockfile):
            self._save({})
            self._apply({})

    def rules(self):
        """Names of CheckHook's firewall rules currently present."""
        r = self.run(f"Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue "
                     "| ForEach-Object { $_.DisplayName }")
        return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
