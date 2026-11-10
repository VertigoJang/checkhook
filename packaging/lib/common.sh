# shellcheck shell=bash
# Shared helpers for CheckHook's Linux installers: distro detection, package-name
# hints, AppArmor/SELinux handling. Sourced, not executed.

# --- distro family -------------------------------------------------------------
# rhel (RHEL/Rocky/Alma/Fedora/CentOS), debian (Debian/Ubuntu/Mint...),
# arch (Arch/Manjaro/EndeavourOS), suse (openSUSE/SLES), or unknown.
distro_family() {
  local id="" like=""
  if [[ -r /etc/os-release ]]; then
    id="$(. /etc/os-release; echo "${ID:-}")"
    like="$(. /etc/os-release; echo "${ID_LIKE:-}")"
  fi
  case " $id $like " in
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) echo rhel ;;
    *" debian "*|*" ubuntu "*) echo debian ;;
    *" arch "*) echo arch ;;
    *" suse "*|*" opensuse "*|*" sles "*|*opensuse*) echo suse ;;
    *) echo unknown ;;
  esac
}

distro_id() { [[ -r /etc/os-release ]] && (. /etc/os-release; echo "${ID:-unknown}") || echo unknown; }

# install command prefix for the family
pkg_install_cmd() {
  case "$(distro_family)" in
    rhel)   echo "sudo dnf install -y" ;;
    debian) echo "sudo apt-get install -y" ;;
    arch)   echo "sudo pacman -S --needed" ;;
    suse)   echo "sudo zypper install -y" ;;
    *)      echo "install with your package manager:" ;;
  esac
}

# logical name -> package name(s) for this distro
pkg_name() {
  local fam id; fam="$(distro_family)"; id="$(distro_id)"
  case "$1:$fam" in
    pyyaml:rhel)      echo python3-pyyaml ;;
    pyyaml:debian)    echo python3-yaml ;;
    pyyaml:arch)      echo python-yaml ;;
    pyyaml:suse)      echo python3-PyYAML ;;
    bpftool:debian)   if [[ " $id $(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}") " == *" ubuntu "* ]]; then echo "linux-tools-common linux-tools-$(uname -r)"; else echo bpftool; fi ;;
    bpftool:arch)     echo bpf ;;
    libbpf:rhel|libbpf:suse) echo libbpf-devel ;;
    libbpf:debian)    echo libbpf-dev ;;
    libbpf:arch)      echo libbpf ;;
    semanage:*)       echo policycoreutils-python-utils ;;
    mergecap:rhel|mergecap:arch) echo wireshark-cli ;;
    mergecap:debian)  echo wireshark-common ;;
    mergecap:suse)    echo wireshark ;;
    *)                echo "$1" ;;   # tcpdump, nftables, clang, suricata ... same name
  esac
}

# print "missing X -> <install command>" and exit unless the command exists
need_cmd() {   # need_cmd <command> <logical package name>
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "missing '$1'  ->  $(pkg_install_cmd) $(pkg_name "$2")" >&2
  [[ "$2" == libbpf && "$(distro_family)" == rhel ]] && \
    echo "  (RHEL: libbpf-devel is in the CodeReady Builder repo)" >&2
  exit 1
}

# hint for pip on distros that mark the system Python as externally managed (PEP 668)
pip_hint() {   # pip_hint <packages...>
  if compgen -G "/usr/lib/python3*/EXTERNALLY-MANAGED" >/dev/null; then
    echo "sudo pip install --break-system-packages $*"
  else
    echo "sudo pip install $*"
  fi
}

# --- mandatory access control ------------------------------------------------------
selinux_on() { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; }

apparmor_on() {
  [[ -r /sys/module/apparmor/parameters/enabled ]] && \
    [[ "$(cat /sys/module/apparmor/parameters/enabled)" == Y ]]
}

# Let an AppArmor-confined tcpdump write into DIR (Ubuntu/Debian/openSUSE ship a
# tcpdump profile). Adds rules to the profile's local override file only.
apparmor_allow_tcpdump() {   # apparmor_allow_tcpdump <dir>
  apparmor_on || return 0
  local dir="$1" prof local_file
  for prof in /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/usr.sbin.tcpdump; do
    [[ -f "$prof" ]] || continue
    local_file="/etc/apparmor.d/local/$(basename "$prof")"
    if ! grep -q "local/$(basename "$prof")" "$prof"; then
      echo "[!] AppArmor: $prof has no local override include; tcpdump may be denied writing to $dir" >&2
      echo "    put it in complain mode if capture fails:  sudo aa-complain $prof" >&2
      continue
    fi
    mkdir -p /etc/apparmor.d/local
    touch "$local_file"
    if ! grep -qF "$dir/** rwk," "$local_file"; then
      printf '# added by CheckHook install-capture.sh\n%s/ r,\n%s/** rwk,\n' "$dir" "$dir" >> "$local_file"
    fi
    apparmor_parser -r "$prof" && echo "[+] AppArmor: tcpdump may write to $dir ($local_file)"
  done
}

nologin_shell() { command -v nologin 2>/dev/null || echo /bin/false; }
