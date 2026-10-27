#!/usr/bin/env python3
"""php2shell-audit: check THIS machine for the PHP2Shell fix
(CVE-2026-109618 / CVE-2026-109619).

Read-only. Stdlib only. Python 3.8+. Nothing is sent anywhere, nothing is
scanned except the local filesystem and /proc of the host it runs on.

Exit codes: 0 all patched, 1 something vulnerable, 2 needs manual review,
3 no PHP found.
"""
from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

PATCHED = "PATCHED"
VULNERABLE = "VULNERABLE"
NEEDS_REVIEW = "NEEDS REVIEW"

# Fixed upstream in these patch releases, per branch.
FIXED_IN = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
# Only minimal source backports exist for these; no regular release.
BACKPORT_ONLY = {(8, 1), (8, 0), (7, 4)}

EVIDENCE_RE = re.compile(r"109618|109619|php2shell", re.I)
# Scan only the newest slice of a changelog. Entries are newest-first, so a CVE
# citation (if present) sits at the top; this caps memory/time on a package with
# a pathologically long history without affecting any real verdict.
MAX_CHANGELOG_BYTES = 200_000
# Strict allowlist: php-config, phpize, phpenmod, phpquery, phpdbg never match.
BIN_RE = re.compile(r"^(?:php|php-fpm|php-cgi|lsphp|frankenphp)(?:\d+(?:\.\d+)*)?$")
WEB_COMMS = {"apache2", "httpd", "litespeed", "lshttpd", "frankenphp"}

MARKER = "#P2S1"

# Distros whose package version number stays put while fixes are backported.
BACKPORTING_IDS = {"ubuntu", "rhel", "centos", "almalinux", "rocky", "cloudlinux",
                   "ol", "amzn", "sles", "opensuse-leap"}
# Distros whose security archive ships the upstream version number.
UPSTREAM_IDS = {"debian", "alpine"}

DEB_RUNTIME_RE = re.compile(
    r"^(?:php(?:\d+\.\d+)?-(?:cli|fpm|cgi|embed)|libapache2-mod-php(?:\d+\.\d+)?"
    r"|libphp(?:\d+\.\d+)?-embed)$")
RPM_APK_RUNTIME_RE = re.compile(
    r"^(?:ea-|alt-)?php\d*(?:-php)?(?:-(?:cli|fpm|cgi|embedded|embed|litespeed|apache2))?$")


# --------------------------------------------------------------------------
# Verdict logic
# --------------------------------------------------------------------------

def parse_version(s: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """x.y.z from 'PHP 8.3.6', '1:8.3.6-0ubuntu0.1', '8.3.14-r0'; else None."""
    if not s:
        return None
    m = re.match(r"^\s*(?:\d+:)?(\d+)\.(\d+)\.(\d+)", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def classify_family(name: str, version: str, os_id: Optional[str] = None) -> Optional[str]:
    """'upstream' (pkg version tracks php.net), 'backporting' (old number, fixes
    patched in), or None when we cannot tell."""
    v = (version or "").lower()
    n = (name or "").lower()
    if "sury" in v or "remi" in v or n.startswith("ea-php"):
        return "upstream"
    if n.startswith("alt-php"):
        return "backporting"
    if "ubuntu" in v:
        return "backporting"
    if re.search(r"[~+]deb\d+", v):
        return "upstream"
    if re.search(r"\.(?:el|cl|amzn)\d", v) or "cloudlinux" in v or "alma" in v:
        return "backporting"
    if re.search(r"-r\d+$", v):
        return "upstream"
    if os_id in BACKPORTING_IDS:
        return "backporting"
    if os_id in UPSTREAM_IDS:
        return "upstream"
    return None


def judge(version: Optional[str], packaged: Optional[bool], family: Optional[str] = None,
          evidence: Optional[bool] = None) -> Tuple[str, str]:
    """Core verdict table.

    packaged: True = owned by a distro package, False = self-compiled/unpackaged,
              None = unknown (only `php -v` output available).
    family:   'upstream' | 'backporting' | None, for packaged builds.
    evidence: True = changelog cites the CVE, False = changelog checked and does
              not, None = no changelog available.
    """
    v = parse_version(version)
    if v is None:
        return NEEDS_REVIEW, "Could not read a x.y.z version number from the input."
    branch = (v[0], v[1])
    bname = "%d.%d" % branch
    fixed = FIXED_IN.get(branch)

    if evidence is True:
        return PATCHED, ("The package changelog cites the CVE-2026-109618/109619 fix, so the "
                         "old-looking version number %s.%d is expected." % (bname, v[2]))
    if branch > (8, 5):
        return PATCHED, "%s is newer than every affected release (up to 8.5.11)." % version
    if fixed is not None and v[2] >= fixed:
        return PATCHED, "%s is at or above the upstream fix (%s.%d)." % (version, bname, fixed)

    # Below the fix, no changelog proof from here on.
    if fixed is not None:
        want = "upstream fixed it in %s.%d" % (bname, fixed)
    elif branch in BACKPORT_ONLY:
        want = "%s has no regular upstream fix release (source backports only)" % bname
    else:
        want = "%s has no fix at all" % bname

    if packaged is None:
        return NEEDS_REVIEW, ("Version %s is below the fix (%s). `php -v` cannot tell whether a "
                              "distro backported the patch into this number, so check the owning "
                              "package's changelog." % (version, want))
    if packaged is False:
        return VULNERABLE, ("Version %s is below the fix (%s) and the binary is not owned by a "
                            "package, so there is no distro backport to hope for." % (version, want))
    # Packaged, no proof.
    if branch < (7, 4):
        return VULNERABLE, ("%s is end-of-life with no fix, and the package changelog does not "
                            "cite the CVE." % bname)
    if family == "upstream" and fixed is not None:
        return VULNERABLE, ("This distro ships upstream version numbers and %s is below the fix "
                            "(%s), so it is not patched." % (version, want))
    why = {True: "its changelog does not mention the CVE",
           False: "its changelog does not mention the CVE",
           None: "no changelog was available to check"}[evidence]
    return NEEDS_REVIEW, ("Version %s is below the fix (%s) but distro packages keep the old "
                          "number when they backport. %s; most likely not patched yet. Update the "
                          "package and re-check." % (version, want, why[0].upper() + why[1:]))


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str                      # binary | module | package | process | version
    subject: str
    verdict: str
    reason: str
    version: Optional[str] = None
    fix: List[str] = field(default_factory=list)
    extra: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "subject": self.subject, "version": self.version,
                "verdict": self.verdict, "reason": self.reason, "fix": self.fix,
                "extra": self.extra}


@dataclass
class Inventory:
    os: Dict[str, str] = field(default_factory=dict)
    pm: str = "none"
    is_root: Optional[bool] = None
    bins: List[Dict[str, str]] = field(default_factory=list)
    mods: List[Dict[str, str]] = field(default_factory=list)
    procs: List[Dict[str, str]] = field(default_factory=list)
    complete: bool = False


# --------------------------------------------------------------------------
# Fix commands
# --------------------------------------------------------------------------

def _fpm_unit(pm: str, pkg: str, branch: str) -> str:
    if pm == "dpkg":
        return "php%s-fpm" % branch
    m = re.match(r"^((?:ea-)?php\d+)-php", pkg or "")
    if m:
        return m.group(1) + "-php-fpm"
    return "php-fpm"


def fix_commands(pm: str, kind: str, pkg: str, version: Optional[str], subject: str,
                 packaged: Optional[bool]) -> List[str]:
    v = parse_version(version)
    branch = "%d.%d" % (v[0], v[1]) if v else ""
    bkey = (v[0], v[1]) if v else None
    cmds: List[str] = []
    is_fpm = "fpm" in (pkg or "") or "fpm" in os.path.basename(subject)
    is_mod = "mod" in (pkg or "") or "libphp" in subject or (pkg or "") in ("php", "php-apache2")

    if packaged is None:
        cmds += ["# Find the owning package first, then re-run this check with the package list:",
                 "dpkg -S \"$(readlink -f \"$(command -v php)\")\"    # Debian/Ubuntu",
                 "rpm -qf \"$(readlink -f \"$(command -v php)\")\"    # RHEL/Alma/CloudLinux"]
        return cmds

    if packaged is False or pm == "none":
        if bkey in FIXED_IN:
            cmds.append("# Rebuild/redeploy from php.net source %s.%d or newer (or pull a fixed official image)."
                        % (branch, FIXED_IN[bkey]))
        else:
            cmds.append("# No upstream fix for %s. Move to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer, "
                        "or use a vendor build whose changelog cites CVE-2026-109618." % (branch or "this branch"))
        return cmds

    target = pkg or ""
    if pm == "dpkg":
        cmds.append("sudo apt-get update && sudo apt-get install --only-upgrade %s"
                    % (target or "'php*' 'libapache2-mod-php*'"))
        if target:
            cmds.append("zgrep -iE '109618|109619' /usr/share/doc/%s/changelog.Debian.gz" % target)
        restart = "sudo systemctl restart apache2" if is_mod else (
            "sudo systemctl restart %s" % _fpm_unit(pm, target, branch) if is_fpm else "")
    elif pm == "rpm":
        cmds.append("sudo dnf upgrade --refresh %s    # yum on EL7" % (target or "'php*'"))
        if target:
            cmds.append("rpm -q --changelog %s | grep -iE '109618|109619'" % target)
        restart = "sudo systemctl restart httpd" if is_mod else (
            "sudo systemctl restart %s" % _fpm_unit(pm, target, branch) if is_fpm else "")
    elif pm == "apk":
        cmds.append("apk update && apk upgrade %s" % (target or "'php*'"))
        restart = "rc-service %s restart" % (re.sub(r"-fpm$", "", target).replace("php", "php-fpm", 1)
                                              if is_fpm and target else "apache2" if is_mod else "php-fpm")
        if not (is_fpm or is_mod):
            restart = ""
    else:
        restart = ""
    if restart:
        cmds.append(restart)
    elif kind in ("binary", "package", "module"):
        cmds.append("# After updating, restart whatever serves PHP (apache2/httpd, php-fpm, lsws, frankenphp).")
    if bkey in BACKPORT_ONLY or (bkey is not None and bkey < (7, 4)):
        cmds.append("# %s has no regular upstream fix. Unless the changelog check above shows the CVE, "
                    "move to a supported branch (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+)." % branch)
    return cmds


# --------------------------------------------------------------------------
# Parsers for pasted/collected input
# --------------------------------------------------------------------------

def parse_collector(text: str) -> Inventory:
    inv = Inventory()
    started = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(MARKER):
            started = True
            continue
        if not started or not line:
            continue
        parts = line.split("|")
        kind = parts[0]
        kv = {}
        for p in parts[1:]:
            if "=" in p:
                k, _, val = p.partition("=")
                kv[k] = val
        if kind == "os":
            inv.os = kv
        elif kind == "pm":
            inv.pm = kv.get("name", "none")
        elif kind == "user":
            inv.is_root = kv.get("root") == "1"
        elif kind == "bin":
            inv.bins.append(kv)
        elif kind == "mod":
            inv.mods.append(kv)
        elif kind == "proc":
            inv.procs.append(kv)
        elif kind == "end":
            inv.complete = True
    return inv


def parse_php_v(text: str) -> List[Dict[str, str]]:
    out = []
    for m in re.finditer(r"^PHP (\d+\.\d+\.\d+\S*) \(([^)]*)\)(?: \(built: ([A-Za-z]{3} +\d+ \d{4})[^)]*\))?",
                         text, re.M):
        out.append({"version": m.group(1), "sapi": m.group(2), "built": m.group(3) or ""})
    return out


def parse_packages(text: str) -> List[Dict[str, str]]:
    """dpkg -l / rpm -qa / apk info -v lines -> [{name, version, pm}]."""
    pkgs = []
    for raw in text.splitlines():
        line = raw.rstrip()
        m = re.match(r"^([a-z ]{2})([A-Z ]?)\s+([^\s:]+)(?::\S+)?\s+(\S+)\s+\S+", line)
        if m and m.group(1)[1] == "i" and not line.startswith(("Desired", "|", "+++")):
            pkgs.append({"name": m.group(3), "version": m.group(4), "pm": "dpkg"})
            continue
        s = line.strip()
        m = re.match(r"^(.+)-(\d[^-\s]*)-r(\d+)$", s)          # apk: php83-fpm-8.3.14-r0
        if m:
            pkgs.append({"name": m.group(1), "version": "%s-r%s" % (m.group(2), m.group(3)), "pm": "apk"})
            continue
        m = re.match(r"^(.+)-(\d[^-\s]*)-([^-\s]+)\.([A-Za-z0-9_]+)$", s)   # rpm NVRA
        if m and not re.search(r"\s", s):
            pkgs.append({"name": m.group(1), "version": "%s-%s" % (m.group(2), m.group(3)), "pm": "rpm"})
    return pkgs


def is_runtime_pkg(name: str, pm: str) -> bool:
    return bool((DEB_RUNTIME_RE if pm == "dpkg" else RPM_APK_RUNTIME_RE).match(name))


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

def _evidence(ev: str) -> Optional[bool]:
    if ev.startswith("yes"):
        return True
    if ev == "no":
        return False
    return None


def findings_from_inventory(inv: Inventory) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    notes: List[str] = []
    os_id = inv.os.get("id")
    pm = inv.pm

    for kind, items in (("binary", inv.bins), ("module", inv.mods)):
        for b in items:
            path = b.get("path", "?")
            pkg = b.get("pkg", "")
            pkgver = b.get("pkgver", "")
            ver = b.get("ver", "") or (pkgver if kind == "module" else "")
            packaged = bool(pkg)
            family = classify_family(pkg, pkgver, os_id) if packaged else None
            if not parse_version(ver):
                verdict, reason = NEEDS_REVIEW, "Could not determine the PHP version of this file."
            else:
                verdict, reason = judge(ver, packaged, family, _evidence(b.get("ev", "na")))
            extra = {k: b[k] for k in ("built", "pkg", "pkgver", "loaded") if b.get(k)}
            if kind == "module" and b.get("loaded") == "1":
                reason += " It is loaded by a running web server (mod_php, the highest-risk SAPI)."
            f = Finding(kind, path, verdict, reason, ver or None, [], extra)
            if verdict != PATCHED:
                f.fix = fix_commands(pm, kind, pkg, ver, path, packaged)
            findings.append(f)

    for p in inv.procs:
        n = p.get("n", "1")
        if p.get("stale") == "1":
            findings.append(Finding(
                "process", "%s (%s process%s)" % (p.get("comm", "?"), n, "" if n == "1" else "es"),
                NEEDS_REVIEW,
                "Still maps a replaced file (%s). The running code predates the on-disk update, so "
                "installing the patch is not enough until this is restarted." % p.get("stalepath", "?"),
                None, ["# restart the matching service, e.g.:",
                       "sudo systemctl restart apache2 php8.3-fpm    # httpd / php-fpm on RHEL-family"],
                {"comm": p.get("comm", "")}))
        if p.get("ro") == "1":
            notes.append("Could not read /proc maps for %s process(es) of %s; re-run as root to check "
                         "for stale code." % (n, p.get("comm", "?")))
    if inv.procs and inv.is_root is False and not any(p.get("stale") == "1" for p in inv.procs):
        notes.append("Run as root to inspect processes owned by other users (web workers usually are).")
    if not inv.complete:
        notes.append("The collector block looks truncated (no end marker). Paste the whole output.")
    return findings, notes


def findings_from_packages(pkgs: List[Dict[str, str]], os_id: Optional[str] = None) -> List[Finding]:
    out = []
    for p in pkgs:
        if not is_runtime_pkg(p["name"], p["pm"]) or not parse_version(p["version"]):
            continue
        family = classify_family(p["name"], p["version"], os_id)
        verdict, reason = judge(p["version"], True, family, None)
        f = Finding("package", "%s %s" % (p["name"], p["version"]), verdict, reason, p["version"],
                    [], {"pkg": p["name"], "pkgver": p["version"], "pm": p["pm"]})
        if verdict != PATCHED:
            f.fix = fix_commands(p["pm"], "package", p["name"], p["version"], p["name"], True)
        out.append(f)
    return out


def findings_from_php_v(entries: List[Dict[str, str]]) -> List[Finding]:
    out = []
    for e in entries:
        verdict, reason = judge(e["version"], None)
        f = Finding("version", "php -v: PHP %s (%s)" % (e["version"], e["sapi"]), verdict, reason,
                    e["version"], [], {"sapi": e["sapi"], "built": e["built"]})
        if verdict != PATCHED:
            f.fix = fix_commands("none", "version", "", e["version"], "php", None)
        out.append(f)
    return out


def overall(findings: List[Finding]) -> Tuple[str, int]:
    if not findings:
        return "NO PHP FOUND", 3
    verdicts = {f.verdict for f in findings}
    if VULNERABLE in verdicts:
        return VULNERABLE, 1
    if NEEDS_REVIEW in verdicts:
        return NEEDS_REVIEW, 2
    return PATCHED, 0


# --------------------------------------------------------------------------
# Live collection (mirrors collect.sh)
# --------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 5, merge: bool = False) -> Tuple[Optional[int], str]:
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT if merge else subprocess.DEVNULL,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def _have(tool: str) -> bool:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.access(os.path.join(d, tool), os.X_OK):
            return True
    return False


def read_os_release() -> Dict[str, str]:
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                info[k] = v.strip('"')
    except OSError:
        return {}
    return {"id": info.get("ID", ""), "ver": info.get("VERSION_ID", ""), "name": info.get("PRETTY_NAME", "")}


def detect_pm() -> str:
    for pm, tool in (("dpkg", "dpkg-query"), ("rpm", "rpm"), ("apk", "apk")):
        if _have(tool):
            return pm
    return "none"


EXTRA_DIRS = [
    "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
    "/usr/local/php*/bin", "/usr/local/php*/sbin",
    "/opt/remi/php*/root/usr/bin", "/opt/remi/php*/root/usr/sbin",
    "/opt/cpanel/ea-php*/root/usr/bin", "/opt/cpanel/ea-php*/root/usr/sbin",
    "/opt/alt/php*/usr/bin", "/opt/alt/php*/usr/sbin",
    "/usr/local/lsws/lsphp*/bin", "/opt/plesk/php/*/bin", "/opt/plesk/php/*/sbin",
]
MOD_GLOBS = ["/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
             "/usr/lib/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so"]
DELETED_PREFIX = re.compile(r"^/(?:usr|opt|lib|lib32|lib64|bin|sbin|snap)/")


def scan_processes() -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """-> (aggregated proc dicts, exe paths, libphp paths)"""
    counter: Counter = Counter()
    exes, libs = [], []
    for d in glob.glob("/proc/[0-9]*"):
        try:
            with open(d + "/comm", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if not (comm in WEB_COMMS or BIN_RE.match(comm)):
            continue
        try:
            exe = os.readlink(d + "/exe")
            exes.append(re.sub(r" \(deleted\)$", "", exe))
        except OSError:
            pass
        lp, stale, sp, ro = "-", 0, "-", 0
        try:
            with open(d + "/maps", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    f = line.split(None, 5)
                    if len(f) < 6:
                        continue
                    path = f[5].strip()
                    deleted = path.endswith(" (deleted)")
                    if deleted:
                        path = path[:-len(" (deleted)")]
                    if "libphp" in path and lp == "-":
                        lp = path
                    if deleted and DELETED_PREFIX.match(path):
                        stale = 1
                        if sp == "-":
                            sp = path
        except OSError:
            ro = 1
        if lp != "-":
            libs.append(lp)
        counter[(comm, lp, stale, sp, ro)] += 1
    procs = [{"comm": k[0], "libphp": k[1], "stale": str(k[2]), "stalepath": k[3], "ro": str(k[4]),
              "n": str(n)} for k, n in sorted(counter.items())]
    return procs, exes, libs


def changelog_hit(text: str) -> Optional[str]:
    """First line within the scan cap that cites the CVE, stripped, else None.

    Changelogs are newest-first, so a backport citation is in the top entry;
    only the first MAX_CHANGELOG_BYTES are scanned (see the constant).
    """
    for ln in text[:MAX_CHANGELOG_BYTES].splitlines():
        if EVIDENCE_RE.search(ln):
            return ln.strip()
    return None


def parse_apk_owner(who_owns: str) -> Tuple[str, str]:
    """Parse `apk info -W <path>` output into (name, version).

    The real output is one line of the form
        /usr/bin/php83 is owned by php83-8.3.36-r0
    so the owner token is a full name-version-release, not a bare package
    name. Split it into ("php83", "8.3.36-r0"). Return (owner, "") if it does
    not match that shape, or ("", "") when the path is owned by nothing.
    """
    m = re.search(r" owned by (\S+)", who_owns)
    if not m:
        return "", ""
    owner = m.group(1)
    mm = re.match(r"^(.+)-(\d[^-\s]*-r\d+)$", owner)
    if mm:
        return mm.group(1), mm.group(2)
    return owner, ""


def lookup_pkg(pm: str, resolved: str, original: str) -> Tuple[str, str, str]:
    """-> (pkg, pkgver, evidence) where evidence is yes:<line> | no | na."""
    pkg = pkgver = ""
    ev = "na"
    if pm == "dpkg":
        for q in (resolved, original):
            _, out = _run(["dpkg", "-S", q])
            first = out.splitlines()[0] if out.strip() else ""
            pkg = re.split(r"[:,]", first, 1)[0].strip() if first else ""
            if pkg:
                break
        if pkg:
            _, pkgver = _run(["dpkg-query", "-W", "-f=${Version}", pkg])
            for fn in ("changelog.Debian.gz", "changelog.gz", "changelog.Debian"):
                path = "/usr/share/doc/%s/%s" % (pkg, fn)
                if not os.access(path, os.R_OK):
                    continue
                try:
                    opener = gzip.open if path.endswith(".gz") else open
                    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                        chunk = fh.read(MAX_CHANGELOG_BYTES)
                    hit = changelog_hit(chunk)
                except (OSError, EOFError):
                    continue
                if hit:
                    ev = "yes:" + hit[:120].replace("|", "/")
                    break
                ev = "no"
    elif pm == "rpm":
        rc, out = _run(["rpm", "-qf", "--qf", "%{NAME}\\n", resolved])
        pkg = out.splitlines()[0].strip() if rc == 0 and out.strip() else ""
        if pkg:
            _, out = _run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", pkg])
            pkgver = out.splitlines()[0].strip() if out.strip() else ""
            _, cl = _run(["rpm", "-q", "--changelog", pkg], timeout=30)
            if cl.strip():
                hit = changelog_hit(cl)
                ev = ("yes:" + hit[:120].replace("|", "/")) if hit else "no"
    elif pm == "apk":
        _, out = _run(["apk", "info", "-W", resolved])
        pkg, pkgver = parse_apk_owner(out)
    return pkg, pkgver.strip(), ev


def probe_binary(path: str) -> Tuple[str, str]:
    for args in (["-v"], ["version"]):
        _, out = _run([path] + args, merge=True)
        m = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out)
        if m:
            b = re.search(r"built: ([A-Za-z]{3} +\d+ \d{4})", out)
            return m.group(1), re.sub(r" +", " ", b.group(1)) if b else ""
    return "", ""


def collect_live() -> Inventory:
    inv = Inventory(os=read_os_release(), pm=detect_pm())
    inv.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    inv.procs, exes, proc_libs = scan_processes()

    cands = list(exes)
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    for pattern in dirs + EXTRA_DIRS:
        for d in glob.glob(pattern):
            if not os.path.isdir(d):
                continue
            try:
                names = os.listdir(d)
            except OSError:
                continue
            cands += [os.path.join(d, n) for n in names if BIN_RE.match(n)]
    seen = set()
    for orig in sorted(set(cands)):
        if not (os.path.isfile(orig) and os.access(orig, os.X_OK)):
            continue
        real = os.path.realpath(orig)
        if real in seen:
            continue
        seen.add(real)
        ver, built = probe_binary(real)
        pkg, pkgver, ev = lookup_pkg(inv.pm, real, orig)
        inv.bins.append({"path": real, "ver": ver, "built": built, "pkg": pkg, "pkgver": pkgver, "ev": ev})

    mods = set(proc_libs)
    for g in MOD_GLOBS:
        mods.update(glob.glob(g))
    for m in sorted(mods):
        if not os.path.isfile(m):
            continue
        real = os.path.realpath(m)
        pkg, pkgver, ev = lookup_pkg(inv.pm, real, m)
        ver = ""
        try:
            with open(real, "rb") as fh:
                hit = re.search(rb"PHP/(\d+\.\d+\.\d+)", fh.read())
            ver = hit.group(1).decode() if hit else ""
        except OSError:
            pass
        inv.mods.append({"path": real, "ver": ver, "pkg": pkg, "pkgver": pkgver, "ev": ev,
                         "loaded": "1" if m in proc_libs else "0"})
    inv.complete = True
    return inv


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

COLOURS = {PATCHED: "32", VULNERABLE: "31", NEEDS_REVIEW: "33", "NO PHP FOUND": "36"}


def render_text(findings: List[Finding], notes: List[str], over: str, colour: bool) -> str:
    def c(label: str, code: Optional[str] = None) -> str:
        code = code or COLOURS.get(label, "0")
        return "\033[1;%sm%s\033[0m" % (code, label) if colour else label

    lines = ["php2shell-audit: PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
             "Read-only check of this machine. Nothing is sent anywhere.", ""]
    for f in findings:
        lines.append("[%s] %s%s" % (c(f.verdict), f.subject, " (PHP %s)" % f.version if f.version and f.kind in ("binary", "module") else ""))
        lines.append("    " + f.reason)
        for cmd in f.fix:
            lines.append("      $ " + cmd if not cmd.startswith("#") else "      " + cmd)
        lines.append("")
    for n in notes:
        lines.append("note: " + n)
    if notes:
        lines.append("")
    lines.append("Overall: " + c(over))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check this machine for the PHP2Shell fix (read-only).")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true")
    ap.add_argument("--input", metavar="FILE",
                    help="judge a saved collect.sh block (use - for stdin) instead of inspecting this machine")
    args = ap.parse_args(argv)

    if args.input:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8", errors="replace").read()
        inv = parse_collector(text)
    else:
        inv = collect_live()
    findings, notes = findings_from_inventory(inv)
    over, code = overall(findings)

    if args.json:
        print(json.dumps({"tool": "php2shell-audit", "cves": ["CVE-2026-109618", "CVE-2026-109619"],
                          "overall": over, "exit_code": code, "os": inv.os, "package_manager": inv.pm,
                          "findings": [f.as_dict() for f in findings], "notes": notes}, indent=2))
    else:
        colour = not args.no_colour and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render_text(findings, notes, over, colour))
        if code == 3:
            print("No PHP binary, module or web process found in the usual places.")
    return code


if __name__ == "__main__":
    sys.exit(main())
