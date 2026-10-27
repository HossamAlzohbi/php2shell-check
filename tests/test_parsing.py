"""Parsing of real dpkg / rpm / apk / php -v output and the collector block."""

DPKG_UBUNTU = """\
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                       Version                        Architecture Description
+++-==========================-==============================-============-=========================================
ii  libapache2-mod-php8.3      1:8.3.6-0ubuntu0.24.04.12      amd64        server-side, HTML-embedded scripting language (Apache 2 module)
ii  php-common                 2:93ubuntu2                    all          Common files for PHP packages
ii  php8.3-cli                 8.3.6-0ubuntu0.24.04.12        amd64        command-line interpreter for the PHP scripting language
ii  php8.3-common              8.3.6-0ubuntu0.24.04.12        amd64        documentation, examples and common module for PHP
ii  php8.3-fpm                 8.3.6-0ubuntu0.24.04.12        amd64        server-side, HTML-embedded scripting language (FPM-CGI binary)
ii  php8.3-mysql               8.3.6-0ubuntu0.24.04.12        amd64        MySQL module for PHP
rc  php8.1-cli                 8.1.2-1ubuntu2.19              amd64        command-line interpreter for the PHP scripting language
ii  php-cli                    2:8.3+93ubuntu2                all          command-line interpreter for the PHP scripting language (default)
"""

DPKG_DEBIAN = """\
ii  php8.2-cli:amd64   8.2.28-1~deb12u1   amd64   command-line interpreter for the PHP scripting language
ii  php8.2-fpm:amd64   8.2.35-1~deb12u1   amd64   server-side, HTML-embedded scripting language (FPM-CGI binary)
"""

RPM_ALMA = """\
php-common-8.3.6-1.el9_4.x86_64
php-cli-8.3.6-1.el9_4.x86_64
php-fpm-8.3.6-1.el9_4.x86_64
php-mysqlnd-8.3.6-1.el9_4.x86_64
php-pear-1.10.15-1.el9.noarch
"""

RPM_REMI = """\
php83-php-cli-8.3.14-1.el9.remi.x86_64
php83-php-fpm-8.3.14-1.el9.remi.x86_64
"""

APK = """\
php83-8.3.14-r0
php83-fpm-8.3.14-r0
php83-common-8.3.14-r0
php83-pecl-redis-6.1.0-r0
"""

PHP_V = """\
PHP 8.3.6 (cli) (built: Jun 12 2026 10:01:02) ( NTS )
Copyright (c) The PHP Group
Zend Engine v4.3.6, Copyright (c) Zend Technologies
    with Zend OPcache v8.3.6, Copyright (c), by Zend Technologies
"""


def _by_name(pkgs):
    return {p["name"]: p for p in pkgs}


def test_dpkg_ubuntu(audit):
    pkgs = _by_name(audit.parse_packages(DPKG_UBUNTU))
    assert pkgs["php8.3-cli"]["version"] == "8.3.6-0ubuntu0.24.04.12"
    assert pkgs["php8.3-cli"]["pm"] == "dpkg"
    assert pkgs["libapache2-mod-php8.3"]["version"] == "1:8.3.6-0ubuntu0.24.04.12"
    assert "php8.1-cli" not in pkgs                      # 'rc' = removed, config left
    assert "Desired=Unknown/Install/Remove/Purge/Hold" not in str(pkgs)


def test_dpkg_ubuntu_findings(audit):
    fs = audit.findings_from_packages(audit.parse_packages(DPKG_UBUNTU))
    names = {f.extra["pkg"]: f for f in fs}
    assert set(names) == {"libapache2-mod-php8.3", "php8.3-cli", "php8.3-fpm"}   # no -common/-mysql/meta
    assert all(f.verdict == "NEEDS REVIEW" for f in fs)                          # php -v style number, no proof
    assert any("apt-get" in c for c in names["php8.3-cli"].fix)
    assert any("restart php8.3-fpm" in c for c in names["php8.3-fpm"].fix)
    assert any("restart apache2" in c for c in names["libapache2-mod-php8.3"].fix)


def test_dpkg_debian_arch_suffix_and_upstream_numbers(audit):
    pkgs = audit.parse_packages(DPKG_DEBIAN)
    assert [p["name"] for p in pkgs] == ["php8.2-cli", "php8.2-fpm"]
    v = {f.extra["pkg"]: f.verdict for f in audit.findings_from_packages(pkgs)}
    assert v == {"php8.2-cli": "VULNERABLE", "php8.2-fpm": "PATCHED"}


def test_rpm_alma(audit):
    pkgs = audit.parse_packages(RPM_ALMA)
    byn = _by_name(pkgs)
    assert byn["php-cli"]["version"] == "8.3.6-1.el9_4"
    assert byn["php-cli"]["pm"] == "rpm"
    assert byn["php-pear"]["version"] == "1.10.15-1.el9"
    fs = audit.findings_from_packages(pkgs)
    assert {f.extra["pkg"] for f in fs} == {"php-cli", "php-fpm"}                 # php-common/mysqlnd/pear skipped
    assert all(f.verdict == "NEEDS REVIEW" for f in fs)
    assert any("dnf upgrade" in c for c in fs[0].fix)


def test_rpm_remi_is_upstream_numbered(audit):
    fs = audit.findings_from_packages(audit.parse_packages(RPM_REMI))
    assert {f.extra["pkg"] for f in fs} == {"php83-php-cli", "php83-php-fpm"}
    assert all(f.verdict == "VULNERABLE" for f in fs)                             # 8.3.14 < 8.3.36, remi tracks upstream
    assert any("php83-php-fpm" in c and "restart" in c for f in fs for c in f.fix)


def test_apk(audit):
    pkgs = audit.parse_packages(APK)
    assert _by_name(pkgs)["php83-fpm"] == {"name": "php83-fpm", "version": "8.3.14-r0", "pm": "apk"}
    fs = audit.findings_from_packages(pkgs)
    assert {f.extra["pkg"] for f in fs} == {"php83", "php83-fpm"}
    assert all(f.verdict == "VULNERABLE" for f in fs)


def test_apk_owner(audit):
    # Real `apk info -W <path>` output captured from alpine:3.21 with apk-installed php83.
    assert audit.parse_apk_owner("/usr/bin/php83 is owned by php83-8.3.36-r0") == ("php83", "8.3.36-r0")
    assert audit.parse_apk_owner("/usr/sbin/php-fpm83 is owned by php83-fpm-8.3.14-r0") == ("php83-fpm", "8.3.14-r0")
    # Unowned (self-compiled) binary: apk prints nothing matchable.
    assert audit.parse_apk_owner("") == ("", "")


def test_changelog_hit(audit):
    # Real-shape rpm changelog: the CVE citation is in the newest (top) entry.
    cl = (
        "* Mon Oct 19 2026 Remi Collet <rcollet@redhat.com> - 8.0.30-8.1\n"
        "- Avoid state corruption via bailout\n"
        "  CVE-2026-109618, CVE-2026-109619\n"
        "* Tue Jan 01 2019 Someone - 8.0.0-1\n"
        "- initial build\n"
    )
    assert audit.changelog_hit(cl) == "CVE-2026-109618, CVE-2026-109619"
    assert audit.changelog_hit("- nothing relevant here\n") is None
    # A citation sitting past the scan cap is deliberately not reached.
    buried = ("- filler\n" * 40000) + "  CVE-2026-109618\n"
    assert len(buried) > audit.MAX_CHANGELOG_BYTES
    assert audit.changelog_hit(buried) is None


def test_php_v(audit):
    (e,) = audit.parse_php_v(PHP_V)
    assert e == {"version": "8.3.6", "sapi": "cli", "built": "Jun 12 2026"}
    (f,) = audit.findings_from_php_v([e])
    assert f.verdict == "NEEDS REVIEW"                       # can never say "patched" for a low number
    assert "changelog" in f.reason
    (g,) = audit.findings_from_php_v(audit.parse_php_v(PHP_V.replace("8.3.6", "8.3.36")))
    assert g.verdict == "PATCHED"


COLLECTED = """\
#P2S1
os|id=ubuntu|ver=24.04|name=Ubuntu 24.04.2 LTS
pm|name=dpkg
user|root=0
bin|path=/usr/bin/php8.3|ver=8.3.6|built=Jun 12 2026|pkg=php8.3-cli|pkgver=8.3.6-0ubuntu0.24.04.13|ev=yes:  * SECURITY UPDATE: CVE-2026-109618 and CVE-2026-109619
bin|path=/usr/sbin/php-fpm8.3|ver=8.3.6|built=Jun 12 2026|pkg=php8.3-fpm|pkgver=8.3.6-0ubuntu0.24.04.12|ev=no
bin|path=/usr/local/bin/php|ver=8.3.6|built=Mar 1 2026|pkg=|pkgver=|ev=na
mod|path=/usr/lib/apache2/modules/libphp8.3.so|ver=8.3.6|pkg=libapache2-mod-php8.3|pkgver=8.3.6-0ubuntu0.24.04.12|ev=no|loaded=1
proc|comm=apache2|libphp=/usr/lib/apache2/modules/libphp8.3.so|stale=1|stalepath=/usr/lib/apache2/modules/libphp8.3.so|ro=0|n=11
proc|comm=php-fpm8.3|libphp=-|stale=0|stalepath=-|ro=1|n=5
end|ok
"""


def test_collector_block(audit):
    inv = audit.parse_collector("junk before\n" + COLLECTED)
    assert inv.os["id"] == "ubuntu" and inv.pm == "dpkg" and inv.is_root is False and inv.complete
    fs, notes = audit.findings_from_inventory(inv)
    by = {f.subject: f for f in fs}
    assert by["/usr/bin/php8.3"].verdict == "PATCHED"             # same 8.3.6, changelog proves it
    assert by["/usr/sbin/php-fpm8.3"].verdict == "NEEDS REVIEW"   # same number, package without proof
    assert by["/usr/local/bin/php"].verdict == "VULNERABLE"       # not owned by any package
    assert by["/usr/lib/apache2/modules/libphp8.3.so"].verdict == "NEEDS REVIEW"
    assert "mod_php" in by["/usr/lib/apache2/modules/libphp8.3.so"].reason
    stale = [f for f in fs if f.kind == "process"]
    assert len(stale) == 1 and stale[0].verdict == "NEEDS REVIEW" and "restart" in stale[0].reason.lower()
    assert any("php-fpm8.3" in n for n in notes)                   # unreadable maps note
    assert audit.overall(fs) == ("VULNERABLE", 1)


def test_truncated_collector_is_flagged(audit):
    inv = audit.parse_collector(COLLECTED.replace("end|ok\n", ""))
    _, notes = audit.findings_from_inventory(inv)
    assert any("truncated" in n for n in notes)


def test_cli_from_input_exit_code(audit, tmp_path, capsys):
    f = tmp_path / "block.txt"
    f.write_text(COLLECTED)
    assert audit.main(["--input", str(f), "--no-colour", "--json"]) == 1
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["exit_code"] == 1 and data["overall"] == "VULNERABLE"
    empty = tmp_path / "empty.txt"
    empty.write_text("#P2S1\nos|id=debian\npm|name=dpkg\nend|ok\n")
    assert audit.main(["--input", str(empty), "--no-colour"]) == 3
