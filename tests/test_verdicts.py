"""The verdict table. Every row here is also mirrored in test_js_parity.py."""
import pytest

# (version, packaged, family, evidence, expected)
CASES = [
    ("8.3.36", False, None, None, "PATCHED"),                  # upstream fix, no distro
    ("8.3.6", True, "backporting", True, "PATCHED"),           # old number, changelog proves fix
    ("8.3.6", True, "backporting", False, "NEEDS REVIEW"),     # package, no proof
    ("8.3.6", True, "backporting", None, "NEEDS REVIEW"),      # package, no changelog at all
    ("8.3.6", False, None, None, "VULNERABLE"),                # self-compiled
    ("8.1.34", False, None, None, "VULNERABLE"),               # backport-only branch, nothing applied
    ("8.1.34", True, "backporting", True, "PATCHED"),          # backport-only branch, with backport
    ("8.1.34", False, None, True, "PATCHED"),
    ("8.5.11", False, None, None, "VULNERABLE"),
    ("8.5.12", False, None, None, "PATCHED"),
    ("7.2.1", False, None, None, "VULNERABLE"),
    # branch boundaries
    ("8.4.26", False, None, None, "VULNERABLE"),
    ("8.4.27", False, None, None, "PATCHED"),
    ("8.2.34", False, None, None, "VULNERABLE"),
    ("8.2.35", False, None, None, "PATCHED"),
    ("8.6.0", False, None, None, "PATCHED"),
    # Debian/Alpine ship upstream numbers: the version is trustworthy
    ("8.2.34", True, "upstream", False, "VULNERABLE"),
    ("8.2.35", True, "upstream", None, "PATCHED"),
    # Sury backports into EOL 8.1 and keeps 8.1.34: changelog proof must win over the
    # "upstream numbering" family shortcut. Without proof it is a review, never a false alarm.
    ("8.1.34", True, "upstream", True, "PATCHED"),
    ("8.1.34", True, "upstream", False, "NEEDS REVIEW"),
    ("8.3.14", True, "upstream", True, "PATCHED"),             # supported branch, upstream family, but backport proven
    # EOL with no fix anywhere, packaged, no proof
    ("7.2.1", True, "backporting", False, "VULNERABLE"),
    ("7.2.1", True, "backporting", True, "PATCHED"),
    # unknown distro keeps the benefit of the doubt
    ("8.3.6", True, None, False, "NEEDS REVIEW"),
    # php -v alone: never concludes patched for a low number, never VULNERABLE
    ("8.3.6", None, None, None, "NEEDS REVIEW"),
    ("8.3.36", None, None, None, "PATCHED"),
    ("8.5.11", None, None, None, "NEEDS REVIEW"),
    # unreadable
    ("garbage", False, None, None, "NEEDS REVIEW"),
]


@pytest.mark.parametrize("version,packaged,family,evidence,expected", CASES)
def test_verdict_table(audit, version, packaged, family, evidence, expected):
    verdict, reason = audit.judge(version, packaged, family, evidence)
    assert verdict == expected, reason
    assert reason


def test_epoch_and_distro_suffix_versions_parse(audit):
    assert audit.parse_version("1:8.3.6-0ubuntu0.24.04.12") == (8, 3, 6)
    assert audit.parse_version("8.3.14-r0") == (8, 3, 14)
    assert audit.parse_version("2:8.3+93ubuntu2") is None   # metapackage


@pytest.mark.parametrize("name", ["php", "php8.3", "php83", "php-fpm", "php-fpm8.3", "php-cgi",
                                  "lsphp", "lsphp83", "frankenphp", "php7.4"])
def test_binary_allowlist_accepts(audit, name):
    assert audit.BIN_RE.match(name)


@pytest.mark.parametrize("name", ["php-config", "php-config8.3", "phpize", "phpize8.3", "phpenmod",
                                  "phpdismod", "phpquery", "phpdbg", "phpdbg8.3", "php.ini",
                                  "php8.3.bak", "phpunit", "php-fpm.conf"])
def test_binary_allowlist_rejects(audit, name):
    assert not audit.BIN_RE.match(name)


def test_family_classification(audit):
    c = audit.classify_family
    assert c("php8.3-cli", "8.3.6-0ubuntu0.24.04.12") == "backporting"
    assert c("php8.2-cli", "8.2.28-1~deb12u1") == "upstream"
    assert c("php8.3-cli", "8.3.14-1+ubuntu22.04.1+deb.sury.org+1") == "upstream"   # sury beats ubuntu
    assert c("php-cli", "8.3.6-1.el9_4.alma") == "backporting"
    assert c("php83-php-cli", "8.3.14-1.el9.remi") == "upstream"
    assert c("php83-fpm", "8.3.14-r0") == "upstream"
    assert c("php-cli", "8.3.6-1", "ubuntu") == "backporting"
    assert c("php-cli", "8.3.6-1", "debian") == "upstream"
    assert c("php-cli", "8.3.6-1") is None


def test_overall_exit_codes(audit):
    F = audit.Finding
    assert audit.overall([])[1] == 3
    assert audit.overall([F("binary", "a", "PATCHED", "")])[1] == 0
    assert audit.overall([F("binary", "a", "PATCHED", ""), F("binary", "b", "NEEDS REVIEW", "")])[1] == 2
    assert audit.overall([F("binary", "a", "NEEDS REVIEW", ""), F("binary", "b", "VULNERABLE", "")])[1] == 1


def test_sury_eol_branch_with_changelog_proof_is_patched(audit):
    """End to end through the collector block, family derived from the Sury version string."""
    block = (
        "#P2S1\nos|id=ubuntu|ver=22.04|name=Ubuntu 22.04\npm|name=dpkg\nuser|root=1\n"
        "bin|path=/usr/bin/php8.1|ver=8.1.34|built=Oct 1 2026|pkg=php8.1-cli"
        "|pkgver=8.1.34-1+ubuntu22.04.1+deb.sury.org+2|ev=yes:CVE-2026-109618 backport\nend|ok\n")
    fs, _ = audit.findings_from_inventory(audit.parse_collector(block))
    assert [f.verdict for f in fs] == ["PATCHED"]
    nobody = block.replace("ev=yes:CVE-2026-109618 backport", "ev=no")
    fs, _ = audit.findings_from_inventory(audit.parse_collector(nobody))
    assert fs[0].verdict == "NEEDS REVIEW"
