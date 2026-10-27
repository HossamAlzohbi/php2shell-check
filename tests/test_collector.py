"""Run the real collect.sh against a fake PHP tree and feed it to the parser."""
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")


def _fake_tree(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    for name in ["php8.3", "php-fpm8.3", "php-config", "php-config8.3", "phpize", "phpdbg",
                 "phpenmod", "phpquery", "lsphp83", "php.ini", "phpunit"]:
        p = b / name
        p.write_text('#!/bin/sh\necho "PHP 8.3.6 (cli) (built: Jun  5 2026 10:01:02) ( NTS )"\n')
        p.chmod(0o755)
    (b / "php").symlink_to("php8.3")
    return b


def test_collector_output_and_allowlist(audit, root, tmp_path):
    b = _fake_tree(tmp_path)
    env = dict(os.environ, PATH="%s:/usr/bin:/bin" % b)
    out = subprocess.run(["sh", str(root / "collect.sh")], env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, universal_newlines=True, timeout=60).stdout
    assert out.startswith("#P2S1\n") and out.rstrip().endswith("end|ok")
    inv = audit.parse_collector(out)
    names = sorted(os.path.basename(x["path"]) for x in inv.bins if x["path"].startswith(str(b)))
    assert names == ["lsphp83", "php-fpm8.3", "php8.3"]       # `php` symlink de-duplicated, helpers rejected
    for x in inv.bins:
        if x["path"].startswith(str(b)):
            assert x["ver"] == "8.3.6" and x["built"] == "Jun 5 2026" and x["pkg"] == ""
    fs, _ = audit.findings_from_inventory(inv)
    ours = [f for f in fs if f.subject.startswith(str(b))]
    assert ours and all(f.verdict == "VULNERABLE" for f in ours)   # unpackaged 8.3.6


def test_collector_is_posix_and_read_only(root):
    src = "\n".join(l for l in (root / "collect.sh").read_text().splitlines() if not l.lstrip().startswith("#"))
    for banned in ("sudo", "rm ", "curl", "wget", "nc ", "> /", "tee ", "chmod", "mv "):
        assert banned not in src, banned
    for sh in ("dash", "bash"):
        if shutil.which(sh):
            assert subprocess.run([sh, "-n", str(root / "collect.sh")]).returncode == 0


def test_page_embeds_current_collector(root):
    r = subprocess.run([sys.executable, str(root / "tools" / "sync_collector.py"), "--check"])
    assert r.returncode == 0, "run: python3 tools/sync_collector.py"
