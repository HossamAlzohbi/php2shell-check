"""The web page re-implements the verdict logic in JS. Run it under node and compare."""
import json
import re
import shutil
import subprocess

import pytest

from test_parsing import APK, COLLECTED, DPKG_DEBIAN, DPKG_UBUNTU, PHP_V, RPM_ALMA, RPM_REMI
from test_verdicts import CASES

node = shutil.which("node")
pytestmark = pytest.mark.skipif(node is None, reason="node not installed")


def _run_js(root, expr_js):
    html = (root / "docs" / "index.html").read_text()
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    prog = "var module={exports:{}};\n%s\nconst P=module.exports;\nconsole.log(JSON.stringify(%s));" % (script, expr_js)
    r = subprocess.run([node, "-e", prog], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_verdict_table_matches_python(audit, root):
    args = json.dumps([[v, p, f, e] for v, p, f, e, _ in CASES])
    got = _run_js(root, "%s.map(a=>P.judge(a[0],a[1],a[2],a[3])[0])" % args)
    assert got == [exp for *_, exp in CASES]


@pytest.mark.parametrize("text", [DPKG_UBUNTU, DPKG_DEBIAN, RPM_ALMA, RPM_REMI, APK, PHP_V, COLLECTED])
def test_analyse_matches_python(audit, root, text):
    js = _run_js(root, "(()=>{const r=P.analyse(%s);return {o:r.overall,c:r.exitCode,f:r.findings.map(f=>[f.subject,f.verdict])}})()"
                 % json.dumps(text))
    if "#P2S1" in text:
        fs, _ = audit.findings_from_inventory(audit.parse_collector(text))
    else:
        fs = audit.findings_from_php_v(audit.parse_php_v(text)) + audit.findings_from_packages(audit.parse_packages(text))
    over, code = audit.overall(fs)
    assert js["o"] == over and js["c"] == code
    assert js["f"] == [[f.subject, f.verdict] for f in fs]
