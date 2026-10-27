#!/usr/bin/env python3
"""Embed collect.sh into docs/index.html, wrapped so it pastes as ONE command.

    python3 tools/sync_collector.py          # rewrite the page
    python3 tools/sync_collector.py --check  # exit 1 if the page is stale
"""
import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
START, END = "<!--COLLECTOR-START-->", "<!--COLLECTOR-END-->"


def wrapped() -> str:
    script = (ROOT / "collect.sh").read_text(encoding="utf-8").rstrip("\n")
    assert "\nP2S\n" not in "\n" + script + "\n", "collect.sh must not contain the heredoc delimiter"
    return "sh -c \"$(cat <<'P2S'\n%s\nP2S\n)\"" % script


def render(page: str) -> str:
    pat = re.compile(re.escape(START) + ".*?" + re.escape(END), re.S)
    return pat.sub(lambda _: START + html.escape(wrapped(), quote=False) + END, page)


if __name__ == "__main__":
    path = ROOT / "docs" / "index.html"
    old = path.read_text(encoding="utf-8")
    new = render(old)
    if "--check" in sys.argv:
        sys.exit(0 if old == new else 1)
    path.write_text(new, encoding="utf-8")
