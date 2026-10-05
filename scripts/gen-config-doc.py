#!/usr/bin/env python3
"""Generate docs/configuration.md from src/config.py - the one reference for env vars.

Every environment variable the monitor reads is listed in config.py order with its
default and the comment block right above it. Run after changing config.py:
    python3 scripts/gen-config-doc.py
pre-commit runs it with --check and fails when the doc is out of date.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "config.py"
OUT = ROOT / "docs" / "configuration.md"

# env var name and its default, for the readers config.py uses
READ_RE = re.compile(
    r'(?:os\.environ\.get|parse_env_int|parse_env_float|parse_env_bool|parse_env_thinking_level)'
    r'\(\s*"([A-Z][A-Z0-9_]+)"\s*(?:,\s*([^,)\n]+))?'
)
HOURS_RE = re.compile(r'_parse_hour_list\("([A-Z][A-Z0-9_]+)"\)')


def comment_above(lines: list[str], index: int) -> str:
    """The contiguous '#' comment block right above line `index`, joined into one line."""
    out = []
    i = index - 1
    while i >= 0 and lines[i].lstrip().startswith("#"):
        out.append(lines[i].lstrip().lstrip("#").strip())
        i -= 1
    return " ".join(reversed(out)).replace("|", "\\|")


def build() -> str:
    lines = SRC.read_text().splitlines()
    rows, seen = [], set()
    for i, line in enumerate(lines):
        found = [(m.group(1), (m.group(2) or "").strip()) for m in READ_RE.finditer(line)]
        found += [(m.group(1), '""') for m in HOURS_RE.finditer(line)]
        if not found and i + 1 < len(lines):
            # a call split over two lines: name on the next line
            m = READ_RE.search(line + " " + lines[i + 1].strip())
            if m and line.rstrip().endswith("("):
                found = [(m.group(1), (m.group(2) or "").strip())]
        start = i
        while start > 0 and lines[start - 1].strip() and not lines[start - 1].lstrip().startswith("#") \
                and lines[start - 1].startswith((" ", ")")):
            start -= 1
        for name, default in found:
            if name in seen:
                continue
            seen.add(name)
            fallback = re.match(r'os\.environ\.get\("([A-Z][A-Z0-9_]+)"', default)
            if fallback:
                # the default is another variable: name it, and list that one too
                default_cell = f"falls back to `{fallback.group(1)}`"
                found.append((fallback.group(1), '""'))
            else:
                default_cell = f"`{default.rstrip(')').strip()}`" if default else "_(empty)_"
            rows.append(f"| `{name}` | {default_cell} | {comment_above(lines, start) or ''} |")
    header = [
        "# Configuration reference",
        "",
        "Generated from `src/config.py` by `scripts/gen-config-doc.py` - do not edit by hand.",
        "Every variable, its default and the comment that explains it, in the order of config.py.",
        "Features marked off by default (feature gates) are not used on the SafeOps course platform",
        "unless the course says so.",
        "",
        "| Variable | Default | Notes |",
        "|---|---|---|",
    ]
    return "\n".join(header + rows) + "\n"


def main() -> int:
    content = build()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != content:
            print(f"{OUT.relative_to(ROOT)} is out of date: run python3 scripts/gen-config-doc.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(content)
    print(f"wrote {OUT.relative_to(ROOT)} ({content.count(chr(10)) - 9} variables)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
