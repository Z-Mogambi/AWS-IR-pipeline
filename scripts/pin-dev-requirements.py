#!/usr/bin/env python3
"""Regenerate requirements-dev.txt with hashes for every pinned version.

Hashes are taken from PyPI's own metadata for each exact version, covering
every distribution it publishes - source and all wheels. That matters because
`pip download` on a developer's machine only fetches wheels for that platform,
and a Linux CI runner would then fail hash checking on a manylinux wheel that
was never listed.

    python scripts/pin-dev-requirements.py

Bumping a version means editing PINS below and re-running this. Do not hand-edit
requirements-dev.txt.
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# name, version, optional note rendered as a comment above the entry
PINS = [
    ("pytest", "9.1.1", "test runner"),
    ("iniconfig", "2.3.0", None),
    ("packaging", "26.3", None),
    ("pluggy", "1.6.0", None),
    ("pygments", "2.21.0", None),
    ("aws-sam-translator", "1.113.0",
     "runs the SAM transform offline in tests/test_template.py"),
    ("attrs", "26.1.0", None),
    ("jsonschema", "4.26.0", None),
    ("jsonschema-specifications", "2025.9.1", None),
    ("referencing", "0.37.0", None),
    ("rpds-py", "2026.6.3", None),
    ("pydantic", "2.13.5", None),
    ("pydantic-core", "2.46.5", None),
    ("annotated-types", "0.8.0", None),
    ("typing-extensions", "4.16.0", None),
    ("typing-inspection", "0.4.4", None),
    ("pyyaml", "6.0.3", None),
    ("boto3", "1.42.33",
     "only for botocore's Stubber in tests; the runtime supplies its own"),
    ("botocore", "1.42.97", None),
    ("jmespath", "1.1.0", None),
    ("python-dateutil", "2.9.0.post0", None),
    ("s3transfer", "0.16.1", None),
    ("six", "1.17.0", None),
    ("urllib3", "2.8.0", None),
]

HEADER = """# Development and CI dependencies. Hash-pinned; install with:
#
#     pip install --require-hashes -r requirements-dev.txt
#
# None of this reaches a Lambda. The functions import only the standard
# library plus the boto3 and botocore already present in the runtime, which
# is asserted by tests/test_supply_chain.py. boto3 appears below solely so
# the test suite can use botocore's Stubber.
#
# Hashes cover every distribution PyPI publishes for each pinned version, so
# the file works on a developer's machine and on a Linux CI runner alike.
# Regenerate with scripts/pin-dev-requirements.py after changing a version.
"""


def digests_for(name, version):
    raw = subprocess.run(
        ["curl", "-sS", "-m", "30", f"https://pypi.org/pypi/{name}/{version}/json"],
        capture_output=True, text=True, check=True,
    ).stdout
    urls = json.loads(raw)["urls"]
    found = sorted({entry["digests"]["sha256"] for entry in urls})
    if not found:
        raise SystemExit(f"PyPI lists no distributions for {name}=={version}")
    return found


def main():
    lines = [HEADER]
    for name, version, note in PINS:
        digests = digests_for(name, version)
        if note:
            lines.append(f"# {note}")
        entry = f"{name}=={version}"
        for digest in digests:
            entry += f" \\\n    --hash=sha256:{digest}"
        lines.append(entry)
        print(f"{name:28s} {version:14s} {len(digests):3d} hashes", file=sys.stderr)

    (ROOT / "requirements-dev.txt").write_text("\n".join(lines) + "\n")
    print("wrote requirements-dev.txt", file=sys.stderr)


if __name__ == "__main__":
    main()
