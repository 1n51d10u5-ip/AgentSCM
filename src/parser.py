"""
parser.py
---------
Stage 1: Reads a requirements.txt file and returns a clean,
normalized list of packages with name and version.

Handles:
- Standard pinned versions:     requests==2.28.1
- Minimum version specs:        flask>=2.0.0
- Comments and blank lines
- Packages with no version specified
- Editable installs (-e .) are skipped
"""

import re
from pathlib import Path


def parse_requirements(file_path: str) -> list[dict]:
    """
    Parse a requirements.txt file into a list of package dicts.

    Args:
        file_path: Path to requirements.txt

    Returns:
        List of dicts like:
        [
            {
                "name": "requests",
                "version": "2.28.1",
                "version_spec": "==",   # the operator used, e.g. ==, >=, <=
                "raw_line": "requests==2.28.1",
                "pinned": True          # True only if exact version (==)
            },
            ...
        ]

    Raises:
        FileNotFoundError: if the file doesn't exist
        ValueError: if the file is empty or has no parseable packages
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    packages = []
    skipped = []

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        raise ValueError(f"File is empty: {file_path}")

    for raw_line in lines:
        line = raw_line.strip()

        # Skip blank lines, comments, and options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Skip editable installs like: -e .
        if line.startswith("-e"):
            skipped.append(line)
            continue

        # Skip VCS/URL-based installs like: git+https://...
        if line.startswith("git+") or line.startswith("http"):
            skipped.append(line)
            continue

        # Remove inline comments e.g. requests==2.28.1  # pinned for security
        if " #" in line:
            line = line.split(" #")[0].strip()

        # Parse name and version using regex
        # Matches: name[extras] operator version
        # e.g.: requests==2.28.1, flask>=2.0.0, numpy, Pillow[imaging]>=9.0
        pattern = r"^([A-Za-z0-9_\-\.]+)(\[.*?\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_\-\.\*]*)$"
        match = re.match(pattern, line)

        if not match:
            skipped.append(line)
            continue

        name_raw = match.group(1)
        version_spec = match.group(3) or ""
        version = match.group(4) or ""

        # Normalize package name: lowercase, hyphens (PyPI canonical form)
        name = name_raw.lower().replace("_", "-")

        packages.append({
            "name": name,
            "version": version if version else None,
            "version_spec": version_spec if version_spec else None,
            "raw_line": raw_line.strip(),
            "ecosystem": "pypi",
            "is_direct": True,  # requirements.txt entries are all direct by convention
            "pinned": version_spec == "==" and bool(version)
        })

    if not packages:
        raise ValueError("No parseable packages found in the file.")

    return packages, skipped


def summarize_parse(packages: list[dict], skipped: list[str]) -> None:
    """Print a human-readable summary of what was parsed."""

    print(f"\n{'='*50}")
    print(f"  DEPENDENCY THREAT MONITOR — Parser Output")
    print(f"{'='*50}")
    print(f"  Total packages found : {len(packages)}")
    print(f"  Pinned (exact ==)    : {sum(1 for p in packages if p['pinned'])}")
    print(f"  Unpinned / flexible  : {sum(1 for p in packages if not p['pinned'])}")
    print(f"  Skipped lines        : {len(skipped)}")
    print(f"{'='*50}\n")

    print(f"  {'PACKAGE':<30} {'VERSION':<15} {'PINNED'}")
    print(f"  {'-'*30} {'-'*15} {'-'*6}")
    for p in packages:
        version_display = f"{p['version_spec']}{p['version']}" if p['version'] else "not specified"
        pinned_display = "yes" if p['pinned'] else "no"
        print(f"  {p['name']:<30} {version_display:<15} {pinned_display}")

    if skipped:
        print(f"\n  Skipped lines (not parsed):")
        for s in skipped:
            print(f"    - {s}")

    print()


# ── quick manual test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    file = sys.argv[1] if len(sys.argv) > 1 else "data/samples/requirements.txt"

    try:
        packages, skipped = parse_requirements(file)
        summarize_parse(packages, skipped)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
