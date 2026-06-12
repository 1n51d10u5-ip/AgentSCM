"""
parser_npm.py
-------------
Parses npm lockfiles into the same normalized format used by parser.py,
so the rest of the pipeline (enricher, scorer, remediation) works
identically regardless of ecosystem.

Supports:
  - package-lock.json (v2/v3 format — npm 7+)
  - package.json (fallback — direct dependencies only, version ranges)

Every package dict includes an "ecosystem" field ("pypi" or "npm") so
downstream stages (especially remediation) know which registry to query.
"""

import json
from pathlib import Path


def parse_package_lock(file_path: str) -> tuple[list[dict], list[str]]:
    """
    Parse package-lock.json (lockfile v2/v3, npm 7+).

    Returns (packages, skipped) — same shape as parse_requirements().

    Each package dict:
        {
            "name": "axios",
            "version": "0.21.1",
            "version_spec": "==",   # lockfile versions are always exact/resolved
            "raw_line": "axios@0.21.1",
            "pinned": True,         # lockfile entries are always pinned (resolved)
            "ecosystem": "npm",
            "is_direct": bool,      # True if listed in root package.json dependencies
        }
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {file_path}: {e}")

    lockfile_version = data.get("lockfileVersion", 0)
    packages_section = data.get("packages")

    if lockfile_version < 2 or packages_section is None:
        raise ValueError(
            f"Unsupported lockfile version ({lockfile_version}). "
            f"AgentSCM requires npm lockfile v2 or v3 (npm 7+). "
            f"Run 'npm install' with a recent npm version to regenerate."
        )

    # Direct dependencies are listed under the root "" package entry
    root = packages_section.get("", {})
    direct_deps = set(root.get("dependencies", {}).keys())
    direct_deps |= set(root.get("devDependencies", {}).keys())

    packages = []
    skipped = []
    seen = set()  # avoid duplicate entries for nested same-version deps

    for pkg_path, pkg_info in packages_section.items():
        if pkg_path == "":
            continue  # skip root entry itself

        # node_modules/axios -> axios
        # node_modules/@scope/name -> @scope/name
        if not pkg_path.startswith("node_modules/"):
            skipped.append(pkg_path)
            continue

        name = pkg_path.replace("node_modules/", "", 1)
        # Handle nested deps: node_modules/foo/node_modules/bar -> bar
        if "node_modules/" in name:
            name = name.split("node_modules/")[-1]

        version = pkg_info.get("version")
        if not version:
            skipped.append(pkg_path)
            continue

        key = (name, version)
        if key in seen:
            continue
        seen.add(key)

        packages.append({
            "name": name,
            "version": version,
            "version_spec": "==",
            "raw_line": f"{name}@{version}",
            "pinned": True,
            "ecosystem": "npm",
            "is_direct": name in direct_deps,
        })

    if not packages:
        raise ValueError("No parseable packages found in the lockfile.")

    return packages, skipped


def parse_package_json(file_path: str) -> tuple[list[dict], list[str]]:
    """
    Fallback parser for package.json (no lockfile available).
    Only sees direct dependencies with version ranges (e.g. ^1.2.3) —
    less accurate than package-lock.json since exact resolved versions
    aren't known.

    Returns (packages, skipped).
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {file_path}: {e}")

    packages = []
    skipped = []

    for dep_group in ("dependencies", "devDependencies"):
        deps = data.get(dep_group, {})
        for name, version_range in deps.items():
            # Strip range prefixes: ^1.2.3, ~1.2.3, >=1.2.3 -> 1.2.3
            cleaned = version_range.lstrip("^~>=< ")

            if not cleaned or cleaned in ("*", "latest"):
                skipped.append(f"{name}: {version_range}")
                packages.append({
                    "name": name,
                    "version": None,
                    "version_spec": None,
                    "raw_line": f"{name}: {version_range}",
                    "pinned": False,
                    "ecosystem": "npm",
                    "is_direct": True,
                })
                continue

            packages.append({
                "name": name,
                "version": cleaned,
                "version_spec": "==" if version_range[0] not in "^~>=<" else "~=",
                "raw_line": f"{name}: {version_range}",
                "pinned": version_range[0] not in "^~>=<",
                "ecosystem": "npm",
                "is_direct": True,
            })

    if not packages:
        raise ValueError("No dependencies found in package.json.")

    return packages, skipped


# ── Quick test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    file = sys.argv[1] if len(sys.argv) > 1 else "data/samples/package-lock.json"

    try:
        if file.endswith("package-lock.json"):
            packages, skipped = parse_package_lock(file)
        else:
            packages, skipped = parse_package_json(file)

        print(f"\n{'='*60}")
        print(f"  AgentSCM — npm Parser Output")
        print(f"{'='*60}")
        print(f"  Total packages : {len(packages)}")
        print(f"  Direct deps    : {sum(1 for p in packages if p.get('is_direct'))}")
        print(f"  Transitive     : {sum(1 for p in packages if not p.get('is_direct'))}")
        print(f"  Skipped        : {len(skipped)}")
        print(f"{'='*60}\n")

        print(f"  {'PACKAGE':<25} {'VERSION':<12} {'DIRECT':<8}")
        print(f"  {'-'*25} {'-'*12} {'-'*8}")
        for p in packages[:20]:
            direct = "yes" if p.get("is_direct") else "no"
            print(f"  {p['name']:<25} {p['version']:<12} {direct:<8}")

        if len(packages) > 20:
            print(f"  ... and {len(packages) - 20} more")

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
