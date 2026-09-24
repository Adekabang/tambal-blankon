#!/usr/bin/env python3
"""Tambal — BlankOn Linux security report.

Find packages in the BlankOn repository that are still behind Debian's
security fixes. Results are grouped per source package because a maintainer
imports a *package*, not an advisory or a CVE.

This rewrite replaces the old HTML-scraping approach with Debian's official,
structured security-tracker JSON export, so it no longer scrapes
security-tracker.debian.org (which rate-limits aggressive scrapers and breaks
whenever the markup changes).

Data sources:
  * https://security-tracker.debian.org/tracker/data/json
      (source package -> CVE -> per-release status + fixed version)
  * the target repository's Sources.gz index

Usage:
  python3 tambal.py --repo=http://arsip-dev.blankonlinux.id/sinambung/ \
                    --output=./advisories.json --html=./security-advisories
"""
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

TRACKER_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
TRACKER_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tracker.json")
SOURCE_URL = "https://github.com/blankon/tambal"
TRACKER_URL = "https://security-tracker.debian.org/tracker/"
DSA_URL = "https://www.debian.org/security/#DSAS"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd-cache.json")


def _load_env_file():
    """Load KEY=VALUE pairs from a .env file next to the script, if present."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"\''))


_load_env_file()

# Optional. Set NVD_API_KEY (environment or .env) to raise the rate limit
# (5 req/30s keyless -> 50 req/30s with a key). Never hardcode it here.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")


# ── helpers ───────────────────────────────────────────────────────────────────

# Cache for dpkg version comparisons: (a, b) -> bool, avoids repeated subprocess
# calls when many CVEs share the same fixed version.
_VERSION_CACHE = {}


def _fetch_raw(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def fetch_bytes(url):
    return _fetch_raw(url)


def fetch_text(url):
    return _fetch_raw(url).decode("utf-8")


def version_lt(v1, v2):
    """Return True if v1 < v2 using dpkg version comparison."""
    key = (v1, v2)
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    result = subprocess.run(
        ["dpkg", "--compare-versions", v1, "lt", v2],
        capture_output=True,
    )
    out = result.returncode == 0
    _VERSION_CACHE[key] = out
    return out


def max_version(versions):
    """Return the highest version string (dpkg ordering) from an iterable."""
    best = None
    for v in versions:
        if best is None or version_lt(best, v):
            best = v
    return best


# Severity: prefer the vendor rating embedded in the CVE description
# (e.g. "(Chromium security severity: Critical)"), fall back to Debian's
# per-release urgency (high/medium/low).
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def extract_severity(info):
    """Return a severity label ('Critical'/'High'/'Medium'/'Low') or None."""
    desc = info.get("description", "") or ""
    m = re.search(r"severity:\s*(\w+)", desc)
    if m:
        s = m.group(1).lower()
        if s in SEVERITY_RANK:
            return s.capitalize()
    best = None
    for relinfo in info.get("releases", {}).values():
        u = (relinfo.get("urgency") or "").lower()
        if u in ("high", "medium", "low"):
            if best is None or SEVERITY_RANK[u] > SEVERITY_RANK[best]:
                best = u
    return best.capitalize() if best else None


def max_severity(sevs):
    """Return the highest severity label from a list (or None)."""
    best = None
    for s in sevs:
        if not s:
            continue
        r = SEVERITY_RANK.get(s.lower())
        if r and (best is None or r > SEVERITY_RANK[best.lower()]):
            best = s
    return best


# ── NVD enrichment ────────────────────────────────────────────────────────────

def _nvd_delay():
    # Respect the rolling rate limit: 5 req/30s keyless, 50 req/30s with a key.
    # Sleep a little past the per-request average to stay safely under.
    return 0.7 if NVD_API_KEY else 7.0


def _load_nvd_cache():
    try:
        with open(NVD_CACHE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_nvd_cache(cache):
    with open(NVD_CACHE, "w") as f:
        json.dump(cache, f)


def _fetch_nvd(cve_id, cache):
    """Return {severity, published} for a CVE (or None), using/updating cache."""
    if cve_id in cache:
        return cache[cve_id]
    headers = {"User-Agent": "Mozilla/5.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url = f"{NVD_API_URL}?cveId={cve_id}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except Exception:
        cache[cve_id] = None
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        cache[cve_id] = None
        return None

    cve = vulns[0].get("cve", {})
    sev = None
    for mkey in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in cve.get("metrics", {}).get(mkey, []):
            bs = entry.get("cvssData", {}).get("baseSeverity")
            if bs:
                s = bs.upper()
                if sev is None or SEVERITY_RANK.get(s.lower(), 0) > SEVERITY_RANK.get(sev.lower(), 0):
                    sev = s

    result = {"severity": sev, "published": cve.get("published")}
    cache[cve_id] = result
    time.sleep(_nvd_delay())
    return result


def enrich_nvd(findings):
    """Add NVD severity + published date to each finding's CVEs (cached, throttled)."""
    cache = _load_nvd_cache()

    # cve_id -> list of CVE entries across all findings
    cve_map = {}
    for f in findings:
        for c in f["cves"]:
            cve_map.setdefault(c["id"], []).append(c)

    pending = list(cve_map.keys())
    print(f"Enriching {len(pending)} unique CVEs from NVD ...", file=sys.stderr)
    for i, cve_id in enumerate(pending, 1):
        nvd = _fetch_nvd(cve_id, cache)
        sev = nvd["severity"] if nvd else None
        pub = nvd["published"] if nvd else None
        for c in cve_map[cve_id]:
            c["nvd_severity"] = sev
            c["published"] = pub
        if i % 20 == 0:
            print(f"  [{i}/{len(pending)}]", file=sys.stderr)

    _save_nvd_cache(cache)

    # Recompute each finding's severity, preferring NVD over the Debian estimate.
    for f in findings:
        sevs = [c.get("nvd_severity") or c.get("severity") for c in f["cves"]]
        f["severity"] = max_severity(sevs)


# ── repo discovery ────────────────────────────────────────────────────────────

def discover_dists(repo_url):
    """Parse HTML directory listing at {repo}/dists/ and return dist names."""
    url = repo_url.rstrip("/") + "/dists/"
    html = fetch_text(url)
    names = re.findall(r'href="([^"/][^"]*/)"', html)
    return [n.rstrip("/") for n in names]


def fetch_release(repo_url, dist):
    """Return (codename, components list) from a Release file."""
    url = f"{repo_url.rstrip('/')}/dists/{dist}/Release"
    try:
        text = fetch_text(url)
    except Exception:
        return dist, []
    components = []
    for line in text.splitlines():
        if line.startswith("Components:"):
            components = line.split(":", 1)[1].strip().split()
            break
    return dist, components


def fetch_sources(repo_url, dist, component):
    """Fetch and parse Sources.gz; return dict of package -> version."""
    url = f"{repo_url.rstrip('/')}/dists/{dist}/{component}/source/Sources.gz"
    try:
        data = fetch_bytes(url)
    except Exception:
        return {}
    try:
        text = gzip.decompress(data).decode("utf-8")
    except Exception:
        return {}

    packages = {}
    current_pkg = None
    current_ver = None
    for line in text.splitlines():
        if line.startswith("Package:"):
            current_pkg = line.split(":", 1)[1].strip()
            current_ver = None
        elif line.startswith("Version:"):
            current_ver = line.split(":", 1)[1].strip()
            if current_pkg and current_ver:
                existing = packages.get(current_pkg)
                if existing is None or version_lt(existing, current_ver):
                    packages[current_pkg] = current_ver
    return packages


def build_package_index(repo_url):
    """Walk all dists/components and return package -> highest_version map."""
    print(f"Discovering dists at {repo_url} ...", file=sys.stderr)
    dists = discover_dists(repo_url)
    if not dists:
        print("Error: no dists found.", file=sys.stderr)
        sys.exit(1)
    print(f"  Found dists: {', '.join(dists)}", file=sys.stderr)

    index = {}
    for dist in dists:
        _, components = fetch_release(repo_url, dist)
        for component in components:
            print(f"  Fetching {dist}/{component}/source/Sources.gz ...", file=sys.stderr)
            pkgs = fetch_sources(repo_url, dist, component)
            for pkg, ver in pkgs.items():
                existing = index.get(pkg)
                if existing is None or version_lt(existing, ver):
                    index[pkg] = ver

    print(f"  Indexed {len(index)} source packages.", file=sys.stderr)
    return index


# ── tracker data ──────────────────────────────────────────────────────────────

def load_tracker(no_cache=False):
    """Download (and cache) the security-tracker JSON export."""
    if not no_cache and os.path.exists(TRACKER_CACHE):
        print(f"Using cached tracker data: {TRACKER_CACHE}", file=sys.stderr)
        with open(TRACKER_CACHE) as f:
            return json.load(f)

    print(f"Downloading {TRACKER_JSON_URL} ...", file=sys.stderr)
    data = fetch_bytes(TRACKER_JSON_URL)
    tracker = json.loads(data.decode("utf-8"))
    with open(TRACKER_CACHE, "w") as f:
        json.dump(tracker, f)
    print(f"  Cached {len(tracker)} packages to {TRACKER_CACHE}", file=sys.stderr)
    return tracker


# ── evaluate ──────────────────────────────────────────────────────────────────

def evaluate(package_index, tracker):
    """For each package in the repo, find CVEs whose sid fix is newer than ours.

    A package is flagged when at least one CVE is 'resolved' in sid at a version
    above what the repo ships (i.e. the repo is missing that security fix).
    """
    findings = []
    for pkg, our_ver in package_index.items():
        cves = tracker.get(pkg)
        if not cves:
            continue

        # fixed_version -> list of CVE ids resolved at that version in sid
        fixed_map = {}
        for cve, info in cves.items():
            if not isinstance(info, dict):
                continue
            sid = info.get("releases", {}).get("sid", {})
            if sid.get("status") != "resolved":
                continue
            fv = sid.get("fixed_version")
            if fv and fv != "0":
                fixed_map.setdefault(fv, []).append(cve)

        if not fixed_map:
            continue

        # Only versions strictly above ours mean we're missing a fix.
        vuln_versions = [fv for fv in fixed_map if version_lt(our_ver, fv)]
        if not vuln_versions:
            continue

        target = max_version(vuln_versions)

        cve_list = []
        for fv in vuln_versions:
            for cve in fixed_map[fv]:
                info = cves[cve]
                cve_list.append({
                    "id": cve,
                    "fixed_version": fv,
                    "description": info.get("description", ""),
                    "severity": extract_severity(info),
                })
        # Show highest-version CVEs first; cap the list for huge packages.
        cve_list.sort(key=lambda c: c["fixed_version"], reverse=True)
        cve_list = cve_list[:100]

        sev = max_severity([c["severity"] for c in cve_list])

        # Per-release fixed versions (for the "stable releases" view).
        release_map = {}
        for fv in vuln_versions:
            for cve in fixed_map[fv]:
                for rel, relinfo in cves[cve].get("releases", {}).items():
                    if relinfo.get("status") != "resolved":
                        continue
                    rfv = relinfo.get("fixed_version")
                    if not rfv or rfv == "0":
                        continue
                    if rel not in release_map or version_lt(release_map[rel], rfv):
                        release_map[rel] = rfv
        stable_releases = [
            {"release": r, "version": release_map[r]}
            for r in sorted(release_map)
        ]

        findings.append({
            "package": pkg,
            "severity": sev,
            "our_version": our_ver,
            "fixed_version": target,
            "stable_releases": stable_releases,
            "cves": cve_list,
        })

    # Newest / largest gap first is more useful for triage.
    findings.sort(key=lambda f: f["package"])
    return findings


# ── html report ───────────────────────────────────────────────────────────────

PAGE_STYLE = """
    :root {
      --bg: #ffffff; --fg: #18181b; --muted: #71717a; --border: #e4e4e7;
      --subtle: #f4f4f5; --subtle-2: #fafafa; --accent: #f0f4ff;
      --link: #1a73e8; --ok: #27ae60; --bad: #c0392b;
      --nav-bg: rgba(245,245,245,0.8); --nav-solid: #f5f5f5;
      --nav-border: rgba(204,204,204,0.5); --nav-fg: #737373;
      --nav-fg-hover: #0a0a0a; --nav-hover-bg: rgba(209,209,209,0.5);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090b; --fg: #fafafa; --muted: #a1a1aa; --border: #27272a;
        --subtle: #18181b; --subtle-2: #141417; --accent: #1c2333;
        --link: #6ea8fe; --ok: #4ade80; --bad: #f87171;
        --nav-bg: rgba(18,18,18,0.8); --nav-solid: #121212;
        --nav-border: rgba(102,102,102,0.2); --nav-fg: rgba(179,179,179,0.8);
        --nav-fg-hover: #ebebeb; --nav-hover-bg: rgba(104,104,104,0.3);
      }
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body { margin: 0; background: var(--bg); color: var(--fg);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Ubuntu,
                   'Helvetica Neue', system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
    a { color: var(--link); }
    .nav { position: sticky; top: 0; z-index: 50; background: var(--nav-bg);
      backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--nav-border); }
    .nav-inner { max-width: 1400px; margin: 0 auto; display: flex; align-items: center;
      gap: 1rem; padding: 0 1rem; height: 56px; }
    .nav-logo { display: inline-flex; align-items: center; }
    .nav-logo img { height: 24px; width: auto; display: block; }
    .nav-logo img.dark-only { display: none; }
    @media (prefers-color-scheme: dark) {
      .nav-logo img.light-only { display: none; }
      .nav-logo img.dark-only { display: block; }
    }
    .nav-links { display: flex; align-items: center; gap: 0.25rem; margin-right: auto; font-size: 0.875rem; }
    .nav-links a { display: inline-flex; align-items: center; gap: 0.375rem; padding: 0.5rem;
      border: 0; background: none; font: inherit; color: var(--nav-fg); text-decoration: none;
      transition: color 0.15s; }
    .nav-links a:hover { color: var(--nav-fg-hover); }
    main { max-width: 1400px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
    h1 { font-size: 1.4rem; margin: 0 0 0.25rem; }
    .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; overflow-wrap: anywhere; }
    .summary { font-weight: bold; margin-bottom: 1rem; }
    .summary.bad { color: var(--bad); }
    .summary.ok { color: var(--ok); }
    table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
    th, td { border: 1px solid var(--border); padding: 0.45rem 0.65rem; vertical-align: top; }
    th { background: var(--subtle); text-align: left; white-space: nowrap; }
    tr:hover > td { background: var(--subtle-2); }
    .ver-our { color: var(--bad); font-weight: bold; }
    .ver-fix { color: var(--ok); font-weight: bold; }
    .sev-critical { color: var(--bad); font-weight: bold; }
    .sev-high { color: #e67e22; font-weight: bold; }
    .sev-medium { color: #b8860b; }
    .sev-low { color: var(--muted); }
    .cve-list { font-size: 0.82em; color: var(--muted); }
    table.inner { font-size: 0.82rem; border: none; width: auto; }
    table.inner th, table.inner td { border: 1px solid var(--border); padding: 0.25rem 0.5rem; }
    table.inner th { background: var(--subtle-2); }
    footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--border);
      color: var(--muted); font-size: 0.88rem; overflow-wrap: anywhere; }
"""

NAV_HTML = """
<header class="nav">
  <div class="nav-inner">
    <a class="nav-logo" href="https://blankonlinux.id/en">
      <img class="light-only" src="https://blankonlinux.id/logo-black.png" alt="BlankOn" width="796" height="189">
      <img class="dark-only" src="https://blankonlinux.id/logo-white.png" alt="BlankOn" width="796" height="189">
    </a>
    <nav class="nav-links">
      <a href="https://blankonlinux.id/en/download">Download</a>
      <a href="https://blankonlinux.id/en/wiki/">Wiki</a>
      <a href="https://irgsh.blankonlinux.id/">IRGSH</a>
      <a href="https://packages.blankonlinux.id/">Packages</a>
      <a href="https://security.blankonlinux.id/">Security</a>
      <a href="https://arsip.blankonlinux.id/">Arsip</a>
      <a href="https://arsip-dev.blankonlinux.id/">Arsip Dev</a>
      <a href="https://github.com/blankon">Github</a>
    </nav>
  </div>
</header>
"""


def write_html_report(findings, html_dir, repo_url):
    import html as _html

    def e(s):
        return _html.escape(str(s))

    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    rows = []
    for f in findings:
        cve_links = ", ".join(
            f'<a href="https://security-tracker.debian.org/tracker/{e(c["id"])}" target="_blank">{e(c["id"])}</a>'
            for c in f["cves"]
        )
        desc = f["cves"][0]["description"] if f["cves"] else ""
        desc = desc if len(desc) <= 240 else desc[:240] + "…"

        rel_rows = "".join(
            f'<tr><td>{e(r["release"])}</td><td>{e(r["version"])}</td></tr>'
            for r in f.get("stable_releases", [])
        )
        rel_table = (
            f'<table class="inner"><tr><th>Release</th><th>Version</th></tr>{rel_rows}</table>'
        )

        sev = f.get("severity")
        sev_cls = f"sev-{sev.lower()}" if sev else ""
        sev_cell = f'<td class="{sev_cls}">{e(sev) if sev else "—"}</td>'

        rows.append(f"""
        <tr>
          <td>{e(f['package'])}</td>
          {sev_cell}
          <td class="ver-our">{e(f['our_version'])}</td>
          <td class="ver-fix">{e(f['fixed_version'])}</td>
          <td>{rel_table}</td>
          <td class="cve-list">{len(f['cves'])} — {cve_links}</td>
          <td class="cve-list">{e(desc)}</td>
        </tr>""")

    count = len(findings)
    summary = f"{count} package(s) behind Debian security fixes." if count else "All packages up to date."

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>BlankOn Linux Security Report</title>
  <style>{PAGE_STYLE}</style>
</head>
<body>
{NAV_HTML}
<main>
  <h1>BlankOn Linux Security Report</h1>
  <div class="meta">
    Repository: <a href="{e(repo_url)}" target="_blank">{e(repo_url)}</a>
    &nbsp;|&nbsp; Upstream: <a href="{e(TRACKER_URL)}" target="_blank">Tracker</a>
 &nbsp;|&nbsp; <a href="{e(DSA_URL)}" target="_blank">DSA</a>
    &nbsp;|&nbsp; Generated: {e(generated_at)}
  </div>
  <div class="summary {"bad" if count else "ok"}">{e(summary)}</div>
  {"" if not count else f'''
  <table>
    <thead>
      <tr><th>Package</th><th>Severity</th><th>Our version</th><th>Fixed (Sid)</th><th>Fixed in stable releases</th><th>CVEs</th><th>Description</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>'''}
  <footer>
    Source code: <a href="{e(SOURCE_URL)}" target="_blank">{e(SOURCE_URL)}</a>
  </footer>
</main>
</body>
</html>
"""
    os.makedirs(html_dir, exist_ok=True)
    out_path = os.path.join(html_dir, "index.html")
    with open(out_path, "w") as fh:
        fh.write(page)
    print(f"HTML report written to {out_path}", file=sys.stderr)


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    repo_url = None
    output = None
    html_dir = None
    no_cache = False
    no_nvd = False
    min_severity = None

    for arg in sys.argv[1:]:
        if arg.startswith("--repo=") or arg.startswith("--repository="):
            repo_url = arg.split("=", 1)[1]
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        elif arg.startswith("--html="):
            html_dir = arg.split("=", 1)[1]
        elif arg == "--no-cache":
            no_cache = True
        elif arg == "--no-nvd":
            no_nvd = True
        elif arg.startswith("--min-severity="):
            min_severity = arg.split("=", 1)[1].lower()

    if not repo_url:
        print("Error: --repo=/url or --repository=/url is required", file=sys.stderr)
        sys.exit(1)

    tracker = load_tracker(no_cache=no_cache)
    package_index = build_package_index(repo_url)

    print("Evaluating packages ...", file=sys.stderr)
    findings = evaluate(package_index, tracker)

    if not no_nvd:
        enrich_nvd(findings)

    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity)
        if min_rank is None:
            print(f"Error: invalid --min-severity '{min_severity}' (use critical/high/medium/low)", file=sys.stderr)
            sys.exit(1)
        findings = [
            f for f in findings
            if f.get("severity") and SEVERITY_RANK.get(f["severity"].lower(), 0) >= min_rank
        ]

    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"Findings written to {output}", file=sys.stderr)

    if not findings:
        print("No vulnerable packages found.", file=sys.stderr)
        if html_dir:
            write_html_report(findings, html_dir, repo_url)
        sys.exit(0)

    print(f"Found {len(findings)} package(s) behind Debian security fixes:\n", file=sys.stderr)
    for f in findings:
        print(f"  {f['package']}: {f['our_version']} -> {f['fixed_version']} ({len(f['cves'])} CVE)")

    if html_dir:
        write_html_report(findings, html_dir, repo_url)


if __name__ == "__main__":
    main()
