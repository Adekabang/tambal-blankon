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
import shutil
import subprocess
import sys
import time
import urllib.error
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

# Debian security-tracker git repo (source of the DSA list, mapping DSA -> CVEs).
SEC_TRACKER_REPO = "https://salsa.debian.org/security-tracker-team/security-tracker.git"
SEC_TRACKER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sec-tracker")
DSA_LIST_PATH = os.path.join(SEC_TRACKER_DIR, "data", "DSA", "list")

# debian.org/security page lists each DSA with its mailing-list announcement URL.
DSA_ANNOUNCE_URL = "https://www.debian.org/security/"
DSA_ANNOUNCE_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsa-announce.json")


# ── helpers ───────────────────────────────────────────────────────────────────

# Cache for dpkg version comparisons: (a, b) -> bool, avoids repeated subprocess
# calls when many CVEs share the same fixed version.
_VERSION_CACHE = {}


# Fetches that never succeeded, even after every retry. Collected here so the
# generated report can say which data is missing instead of silently dropping it.
FETCH_FAILURES = []


def record_fetch_failure(url, error, attempts):
    FETCH_FAILURES.append({
        "url": url,
        "error": error,
        "attempts": attempts,
        "time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    })


def report_fetch_failures():
    """Print a stderr summary of fetches that never succeeded."""
    if not FETCH_FAILURES:
        return
    print(f"\n{len(FETCH_FAILURES)} fetch(es) failed after retries:", file=sys.stderr)
    for fail in FETCH_FAILURES:
        print(f"  - {fail['url']} ({fail['attempts']} attempt(s)): {fail['error']}",
              file=sys.stderr)


def _fetch_raw(url):
    """Fetch URL bytes with retry logic for transient failures (503, timeouts)."""
    max_retries = 3
    retry_delay = 30

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < max_retries - 1:
                print(f"HTTP 503: Backend unavailable. Retrying in {retry_delay}s... "
                      f"(attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            record_fetch_failure(url, f"HTTP {e.code} {e.reason}", attempt + 1)
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < max_retries - 1:
                print(f"Connection error: {e}. Retrying in {retry_delay}s... "
                      f"(attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            record_fetch_failure(url, str(e), attempt + 1)
            raise


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


def _is_fresh(path, seconds):
    """Return True if path exists and was modified within the last `seconds`."""
    return os.path.exists(path) and (time.time() - os.path.getmtime(path) < seconds)


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
    """Return {severity, published} for a CVE (or None), using/updating cache.

    Only real CVE IDs are looked up. Failed / not-yet-in-NVD lookups are NOT
    cached, so they get retried on the next run (NVD has a processing backlog).
    """
    if cve_id in cache:
        return cache[cve_id]
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
        return None
    headers = {"User-Agent": "Mozilla/5.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url = f"{NVD_API_URL}?cveId={cve_id}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
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


def enrich_nvd(findings, no_cache=False):
    """Add NVD severity + published date to each finding's CVEs (cached, throttled)."""
    cache = {} if no_cache else _load_nvd_cache()

    # cve_id -> list of CVE entries across all findings
    cve_map = {}
    for f in findings:
        for c in f["cves"]:
            cve_map.setdefault(c["id"], []).append(c)

    pending = [c for c in cve_map.keys() if re.match(r"^CVE-\d{4}-\d+$", c)]
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
    """Download (and cache) the security-tracker JSON export (24h TTL)."""
    if not no_cache and _is_fresh(TRACKER_CACHE, 86400):
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


# ── DSA list ──────────────────────────────────────────────────────────────────

def _ensure_dsa_list(no_cache=False):
    """Ensure data/DSA/list exists via a shallow sparse clone (refreshed daily)."""
    if not no_cache and _is_fresh(DSA_LIST_PATH, 86400):
        return DSA_LIST_PATH

    print("Fetching DSA list (shallow sparse clone) ...", file=sys.stderr)
    if os.path.isdir(SEC_TRACKER_DIR):
        shutil.rmtree(SEC_TRACKER_DIR)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
         SEC_TRACKER_REPO, SEC_TRACKER_DIR],
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", SEC_TRACKER_DIR, "sparse-checkout", "set", "data/DSA"],
        capture_output=True,
    )
    return DSA_LIST_PATH if os.path.exists(DSA_LIST_PATH) else None


def parse_dsa_list(text):
    """Parse data/DSA/list into {CVE: DSA-id} and {DSA-id: YYYY-MM-DD} maps."""
    dsa_map = {}
    dsa_dates = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"\[(\d{2} \w{3} \d{4})\]\s+(DSA-\d+-\d+)\s+", line)
        if m:
            current = m.group(2)
            dsa_dates[current] = _parse_dsa_date(m.group(1))
            continue
        if current:
            m2 = re.search(r"\{([^}]*)\}", line)
            if m2:
                for cve in m2.group(1).split():
                    if cve.startswith("CVE-"):
                        dsa_map.setdefault(cve, current)
    return dsa_map, dsa_dates


def _parse_dsa_date(s):
    """Parse a DSA list date like '24 Sep 2026' -> 'YYYY-MM-DD'."""
    try:
        return datetime.strptime(s, "%d %b %Y").strftime("%Y-%m-%d")
    except ValueError:
        return s


def load_dsa_map(no_cache=False):
    """Return ({CVE: DSA-id}, {DSA-id: date}) from data/DSA/list."""
    path = _ensure_dsa_list(no_cache=no_cache)
    if not path:
        print("Warning: could not fetch the DSA list.", file=sys.stderr)
        return {}, {}
    with open(path) as f:
        dsa_map, dsa_dates = parse_dsa_list(f.read())
    print(f"Loaded {len(dsa_map)} CVE->DSA mappings.", file=sys.stderr)
    return dsa_map, dsa_dates


def load_dsa_announce(no_cache=False):
    """Fetch the DSA -> announcement URL mapping from debian.org/security."""
    if not no_cache and _is_fresh(DSA_ANNOUNCE_CACHE, 86400):
        with open(DSA_ANNOUNCE_CACHE) as f:
            return json.load(f)
    try:
        html = fetch_text(DSA_ANNOUNCE_URL)
    except Exception:
        print("Warning: could not fetch debian.org/security.", file=sys.stderr)
        return {}
    announce = {}
    for m in re.finditer(
        r'href="(https://lists\.debian\.org/debian-security-announce/[^"]+)"[^>]*>\s*(DSA-\d+-\d+)',
        html,
    ):
        announce[m.group(2)] = m.group(1)
    with open(DSA_ANNOUNCE_CACHE, "w") as f:
        json.dump(announce, f)
    print(f"Loaded {len(announce)} DSA announcement URLs.", file=sys.stderr)
    return announce


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
      --bg: #ffffff;
      --fg: #18181b;
      --muted: #71717a;
      --border: #e4e4e7;
      --subtle: #f4f4f5;
      --subtle-2: #fafafa;
      --accent: #f0f4ff;
      --link: #1a73e8;
      --ok: #27ae60;
      --bad: #c0392b;
      --nav-bg: rgba(245, 245, 245, 0.8);
      --nav-solid: #f5f5f5;
      --nav-border: rgba(204, 204, 204, 0.5);
      --nav-fg: #737373;
      --nav-fg-hover: #0a0a0a;
      --nav-hover-bg: rgba(209, 209, 209, 0.5);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090b;
        --fg: #fafafa;
        --muted: #a1a1aa;
        --border: #27272a;
        --subtle: #18181b;
        --subtle-2: #141417;
        --accent: #1c2333;
        --link: #6ea8fe;
        --ok: #4ade80;
        --bad: #f87171;
        --nav-bg: rgba(18, 18, 18, 0.8);
        --nav-solid: #121212;
        --nav-border: rgba(102, 102, 102, 0.2);
        --nav-fg: rgba(179, 179, 179, 0.8);
        --nav-fg-hover: #ebebeb;
        --nav-hover-bg: rgba(104, 104, 104, 0.3);
      }
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--fg);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Ubuntu,
                   'Helvetica Neue', system-ui, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    a { color: var(--link); }

    /* ── top bar (ported from blankon.id) ─────────────────────────────── */
    .nav {
      position: sticky; top: 0; z-index: 50;
      background: var(--nav-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--nav-border);
    }
    .nav-inner {
      max-width: 1400px; margin: 0 auto;
      display: flex; align-items: center; gap: 1rem;
      padding: 0 1rem; height: 56px;
    }
    .nav-logo { display: inline-flex; align-items: center; }
    .nav-logo img { height: 24px; width: auto; display: block; }
    .nav-logo img.dark-only { display: none; }
    @media (prefers-color-scheme: dark) {
      .nav-logo img.light-only { display: none; }
      .nav-logo img.dark-only { display: block; }
    }
    .nav-toggle {
      display: none; background: none; border: 0; cursor: pointer;
      color: var(--nav-fg); padding: 0.5rem; margin: 0 -0.5rem 0 auto;
    }
    .nav-links {
      display: flex; align-items: center; gap: 0.25rem;
      margin-right: auto;
      font-size: 0.875rem;
    }
    .nav-links a, .nav-links button {
      display: inline-flex; align-items: center; gap: 0.375rem;
      padding: 0.5rem; border: 0; background: none; cursor: pointer;
      font: inherit; color: var(--nav-fg); text-decoration: none;
      transition: color 0.15s;
    }
    .nav-links a:hover, .nav-links button:hover { color: var(--nav-fg-hover); }
    .nav-links .ext { width: 14px; height: 14px; opacity: 0.7; flex-shrink: 0; }
    .nav-drop { position: relative; }
    .nav-drop > ul {
      list-style: none; margin: 0; padding: 0.25rem 0;
      min-width: 170px;
      position: absolute; left: 0; top: 100%;
      background: var(--nav-solid); border: 1px solid var(--nav-border);
      border-radius: 0.375rem; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
      visibility: hidden; opacity: 0; transition: opacity 0.15s;
    }
    .nav-drop.open > ul { visibility: visible; opacity: 1; }
    .nav-drop a { display: flex; padding: 0.5rem 1rem; width: 100%; }
    .nav-drop a:hover { background: var(--nav-hover-bg); }
    .nav-caret { width: 12px; height: 12px; transition: transform 0.15s; }
    .nav-drop.open .nav-caret { transform: rotate(180deg); }

    @media (max-width: 860px) {
      .nav-toggle { display: inline-flex; }
      .nav-links {
        display: none; position: absolute; left: 0; right: 0; top: 56px;
        flex-direction: column; align-items: stretch; gap: 0;
        background: var(--nav-solid); border-bottom: 1px solid var(--nav-border);
        padding: 0.5rem 1rem 1rem;
      }
      .nav-links.open { display: flex; }
      .nav-links a, .nav-links button { padding: 0.625rem 0; }
      .nav-drop > ul {
        position: static; visibility: visible; opacity: 1;
        border: 0; box-shadow: none; background: none; margin: 0;
        min-width: 0; display: none;
      }
      .nav-drop.open > ul { display: block; }
      .nav-drop a { padding: 0.625rem 0 0.625rem 1rem; }
      .nav-drop a:hover { background: none; }
    }

    /* ── report ───────────────────────────────────────────────────────── */
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
    table.inner { font-size: 0.82rem; border: none; width: auto; }
    table.inner th, table.inner td { border: 1px solid var(--border); padding: 0.25rem 0.5rem; }
    table.inner th { background: var(--subtle-2); }
    .grp { background: var(--subtle); font-style: italic; font-size: 0.82em; }
    .cve-head { background: var(--accent); font-weight: bold; font-size: 0.82em; }
    .cve-list { font-size: 0.85em; color: var(--muted); margin-top: 0.25rem; }
    .none { color: var(--muted); }
    .ver-above { color: var(--ok); font-weight: bold; }
    .ver-below { color: var(--bad); font-weight: bold; }
    .failures { margin-top: 2.5rem; }
    .failures h2 { font-size: 1.05rem; margin: 0 0 0.25rem; }
    .failures .note { color: var(--muted); font-size: 0.88rem; margin: 0 0 0.75rem; }
    .failures .url { word-break: break-all; }
    .failures .err { color: var(--bad); }
    .ver-our { color: var(--bad); font-weight: bold; }
    .ver-fix { color: var(--ok); font-weight: bold; }
    .sev-critical { color: var(--bad); font-weight: bold; }
    .sev-high { color: #e67e22; font-weight: bold; }
    .sev-medium { color: #b8860b; }
    .sev-low { color: var(--muted); }
    .filters { display: flex; gap: 0.6rem; align-items: center; margin: 0.75rem 0 1rem; flex-wrap: wrap; }
    .filters input[type="text"] { font: inherit; padding: 0.4rem 0.6rem; min-width: 220px;
      border: 1px solid var(--border); background: var(--bg); color: var(--fg); border-radius: 0.375rem; }
    .filters select { font: inherit; padding: 0.4rem 0.6rem; border: 1px solid var(--border);
      background: var(--bg); color: var(--fg); border-radius: 0.375rem; }
    .sev-badge { display: inline-block; padding: 0.12rem 0.55rem; border-radius: 999px;
      font-size: 0.8rem; margin: 0 0.3rem 0.3rem 0; border: 1px solid var(--border); white-space: nowrap; }
    .sev-badge.critical { color: var(--bad); border-color: var(--bad); }
    .sev-badge.high { color: #e67e22; border-color: #e67e22; }
    .sev-badge.medium { color: #b8860b; border-color: #b8860b; }
    .sev-badge.low { color: var(--muted); }
    .sev-badge.unknown { color: var(--muted); }
    footer {
      margin-top: 2.5rem; padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--muted); font-size: 0.88rem; overflow-wrap: anywhere;
    }

    @media (max-width: 860px) {
      table.report, table.report > tbody, table.report > tbody > tr,
      table.report > tbody > tr > td { display: block; width: 100%; }
      table.report > thead { display: none; }
      table.report { border: 0; }
      table.report > tbody > tr {
        border: 1px solid var(--border); border-radius: 0.5rem;
        margin-bottom: 1rem; padding: 0.25rem 0.75rem; overflow: hidden;
      }
      table.report > tbody > tr:hover > td { background: none; }
      table.report > tbody > tr > td {
        border: 0; border-bottom: 1px solid var(--border);
        padding: 0.55rem 0; overflow-wrap: anywhere;
      }
      table.report > tbody > tr > td:last-child { border-bottom: 0; }
      table.report > tbody > tr > td::before {
        content: attr(data-label);
        display: block; font-size: 0.72rem; text-transform: uppercase;
        letter-spacing: 0.04em; color: var(--muted); margin-bottom: 0.15rem;
      }
      table.inner { width: 100%; font-size: 0.78rem; }
      table.inner th, table.inner td { white-space: normal; }
    }
"""

NAV_HTML = """
<header class="nav">
  <div class="nav-inner">
    <a class="nav-logo" href="https://blankonlinux.id/en">
      <img class="light-only" src="https://blankonlinux.id/logo-black.png" alt="BlankOn" width="796" height="189">
      <img class="dark-only" src="https://blankonlinux.id/logo-white.png" alt="BlankOn" width="796" height="189">
    </a>
    <button class="nav-toggle" type="button" aria-label="Menu" aria-expanded="false" aria-controls="nav-links">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M4 6h16M4 12h16M4 18h16"/>
      </svg>
    </button>
    <nav class="nav-links" id="nav-links">
      <a href="https://blankonlinux.id/en/download">Download</a>
      <a href="https://blankonlinux.id/en/wiki/">Wiki</a>
      <div class="nav-drop">
        <button type="button" aria-expanded="false" aria-haspopup="menu">
          Development
          <svg class="nav-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
        </button>
        <ul>
          <li><a href="https://blankonlinux.id/en/team">Team</a></li>
          <li><a href="https://irgsh.blankonlinux.id/">IRGSH</a></li>
          <li><a href="https://packages.blankonlinux.id/">Packages</a></li>
          <li><a href="https://security.blankonlinux.id/" target="_blank" rel="noopener noreferrer">Security</a></li>
          <li><a href="https://jahitan.blankonlinux.id/" target="_blank" rel="noopener noreferrer">Jahitan<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a></li>
          <li><a href="https://arsip.blankonlinux.id/" target="_blank" rel="noopener noreferrer">Arsip<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a></li>
          <li><a href="https://arsip-dev.blankonlinux.id/" target="_blank" rel="noopener noreferrer">Arsip Dev<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a></li>
          <li><a href="https://github.com/blankon" target="_blank" rel="noopener noreferrer">Github<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a></li>
        </ul>
      </div>
      <a href="https://blankon.id/en/sponsorship" target="_blank" rel="noopener noreferrer">Sponsorship<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a>
      <a href="https://blankon.id/en/donate" target="_blank" rel="noopener noreferrer">Donate<svg class="ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg></a>
    </nav>
  </div>
</header>
"""

NAV_SCRIPT = """
  (function () {
    var toggle = document.querySelector('.nav-toggle');
    var links = document.getElementById('nav-links');
    toggle.addEventListener('click', function () {
      var open = links.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });

    // Hover opens the dropdown on pointer devices; touch devices tap it open.
    var drop = document.querySelector('.nav-drop');
    var dropBtn = drop.querySelector('button');
    var canHover = function () { return window.matchMedia('(hover: hover)').matches; };
    var closeTimer = null;

    function setDrop(open) {
      drop.classList.toggle('open', open);
      dropBtn.setAttribute('aria-expanded', String(open));
    }
    // Closing is delayed so the cursor can wander off the menu and back
    // without the panel vanishing under it.
    drop.addEventListener('mouseenter', function () {
      clearTimeout(closeTimer);
      if (canHover()) setDrop(true);
    });
    drop.addEventListener('mouseleave', function () {
      if (!canHover()) return;
      clearTimeout(closeTimer);
      closeTimer = setTimeout(function () { setDrop(false); }, 100);
    });

    dropBtn.addEventListener('click', function (event) {
      event.stopPropagation();
      clearTimeout(closeTimer);
      setDrop(canHover() ? true : !drop.classList.contains('open'));
    });
    document.addEventListener('click', function (event) {
      if (!drop.contains(event.target)) {
        clearTimeout(closeTimer);
        setDrop(false);
      }
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        clearTimeout(closeTimer);
        setDrop(false);
        links.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  })();
"""

FILTER_SCRIPT = """<script>
(function () {
  var input = document.getElementById('filter-pkg');
  var sel = document.getElementById('filter-sev');
  var dsaSel = document.getElementById('filter-dsa');
  if (!input || !sel) return;
  function apply() {
    var q = input.value.toLowerCase().trim();
    var sev = sel.value;
    var dsaV = dsaSel ? dsaSel.value : '';
    document.querySelectorAll('tbody tr[data-pkg]').forEach(function (tr) {
      var pkg = tr.getAttribute('data-pkg') || '';
      var s = tr.getAttribute('data-sev') || '';
      var d = tr.getAttribute('data-dsa') || '';
      var okP = !q || pkg.indexOf(q) !== -1;
      var okS = !sev || s === sev;
      var okD = true;
      if (dsaV === 'has') okD = d.trim() !== '';
      else if (dsaV === 'none') okD = d.trim() === '';
      tr.style.display = (okP && okS && okD) ? '' : 'none';
    });
  }
  input.addEventListener('input', apply);
  sel.addEventListener('change', apply);
  if (dsaSel) dsaSel.addEventListener('change', apply);
})();
</script>
"""


def write_html_report(findings, html_dir, repo_url, dsa_map=None, dsa_announce=None, dsa_dates=None, failures=None):
    import html as _html

    def e(s):
        return _html.escape(str(s))

    def finding_date(f):
        """Date for a finding: latest DSA date among its CVEs, else latest NVD published."""
        if dsa_dates:
            dsas = []
            for c in f.get("cves", []):
                d = (dsa_map or {}).get(c["id"])
                if d and dsa_dates.get(d):
                    dsas.append(dsa_dates[d])
            if dsas:
                return max(dsas)
        dates = [c.get("published") for c in f.get("cves", []) if c.get("published")]
        return max(dates).split("T")[0] if dates else None

    show_dsa = dsa_map is not None
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
        sev_key = sev.lower() if sev else "unknown"
        sev_cls = f"sev-{sev_key}" if sev else ""
        sev_cell = f'<td class="{sev_cls}">{e(sev) if sev else "—"}</td>'

        dsa_ids = []
        for c in f["cves"]:
            d = (dsa_map or {}).get(c["id"])
            if d and d not in dsa_ids:
                dsa_ids.append(d)
        dsa_attr = " ".join(dsa_ids)

        # Advisory cell: DSA lines (if any) above the CVE list.
        adv_parts = []
        if show_dsa and dsa_ids:
            for d in dsa_ids:
                ann = (dsa_announce or {}).get(d)
                label = f'<a href="{e(ann)}" target="_blank">{e(d)}</a>' if ann else e(d)
                tracker = f'<a href="https://security-tracker.debian.org/tracker/{e(d)}" target="_blank">Tracker</a>'
                adv_parts.append(f'{label} | {tracker}')
        adv_parts.append(f'{len(f["cves"])} CVE: {cve_links}')
        advisory_cell = f'<td class="cve-list">{"<br>".join(adv_parts)}</td>'

        # Details cell: fixed-in-stable-releases table + description.
        details_cell = f'<td>{rel_table}<div class="cve-list">{e(desc)}</div></td>'

        date_str = finding_date(f)
        date_cell = f'<td data-label="Date">{e(date_str) if date_str else "—"}</td>'

        rows.append(f"""
        <tr data-pkg="{e(f['package'].lower())}" data-sev="{sev_key}" data-dsa="{e(dsa_attr)}">
          <td>{e(f['package'])}</td>
          {date_cell}
          {sev_cell}
          <td class="ver-our">{e(f['our_version'])}</td>
          <td class="ver-fix">{e(f['fixed_version'])}</td>
          {advisory_cell}
          {details_cell}
        </tr>""")

    count = len(findings)
    summary = f"{count} package(s) behind Debian security fixes." if count else "All packages up to date."

    # Severity summary badges.
    sev_counts = {}
    for f in findings:
        key = (f.get("severity") or "unknown").lower()
        sev_counts[key] = sev_counts.get(key, 0) + 1
    badges = "".join(
        f'<span class="sev-badge {k}">{k.capitalize()}: {n}</span>'
        for k, n in (("critical", sev_counts.get("critical", 0)),
                     ("high", sev_counts.get("high", 0)),
                     ("medium", sev_counts.get("medium", 0)),
                     ("low", sev_counts.get("low", 0)),
                     ("unknown", sev_counts.get("unknown", 0)))
        if n
    )
    badges_html = f'<div class="filters">{badges}</div>' if badges else ""

    filters_html = ""
    if count:
        dsa_filter = '''
    <select id="filter-dsa">
      <option value="">All</option>
      <option value="has">Has DSA</option>
      <option value="none">No DSA</option>
    </select>''' if show_dsa else ''
        filters_html = f'''
  <div class="filters">
    <input type="text" id="filter-pkg" placeholder="Filter by package…">
    <select id="filter-sev">
      <option value="">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="unknown">Unknown</option>
    </select>
    {dsa_filter}
  </div>'''

    # Fetches that never came back, so the reader knows the table above may be
    # missing advisories or versions.
    seen_failures = {}
    for fail in failures or []:
        key = (fail["url"], fail["error"])
        if key in seen_failures:
            seen_failures[key]["occurrences"] += 1
        else:
            seen_failures[key] = dict(fail, occurrences=1)

    fail_rows = []
    for fail in seen_failures.values():
        tries = f'{fail["attempts"]} attempt(s)'
        if fail["occurrences"] > 1:
            tries += f' × {fail["occurrences"]} run(s)'
        fail_rows.append(
            f'<tr>'
            f'<td data-label="Time">{e(fail["time"])}</td>'
            f'<td class="url" data-label="URL">'
            f'<a href="{e(fail["url"])}" target="_blank">{e(fail["url"])}</a></td>'
            f'<td data-label="Tried">{e(tries)}</td>'
            f'<td class="err" data-label="Error">{e(fail["error"])}</td>'
            f'</tr>'
        )

    if fail_rows:
        failures_html = f"""
  <section class="failures">
    <h2>Failed fetches ({len(fail_rows)})</h2>
    <p class="note">These pages could not be retrieved, even after retrying,
       so the report above may be incomplete.</p>
    <table class="report">
      <thead>
        <tr><th>Time</th><th>URL</th><th>Tried</th><th>Error</th></tr>
      </thead>
      <tbody>
        {''.join(fail_rows)}
      </tbody>
    </table>
  </section>"""
    else:
        failures_html = ""

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
  {badges_html}
  {filters_html}
  {"" if not count else f'''
  <table>
    <thead>
      <tr><th>Package</th><th>Date</th><th>Severity</th><th>Our version</th><th>Fixed (Sid)</th><th>Advisory</th><th>Details</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>'''}
  {failures_html}
  <footer>
    Source code: <a href="{e(SOURCE_URL)}" target="_blank">{e(SOURCE_URL)}</a>
  </footer>
</main>
{FILTER_SCRIPT}
<script>{NAV_SCRIPT}</script>
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
    no_dsa = False
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
        elif arg == "--no-dsa":
            no_dsa = True
        elif arg.startswith("--min-severity="):
            min_severity = arg.split("=", 1)[1].lower()

    if not repo_url:
        print("Error: --repo=/url or --repository=/url is required", file=sys.stderr)
        sys.exit(1)

    tracker = load_tracker(no_cache=no_cache)
    package_index = build_package_index(repo_url)
    if no_dsa:
        dsa_map = None
        dsa_announce = None
        dsa_dates = None
    else:
        dsa_map, dsa_dates = load_dsa_map(no_cache=no_cache)
        dsa_announce = load_dsa_announce(no_cache=no_cache)

    print("Evaluating packages ...", file=sys.stderr)
    findings = evaluate(package_index, tracker)

    if not no_nvd:
        enrich_nvd(findings, no_cache=no_cache)

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
            write_html_report(findings, html_dir, repo_url, dsa_map=dsa_map, dsa_announce=dsa_announce, dsa_dates=dsa_dates, failures=FETCH_FAILURES)
        report_fetch_failures()
        sys.exit(0)

    print(f"Found {len(findings)} package(s) behind Debian security fixes:\n", file=sys.stderr)
    for f in findings:
        print(f"  {f['package']}: {f['our_version']} -> {f['fixed_version']} ({len(f['cves'])} CVE)")

    if html_dir:
        write_html_report(findings, html_dir, repo_url, dsa_map=dsa_map, dsa_announce=dsa_announce, dsa_dates=dsa_dates, failures=FETCH_FAILURES)

    report_fetch_failures()


if __name__ == "__main__":
    main()
