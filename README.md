# Tambal

https://security.blankonlinux.id/

1. Scan Debian DSA and fetch the fixed version of packages
2. Evaluate the packages in targeted repository (WIP)
3. Automate the update to repository (WIP)

This is part of BlankOn's responsibility as derivative distribution.

## Usage

```
python3 tambal.py --repo=http://arsip-dev.blankonlinux.id/sinambung/ --output=./advisories.json --html=./security-advisories
```

## Options

- `--repo=` / `--repository=` — target repository root (required).
- `--output=` — write the JSON findings to this file (optional).
- `--html=` — write the HTML report to this directory (optional).
- `--no-cache` — re-download the Debian security-tracker data instead of using the cached `tracker.json`.
- `--no-nvd` — skip NVD severity enrichment (faster; severity comes from Debian data only).
- `--no-dsa` — skip the DSA list fetch and hide the DSA column.
- `--min-severity=high` — only show packages at or above this severity (`critical`/`high`/`medium`/`low`).

## NVD severity

Severity (Critical / High / Medium / Low) is fetched from the NVD API and cached
in `nvd-cache.json`. By default it runs keyless (5 requests / 30s). Set an NVD API
key to raise that to 50 requests / 30s — either in the environment or in a `.env`
file next to the script:

```
NVD_API_KEY=your-key-here
```

Both `.env` and `nvd-cache.json` are gitignored.
