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
