#!/usr/bin/env bash
# Builds TA-viewdns and packages it into dist/TA-viewdns-<version>.tar.gz.
# Usage: scripts/build.sh [version]
#
# The build is staged in a temporary directory on a native Linux/macOS filesystem so file modes are correct
# (Windows drives mounted in WSL report every file as executable, which AppInspect rejects).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
VERSION="${1:-$(python3 -c 'import json;print(json.load(open("globalConfig.json"))["meta"]["version"])')}"
if [ -x .venv/bin/python ]; then export PATH="$ROOT/.venv/bin:$PATH"; fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/ta-viewdns-build.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
cp -r package globalConfig.json "$STAGE/"

# --no-binary keeps charset_normalizer pure Python (its wheels ship compiled .so files tied to one Python version,
# which AppInspect rejects for Splunk Cloud).
( cd "$STAGE" && ucc-gen build --source package --config globalConfig.json -o output --overwrite \
    --ta-version "$VERSION" --pip-custom-flag="--no-binary=charset-normalizer" )
# ucc-gen rewrites schema/version fields in globalConfig.json; keep the repo copy in sync.
cp "$STAGE/globalConfig.json" "$ROOT/globalConfig.json"

OUT="$STAGE/output/TA-viewdns"

# UCC generates one REST handler for all settings tabs and does not support a custom handler class for them, so we
# swap in ViewDNSSettingsHandler (validates the API key on save).
RH="$OUT/bin/ta_viewdns_rh_settings.py"
grep -q "handler=AdminExternalHandler," "$RH" || { echo "ERROR: unexpected UCC REST handler layout in $RH" >&2; exit 1; }
sed -i.bak 's/handler=AdminExternalHandler,/handler=ViewDNSSettingsHandler,/' "$RH"
sed -i.bak 's/^import logging$/import logging\nfrom ta_viewdns_settings_handler import ViewDNSSettingsHandler/' "$RH"
rm -f "$RH.bak"
grep -q "^from ta_viewdns_settings_handler import ViewDNSSettingsHandler" "$RH" || { echo "ERROR: handler patch failed" >&2; exit 1; }

# Stanzas for conf files that UCC generates: UCC overwrites (doesn't merge) same-named package files, so build/append/
# holds them and they are appended here.
for extra in "$ROOT"/build/append/*.conf; do
    name="$(basename "$extra")"
    target="$OUT/default/$name"
    first="$(grep -m1 -o '^\[[^]]*\]' "$extra")"
    if [ -f "$target" ] && grep -qF "$first" "$target"; then
        echo "ERROR: $name already contains $first" >&2; exit 1
    fi
    { [ -f "$target" ] && echo; cat "$extra"; } >> "$target"
done

# Release notes referenced by app.manifest (info.releaseNotes.text).
mkdir -p "$OUT/README"
cp "$ROOT/RELEASE_NOTES.md" "$OUT/README/release_notes.txt"

# Strip build noise that AppInspect flags.
find "$OUT" -name "__pycache__" -type d -prune -exec rm -rf {} +
find "$OUT" -name "*.pyc" -delete
rm -rf "$OUT/lib/bin"   # console-script shims installed by pip
find "$OUT/lib" -mindepth 2 -maxdepth 2 -type d -name tests -prune -exec rm -rf {} +   # libraries' own test suites
if find "$OUT" \( -name "*.so" -o -name "*.pyd" -o -name "*.dylib" \) | grep -q .; then
    echo "ERROR: compiled binaries found in the package:" >&2
    find "$OUT" \( -name "*.so" -o -name "*.pyd" -o -name "*.dylib" \) >&2
    exit 1
fi

# File modes: directories 755, files 644, only the entry-point scripts in bin/ executable.
find "$OUT" -type d -exec chmod 755 {} +
find "$OUT" -type f -exec chmod 644 {} +
chmod 755 "$OUT"/bin/*.py

mkdir -p "$ROOT/dist" "$ROOT/output"
ucc-gen package --path "$OUT" -o "$ROOT/dist"
# Keep an unpacked copy for inspection (modes are not meaningful on Windows drives).
rm -rf "$ROOT/output/TA-viewdns"
cp -r "$OUT" "$ROOT/output/"
ls -l "$ROOT/dist"
