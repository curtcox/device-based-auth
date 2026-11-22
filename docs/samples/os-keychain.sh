#!/usr/bin/env bash
# The dba CLI with its device key in the OS secret store: the macOS Keychain (`security`) or the
# freedesktop Secret Service (GNOME Keyring, KWallet; `secret-tool`). key.json then holds only the
# public key and the entry's name; rotation moves the key to a new entry and revocation removes it.
# `dba enroll` does this by itself where a store exists (--key-store auto); `os` makes it required.
#
#   DBA_ORIGIN=http://localhost:8787 bash docs/samples/os-keychain.sh
#
# This writes one entry to your real keychain and removes it again at the end.
set -euo pipefail

cd "$(dirname "$0")/../.."
origin="${DBA_ORIGIN:-https://devicebasedauth.org}"
# A throwaway profile directory, so the sample leaves your own dba profiles alone.
export DBA_HOME="$(mktemp -d)"
trap 'rm -rf "$DBA_HOME"' EXIT
dba() { node packages/cli/dba.js --origin "$origin" "$@"; }   # or: npm install -g @devicebasedauth/cli

key_json() { node -e 'const k = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); console.log(process.argv[2] ? k[process.argv[2]] : JSON.stringify(Object.keys(k).sort()))' "$DBA_HOME/default/key.json" "${1:-}"; }
# Is there an entry for this key? (Asks the store directly, not through dba.)
in_store() {
  case "$(uname -s)" in
    Darwin) security find-generic-password -s org.devicebasedauth.dba -a "$1" >/dev/null 2>&1 ;;
    *) [ -n "$(secret-tool lookup service org.devicebasedauth.dba account "$1" 2>/dev/null)" ] ;;
  esac && echo yes || echo no
}

dba enroll --key-store os --name "Keychain sample" --aud hashbin.org --action hashbin:content:write --wait 60
first="$(key_json key_store_account)"
echo "key.json keeps no private key: $(key_json)"
echo "Store: $(key_json key_store); entry for the key: $(in_store "$first")"

# Signing reads the key back from the store.
dba curl -sS --fail-with-body "$origin/api/v1/whoami" \
  | node -e 'const w = JSON.parse(require("fs").readFileSync(0, "utf8")); console.log(`whoami: account ${w.account}, device ${w.device_id}`)'

# A new key, in a new entry; the old entry goes once the server has agreed.
dba renew --rotate
second="$(key_json key_store_account)"
echo "After rotation: old entry $(in_store "$first"), new entry $(in_store "$second")"

dba revoke
echo "After revoking: entry $(in_store "$second")"
