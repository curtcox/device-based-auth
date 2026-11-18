#!/usr/bin/env bash
# The dba CLI with its device key inside the TPM: `dba enroll --key-store tpm` makes the key in
# the TPM, proves that to the server by EK credential activation, and every later command (here
# `dba curl`) has the TPM sign its DPoP proof. Needs tpm2-tools 5 and access to the TPM
# (/dev/tpmrm0, usually the "tss" group; or set TPM2TOOLS_TCTI).
#
#   DBA_ORIGIN=http://localhost:8787 bash docs/samples/tpm/dba-cli.sh
set -euo pipefail
origin="${DBA_ORIGIN:-https://devicebasedauth.org}"
# A throwaway profile directory, so the sample leaves your own dba profiles alone.
export DBA_HOME="$(mktemp -d)"
trap 'rm -rf "$DBA_HOME"' EXIT
# DBA_CLI lets CI run the CLI from this repository; otherwise the installed `dba`.
dba() { ${DBA_CLI:-dba} --origin "$origin" "$@"; }

dba enroll --key-store tpm --name "TPM CLI sample" --kind desktop --aud hashbin.org \
  --grant '{"actions":["hashbin:content:write"],"require":{"attestation":"hardware"}}'
echo "key.json keeps only the TPM's blobs: $(jq -c 'keys' "$DBA_HOME/default/key.json")"

# The TPM signs this request's DPoP proof.
dba curl -sS --fail-with-body "$origin/api/v1/whoami" \
  | jq -r '"whoami: account \(.account), device \(.device_id)", (.descriptions[] | " - \(.)")'
